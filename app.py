import os
import sys
import json
import logging
import uuid
import threading
import time
from typing import Dict, Any, List, Optional
import dotenv # type: ignore
from fastapi.middleware.cors import CORSMiddleware # type: ignore
from fastapi import File, UploadFile, HTTPException, status, Query, Form# Import Query for query parameters # type: ignore

dotenv.load_dotenv()

# FastAPI imports
from fastapi import FastAPI, Request, File, UploadFile, HTTPException, status # type: ignore
from fastapi.responses import JSONResponse # type: ignore
from pydantic import BaseModel # type: ignore

# Ensure the 'chatbot_modules' directory is in the Python path for module imports
current_dir = os.path.dirname(os.path.abspath(__file__))
chatbot_modules_path = os.path.join(current_dir, "chatbot_modules")
if chatbot_modules_path not in sys.path:
    sys.path.insert(0, chatbot_modules_path)

# Import core modules from chatbot_modules
try:
    from chatbot_modules import config
    # Changed: Import local_llm and gemini_llm as modules
    import chatbot_modules.local_llm as local_llm_module
    import chatbot_modules.gemini_llm as gemini_llm_module

    from chatbot_modules.nmap_parser import process_nmap_report_file
    from chatbot_modules.zap_parser import process_zap_report_file
    from chatbot_modules.ssl_parser import process_sslscan_report_file
    # The summarizer imports remain the same, but their internal calls will change
    from chatbot_modules.summarizer import summarize_report_with_llm, summarize_chat_history_segment
    from chatbot_modules.pdf_extractor import extract_text_from_pdf
    from chatbot_modules.utils import (
        load_embedding_model, 
        initialize_pinecone_index, 
        retrieve_rag_context, 
        load_report_chunks_and_embeddings, 
        retrieve_internal_rag_context, 
        delete_report_namespace 
    )
    from chatbot_modules.cleanup_utils import delete_namespace, clear_uploaded_files
except ImportError as e:
    print(f"Error importing a module: {e}")
    print("Please ensure all modules are correctly configured in your Python path.")
    sys.exit(1)

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8100", "http://127.0.0.1:8100"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration for file uploads
UPLOAD_FOLDER = os.path.join(current_dir, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size

# Global state for LLM and RAG components (loaded once)
_llm_instances_global: Dict[str, Any] = {} # To hold {'local': local_llm_instance, 'gemini': gemini_llm_instance}
_llm_generate_funcs_global: Dict[str, Any] = {} # To hold {'local': local_generate_func, 'gemini': gemini_generate_func}
_embedding_model_instance_global = None
_pinecone_index_instance_global = None

# A lock to prevent multiple threads from initializing LLM/RAG simultaneously
_init_lock = threading.Lock()

# In-memory session store (replace with Redis/DB for production)
_session_store: Dict[str, Dict[str, Any]] = {}

# --- Pydantic Models for Request Bodies ---
class ChatMessage(BaseModel):
    """Pydantic model for incoming chat messages."""
    message: str
    session_id: Optional[str] = None 
    
class ClearChatRequest(BaseModel):
    """Pydantic model for clearing a chat session."""
    session_id: str

def _init_global_llm_and_rag():
    """
    Initializes global LLM and RAG components if they haven't been already.
    This function uses a lock to ensure thread-safe initialization.
    """
    global _llm_instances_global, _llm_generate_funcs_global, _embedding_model_instance_global, _pinecone_index_instance_global

    with _init_lock:
        if not _llm_instances_global: # Only initialize LLMs if not already done
            logger.info("Initializing global LLM instances...")
            
            # --- Initialize Local LLM ---
            try:
                local_model_instance = local_llm_module.load_model(
                    model_id=config.LLM_MODEL_ID,
                    model_basename=config.LLM_MODEL_BASENAME,
                    local_dir=config.LLM_MODEL_DIR
                )
                _llm_instances_global["local"] = local_model_instance
                _llm_generate_funcs_global["local"] = local_llm_module.generate_response
                logger.info("Local LLM initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize Local LLM: {e}")
                # Decide if this should be a fatal error or just disable local LLM

            # --- Initialize Gemini LLM (only if API key is set) ---
            if config.GEMINI_API_KEY:
                try:
                    # gemini_llm.py's load_model takes args, kwargs
                    gemini_model_instance = gemini_llm_module.load_model(
                        api_key=config.GEMINI_API_KEY # Pass the API key if needed by the loader
                    )
                    _llm_instances_global["gemini"] = gemini_model_instance
                    _llm_generate_funcs_global["gemini"] = gemini_llm_module.generate_response
                    logger.info("Gemini LLM initialized successfully.")
                except Exception as e:
                    logger.warning(f"Failed to initialize Gemini LLM (API key might be missing or invalid): {e}")
            else:
                logger.info("Skipping Gemini LLM initialization: GEMINI_API_KEY not found in environment.")

            # If neither LLM could be initialized, raise an error
            if not _llm_instances_global:
                raise RuntimeError("No LLM could be initialized. Please check your configuration and environment variables.")
            
        # --- RAG Initialization (remains the same as before) ---
        if _embedding_model_instance_global is None:
            logger.info("Initializing global embedding model...")
            try:
                _embedding_model_instance_global = load_embedding_model()
                logger.info("Global embedding model loaded.")
            except Exception as e:
                logger.error(f"Failed to load global embedding model: {e}")
                _embedding_model_instance_global = None

        if _pinecone_index_instance_global is None and _embedding_model_instance_global is not None:
            logger.info("Initializing global Pinecone index...")
            try:
                _pinecone_index_instance_global = initialize_pinecone_index()
                logger.info("Global Pinecone index initialized.")
            except Exception as e:
                logger.error(f"Failed to initialize global Pinecone index: {e}")
                _pinecone_index_instance_global = None

def get_llm_instance():
    """
    Returns the global LLM instance, initializing if necessary.
    Raises HTTPException if LLM instance cannot be loaded.
    """
    if _llm_instances_global is None:
        _init_global_llm_and_rag()
    if _llm_instances_global is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="LLM instance not available.")
    return _llm_instances_global

def get_embedding_model_instance():
    """
    Returns the global embedding model instance, initializing if necessary.
    """
    if _embedding_model_instance_global is None:
        _init_global_llm_and_rag()
    return _embedding_model_instance_global

def get_pinecone_index_instance():
    """
    Returns the global Pinecone index instance, initializing if necessary.
    """
    if _pinecone_index_instance_global is None:
        _init_global_llm_and_rag()
    return _pinecone_index_instance_global


@app.on_event("startup")
async def startup_event():
    """Initializes global resources when the FastAPI app starts."""
    logger.info("FastAPI app startup event - Initializing global LLM and RAG components.")
    _init_global_llm_and_rag()
    logger.info("Global resources initialization complete.")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleans up global resources when the FastAPI app shuts down."""
    global _llm_instances_global, _embedding_model_instance_global, _pinecone_index_instance_global

    logger.info("FastAPI app shutdown event - Cleaning up global resources...")
    
    # Close LLM model if it has a close method
    if _llm_instances_global is not None:
        try:
            if hasattr(_llm_instances_global, 'close') and callable(_llm_instances_global.close):
                _llm_instances_global.close()
                logger.info("Global LLM model closed.")
            _llm_instances_global = None
        except Exception as e:
            logger.error(f"Error during global LLM model closing: {e}")

    _embedding_model_instances_global = None
    _pinecone_index_instance_global = None
    logger.info("Global resources cleanup complete.")


def detect_report_type_web(filename: str) -> Optional[str]:
    """
    Attempts to detect the security report type using ONLY the filename.
    """
    lower_filename = filename.lower()
    logger.info(f"Attempting report type detection using only filename: '{filename}'")

    # --- Filename-based Detection ---
    if 'nmap' in lower_filename:
        logger.info("Detected 'nmap' from filename.")
        return "nmap"
    if 'zap' in lower_filename:
        logger.info("Detected 'zap' from filename.")
        return "zap"
    if 'ssl' in lower_filename:
        logger.info("Detected 'sslscan' from filename.")
        return "sslscan"
    # If no keywords match, return None
    logger.warning(f"Could not determine report type from filename: '{filename}'")
    return None

def is_report_specific_question_web(question: str, report_data: Dict[str, Any]) -> bool:
    """
    Heuristically determines if a question is specific to the loaded Nmap/ZAP/SSLScan/MobSF/Nikto report.
    This check uses the provided report_data.
    """
    if not report_data:
        return False

    question_lower = question.lower()

    if any(keyword in question_lower for keyword in config.REPORT_SPECIFIC_KEYWORDS):
        return True

    report_tool = report_data.get("scan_metadata", {}).get("tool", "").lower()

    if "nmap" in report_tool:
        for host in report_data.get("hosts", []):
            if host.get("ip_address") and host["ip_address"].lower() in question_lower:
                return True
            if host.get("hostname") and host["hostname"].lower() in question_lower:
                return True
            for port in host.get("ports", []):
                if f"port {port.get('port_id')}" in question_lower or f":{port.get('port_id')}" in question_lower:
                    return True
                if port.get("service") and port["service"].lower() in question_lower:
                    return True

    elif "zap" in report_tool:
            # Pre-process the question once for efficiency
            question_lower = question_lower.lower().strip()
            
            # Keywords list to cover general risk categories
            risk_keywords = ["risk", "vulnerability", "finding", "issue", "security", "alerts"]
            
            # Check for general keywords or a simple risk level match outside the loop
            if any(keyword in question_lower for keyword in risk_keywords) or \
            any(level in question_lower for level in ["high", "medium", "low", "informational"]):
                # This is a general query, highly relevant
                return True

            for vuln in report_data.get("vulnerabilities", []):
                # Check 1: Match by Vulnerability Name (Case-insensitive)
                vuln_name = vuln.get("name")
                if vuln_name and vuln_name.lower() in question_lower:
                    return True

                # Check 2: Match by Standard Identifiers (CWE, WASC, Plugin ID)
                if vuln.get("cwe_id") and f"cwe {vuln['cwe_id']}" in question_lower:
                    return True
                if vuln.get("wasc_id") and f"wasc {vuln['wasc_id']}" in question_lower:
                    return True
                # Added check for the specific Plugin ID, often used in ZAP reports
                if vuln.get("plugin_id") and f"plugin {vuln['plugin_id']}" in question_lower:
                    return True

                # Check 3: Match by Risk Level (Specific to the finding)
                # Removed redundant risk level check as it's often too broad for a specific finding's loop.
                # The general risk check outside the loop covers broad queries.

                # Check 4: Match by Affected URLs (Including TLD/Root Domain)
                # Check the root URL of the finding (present in the JSON structure you provided)
                root_url = vuln.get("url")
                if root_url and root_url.lower() in question_lower:
                    return True
                
                # Check for matches against the root domain from the root URL
                if root_url:
                    try:
                        # Extracts 'testphp.vulnweb.com' from 'http://testphp.vulnweb.com/'
                        domain = root_url.split('//')[-1].split('/')[0].lower()
                        if domain in question_lower:
                            return True
                    except Exception:
                        pass # Safely ignore errors in URL parsing

                # Check 5: Match by Specific Instance URL (If detailed instance data exists)
                for url_detail in vuln.get("urls", []):
                    instance_url = url_detail.get("url")
                    if instance_url and instance_url.lower() in question_lower:
                        return True

            return False
        
    elif "sslscan" in report_tool:
        ssl_metadata = report_data.get("scan_metadata", {})
        if ssl_metadata.get("target_host") and ssl_metadata["target_host"].lower() in question_lower:
            return True
        if ssl_metadata.get("connected_ip") and ssl_metadata["connected_ip"].lower() in question_lower:
            return True
        if ssl_metadata.get("sni_name") and ssl_metadata["sni_name"].lower() in question_lower:
            return True
        
        if any(p.get("name", "").lower() in question_lower for p in report_data.get("protocols", [])):
            return True
        if any(c.get("name", "").lower() in question_lower for c in report_data.get("supported_ciphers", [])):
            return True
        if report_data.get("ssl_certificate", {}).get("subject", "").lower() in question_lower:
            return True
        if report_data.get("ssl_certificate", {}).get("issuer", "").lower() in question_lower:
            return True
        if "tls" in question_lower or "ssl" in question_lower or "cipher" in question_lower or "certificate" in question_lower:
            return True


@app.post("/upload_report")
async def upload_report(
    # --- CORE FIX: Change alias to "file" to match client (curl/Swagger) submission ---
    file: UploadFile = File(..., alias="file"),
    llm_mode: str = Query(config.DEFAULT_LLM_MODE, description=f"Choose LLM mode: {config.SUPPORTED_LLM_MODES}")
):
    """
    Handles PDF file uploads, parses them, and generates an initial summary.
    Returns a session_id for subsequent interactions.
    This version always returns a 200 OK response and handles parsing failures.
    """
    logger.info(f"Received file upload: {file.filename} with LLM mode: {llm_mode}")

    if not file.filename or not file.filename.lower().endswith('.pdf'):
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={'success': False, 'summary': 'Invalid file. Please upload a PDF.', 'report_loaded': False, 'session_id': None}
        )
    
    if llm_mode not in config.SUPPORTED_LLM_MODES:
         return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={'success': False, 'summary': f"Invalid LLM mode. Supported modes are: {config.SUPPORTED_LLM_MODES}", 'report_loaded': False, 'session_id': None}
        )

    filename = f"{uuid.uuid4()}_{file.filename}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
        with open(filepath, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        report_type = detect_report_type_web(file.filename)

        if report_type is None:
            logger.warning(f"Failed to detect a supported report type for file: {file.filename}")
            error_message = 'Could not identify the report. Please upload a valid report generated by our Scanning Engine.'
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={'success': False, 'summary': error_message, 'report_loaded': False, 'session_id': None}
            )

        logger.info(f"Detected report type: '{report_type}' for file: {file.filename}")

        session_id = str(uuid.uuid4())
        _session_store[session_id] = {
            'chat_history': [],
            'current_parsed_report': None,
            'current_report_type': None,
            'current_report_namespace': None,
            'llm_mode': llm_mode
        }
        logger.info(f"Session {session_id} created with LLM mode: {llm_mode}")

        parsed_data = None
        if report_type == 'nmap':
            parsed_data = process_nmap_report_file(filepath)
        elif report_type == 'zap':
            parsed_data = process_zap_report_file(filepath)
        elif report_type == 'sslscan':
            parsed_data = process_sslscan_report_file(filepath)

        if parsed_data:
            session_data = _session_store[session_id]
            session_data['current_parsed_report'] = parsed_data
            session_data['current_report_type'] = report_type
            
            # --- CRITICAL CHANGE IS HERE ---
            # Re-introducing the logic for chunking and embedding the report data.
            embedding_model = get_embedding_model_instance()
            pinecone_index = get_pinecone_index_instance()

            if embedding_model and pinecone_index:
                report_namespace = load_report_chunks_and_embeddings(parsed_data, report_type, session_id)
                if report_namespace:
                    session_data['current_report_namespace'] = report_namespace
                    logger.info(f"Report data loaded into namespace: {report_namespace} for session {session_id}")
                else:
                    logger.warning(f"Failed to load report data into Pinecone namespace for session {session_id}.")
            else:
                logger.warning("RAG components (embedding model or Pinecone) not available. Proceeding without report RAG.")
            # --- END OF CRITICAL CHANGE ---

            llm_instance = _llm_instances_global.get(llm_mode)
            llm_generate_func = _llm_generate_funcs_global.get(llm_mode)
            
            initial_summary = await summarize_report_with_llm(llm_instance, llm_generate_func, parsed_data, report_type)

            session_data['chat_history'].append({"role": "assistant", "content": initial_summary})
            
            return JSONResponse(content={'success': True, 'summary': initial_summary, 'report_loaded': True, 'session_id': session_id})
        else:
            logger.error(f"Failed to parse data from a '{report_type}' report: {file.filename}. The file might be empty or malformed.")
            error_message = f"The tool '{report_type.upper()}' was identified, but the report is empty or could not be parsed. Please check the file and try again."
            del _session_store[session_id]
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={'success': False, 'summary': error_message, 'report_loaded': False, 'session_id': None}
            )

    except Exception as e:
        logger.error(f"An unexpected error occurred processing file {file.filename}: {e}", exc_info=True)
        if 'session_id' in locals() and session_id in _session_store:
            del _session_store[session_id]
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={'success': False, 'summary': 'An unexpected server error occurred while processing the file.', 'report_loaded': False, 'session_id': None}
        )
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)
            logger.info(f"Cleaned up temporary file: {filepath}")


@app.post("/chat")
async def chat(chat_message: ChatMessage):
    """Handles user chat messages and returns AI responses."""
    user_question = chat_message.message
    # Get session_id from the request. If not provided, it means a new general chat.
    session_id = chat_message.session_id 

    # If session_id is not provided or not found in store, create a new general session
    if not session_id or session_id not in _session_store:
        # Generate a new session ID for general chat
        new_session_id = str(uuid.uuid4())
        # Initialize a new session entry
        _session_store[new_session_id] = {
            'chat_history': [],
            'current_parsed_report': None, # No report for general chat
            'current_report_type': None,   # No report type
            'current_report_namespace': None, # No dedicated Pinecone namespace
            'llm_mode': config.DEFAULT_LLM_MODE # Use default LLM for general chat
        }
        session_id = new_session_id # Use the newly created session ID
        logger.info(f"New general chat session started: {session_id}")
    
    session_data = _session_store[session_id]

    # Retrieve the LLM mode stored for this session, default to 'local' if not found
    llm_mode = session_data.get('llm_mode', config.DEFAULT_LLM_MODE) 
    
    # Select the appropriate LLM instance and generate function for this session
    llm_instance_for_session = _llm_instances_global.get(llm_mode)
    llm_generate_func_for_session = _llm_generate_funcs_global.get(llm_mode)

    # Validate that the selected LLM is actually available/initialized
    if not llm_instance_for_session or not llm_generate_func_for_session:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"LLM mode '{llm_mode}' is not initialized or available for this session. Please check server logs."
        )

    logger.info(f"Processing chat for session {session_id} using LLM mode: {llm_mode}")

    chat_history = session_data.get('chat_history', [])
    current_parsed_report = session_data.get('current_parsed_report')
    current_report_type = session_data.get('current_report_type')     
    current_report_namespace = session_data.get('current_report_namespace')

    chat_history.append({"role": "user", "content": user_question})

    # --- Chat History Management (Sliding Window) ---
    if len(chat_history) > config.CHAT_HISTORY_MAX_TURNS:
        logger.info(f"Chat history exceeding {config.CHAT_HISTORY_MAX_TURNS} turns for session {session_id}. Summarizing older segments.")
        segment_end_index = len(chat_history) - config.CHAT_HISTORY_SUMMARIZE_THRESHOLD
        segment_to_summarize = chat_history[0 : segment_end_index]
        
        if segment_to_summarize:
            summarized_segment_text = await summarize_chat_history_segment(
                llm_instance_for_session, 
                llm_generate_func_for_session, 
                segment_to_summarize,
                max_tokens=config.DEFAULT_SUMMARIZE_MAX_TOKENS
            )
            new_chat_history = [{"role": "system", "content": f"Summary of previous conversation: {summarized_segment_text}"}]
            new_chat_history.extend(chat_history[segment_end_index:])
            chat_history = new_chat_history
            session_data['chat_history'] = chat_history
            logger.info(f"Chat history summarized for session {session_id}.")
        else:
            logger.info(f"No segment to summarize based on threshold for session {session_id}.")

    llm_prompt_content = ""
    rag_context = ""

    # Determine if the question is report-specific and apply internal RAG if applicable
    if current_parsed_report and is_report_specific_question_web(user_question, current_parsed_report):
        logger.info(f"Determined as report-specific question for session {session_id} - attempting INTERNAL RAG.")
        embedding_model = get_embedding_model_instance()
        pinecone_index = get_pinecone_index_instance()

        if current_report_namespace and embedding_model and pinecone_index:
            rag_context = retrieve_internal_rag_context(user_question, current_report_namespace, top_k=config.DEFAULT_RAG_TOP_K)
            if rag_context:
                llm_prompt_content += f"Here is some relevant information from the current report:\n{rag_context}\n\n"
            else:
                llm_prompt_content += "No specific relevant information found in the current report for this query. "
                logger.info(f"No INTERNAL RAG context found for report-specific question for session {session_id}.")
        else:
            llm_prompt_content += "Internal RAG components not available or report not loaded into Pinecone. Answering based on initial summary and general knowledge.\n"
            logger.warning(f"Internal RAG not available for report-specific question for session {session_id}.")
        
        llm_prompt_content += f"The user is asking a question related to the previously provided {current_report_type.upper()} security report. Please refer to the report's content and your previous summary to answer.\n"
    else:
        # If not report-specific (or no report loaded), attempt external RAG
        logger.info(f"Determined as general cybersecurity question for session {session_id} - attempting EXTERNAL RAG.")
        embedding_model = get_embedding_model_instance()
        pinecone_index = get_pinecone_index_instance()

        if embedding_model and pinecone_index:
            rag_context = retrieve_rag_context(user_question, top_k=config.DEFAULT_RAG_TOP_K, namespace="owasp-cybersecurity-kb") 
            if rag_context:
                llm_prompt_content += f"Here is some relevant information from a cybersecurity knowledge base:\n{rag_context}\n\n"
            else:
                llm_prompt_content += "No specific relevant information found in the knowledge base for this query. "
                logger.info(f"No EXTERNAL RAG context found for session {session_id}.")
        else:
            llm_prompt_content += "RAG components not loaded or initialized. Answering based on general knowledge and chat history.\n"
            logger.warning(f"RAG components not available for general question for session {session_id}.")

    concatenated_prompt = ""
    for msg in chat_history:
        if msg["role"] == "user":
            concatenated_prompt += f"User: {msg['content']}\n"
        elif msg["role"] == "assistant":
            concatenated_prompt += f"Assistant: {msg['content']}\n"
        elif msg["role"] == "system":
            concatenated_prompt += f"System: {msg['content']}\n"
    
    final_llm_prompt = f"{llm_prompt_content}\n{concatenated_prompt}\nAssistant:"

    try:
        llm_response = await llm_generate_func_for_session(llm_instance_for_session, final_llm_prompt, max_tokens=config.DEFAULT_MAX_TOKENS)
        
        chat_history.append({"role": "assistant", "content": llm_response})
        session_data['chat_history'] = chat_history # Update session data

        # Return the session_id with the response so Flask can store it for subsequent general chats
        return JSONResponse(content={'success': True, 'response': llm_response, 'chat_history': chat_history, 'session_id': session_id})

    except Exception as e:
        logger.error(f"Error generating LLM response for session {session_id} using {llm_mode} LLM: {e}", exc_info=True)
        if chat_history and chat_history[-1]["role"] == "user":
            chat_history.pop() 
        session_data['chat_history'] = chat_history 
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f'An error occurred while generating response: {e}')


@app.post("/clear_chat")
async def clear_chat(request: Request, request_body: ClearChatRequest):
    """
    Clears the current chat session for a given session ID,
    including deleting the associated Pinecone namespace and uploaded files.
    """
    logger.info(f"DEBUG: FastAPI /clear_chat RECEIVED REQUEST.")
    logger.info(f"DEBUG: Request Method: {request.method}")
    logger.info(f"DEBUG: Request Headers: {request.headers}")
    
    try:
        raw_body = await request.body()
        logger.info(f"DEBUG: Raw Request Body: {raw_body.decode('utf-8')}")
    except Exception as e:
        logger.error(f"DEBUG: Could not read raw request body: {e}")

    session_id = request_body.session_id
    logger.info(f"DEBUG: Processing clear_chat for session_id: {session_id}")

    if session_id not in _session_store:
        logger.warning(f"Session ID {session_id} not found in store.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    # Clear Pinecone namespace
    namespace_success, namespace_message = delete_namespace(session_id)
    if not namespace_success:
        logger.warning(f"Failed to clear Pinecone namespace: {namespace_message}")
    else:
        logger.info(f"Pinecone namespace cleared: {namespace_message}")

    # Clear uploaded files
    uploads_success, uploads_message = clear_uploaded_files(session_id)
    if not uploads_success:
        logger.warning(f"Failed to clear uploaded files: {uploads_message}")
    else:
        logger.info(f"Uploaded files cleared: {uploads_message}")

    # Remove session data from the store
    del _session_store[session_id]
    logger.info(f"Chat and report context cleared for session {session_id}.")
    
    return JSONResponse(content={
        'success': True, 
        'message': 'Chat, report context, and associated data cleared.',
        'namespace_cleared': namespace_success,
        'uploads_cleared': uploads_success
    })

# To run this FastAPI application, save this code as, for example, `app.py`.
# Then, execute the following command in your terminal:
# uvicorn app:app --host 0.0.0.0 --port 5000 --reload
# The '--reload' flag is useful for development as it restarts the server on code changes.
# For production, remove '--reload' and ensure your environment is set up correctly.