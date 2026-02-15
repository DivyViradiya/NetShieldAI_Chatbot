import os
import sys
import json
import logging
import uuid
import threading
import time
import asyncio
import re  # <--- Added for text normalization
from typing import Dict, Any, List, Optional
import dotenv

# --- FASTAPI & PYDANTIC IMPORTS ---
from fastapi import FastAPI, Request, File, UploadFile, HTTPException, status, Query, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse 
from starlette.concurrency import iterate_in_threadpool 
from pydantic import BaseModel

dotenv.load_dotenv()

current_dir = os.path.dirname(os.path.abspath(__file__))
chatbot_modules_path = os.path.join(current_dir, "chatbot_modules")
if chatbot_modules_path not in sys.path:
    sys.path.insert(0, chatbot_modules_path)

try:
    from chatbot_modules import config
    import chatbot_modules.local_llm as local_llm_module
    import chatbot_modules.gemini_llm as gemini_llm_module
    
    import chatbot_modules.db_utils as db_utils

    from chatbot_modules.nmap_parser import process_nmap_report_file
    from chatbot_modules.zap_parser import process_zap_report_file
    from chatbot_modules.ssl_parser import process_sslscan_report_file
    from chatbot_modules.pcap_parser import process_pcap_report_file
    from chatbot_modules.sql_parser import process_sql_report_file
    from chatbot_modules.killchain_parser import process_killchain_report_file
    
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
    from chatbot_modules.agent_tools import SECURITY_TOOLS
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
_llm_instances_global: Dict[str, Any] = {} 
_llm_generate_funcs_global: Dict[str, Any] = {} 
_embedding_model_instance_global = None
_pinecone_index_instance_global = None

# A lock to prevent multiple threads from initializing LLM/RAG simultaneously
_init_lock = threading.Lock()

# --- Pydantic Models for Request Bodies ---
class ChatMessage(BaseModel):
    """Pydantic model for incoming chat messages with options."""
    message: str
    session_id: Optional[str] = None
    user_id: str 
    verbosity: Optional[str] = "standard" # concise, standard, detailed
    is_incognito: Optional[bool] = False
    
class ClearChatRequest(BaseModel):
    """Pydantic model for clearing a chat session (Legacy/Full Reset)."""
    session_id: str
    user_id: Optional[str] = None

class ClearHistoryRequest(BaseModel):
    """New model for wiping messages but keeping the report context."""
    session_id: str

class DeleteAllSessionsRequest(BaseModel):
    """New model for bulk user cleanup."""
    user_id: str

# --- NEW PYDANTIC MODELS FOR SESSION MANAGEMENT ---
class RenameRequest(BaseModel):
    session_id: str
    new_title: str

class PinRequest(BaseModel):
    session_id: str
    is_pinned: bool

class DeleteSessionRequest(BaseModel):
    session_id: str

# --- NEW HELPER: Retry Logic for API Quotas ---
async def execute_with_retry(func, *args, **kwargs):
    """
    Executes an async function with automatic retry logic for Gemini 429 errors.
    """
    max_retries = 3
    base_delay = 30  
    
    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            error_str = str(e).lower()
            if "429" in error_str or "quota" in error_str or "exhausted" in error_str:
                if attempt < max_retries - 1:
                    logger.warning(f"Gemini Quota Exceeded. Retrying in {base_delay} seconds... (Attempt {attempt + 1}/{max_retries})")
                    await asyncio.sleep(base_delay)
                    base_delay += 10 
                else:
                    logger.error("Max retries reached for Gemini API.")
                    raise e
            else:
                raise e

def _init_global_llm_and_rag():
    """
    Initializes global LLM and RAG components if they haven't been already.
    """
    global _llm_instances_global, _llm_generate_funcs_global, _embedding_model_instance_global, _pinecone_index_instance_global

    with _init_lock:
        if not _llm_instances_global: 
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

            # --- Initialize Gemini LLM with Tools ---
            if config.GEMINI_API_KEY:
                try:
                    model_name_to_use = getattr(config, 'GEMINI_MODEL_NAME', 'gemini-1.5-flash')
                    
                    gemini_model_instance = gemini_llm_module.load_model(
                        api_key=config.GEMINI_API_KEY,
                        model_name=model_name_to_use,
                        tools=SECURITY_TOOLS
                    )
                    _llm_instances_global["gemini"] = gemini_model_instance
                    _llm_generate_funcs_global["gemini"] = gemini_llm_module.generate_response
                    logger.info(f"Gemini AI Agent initialized: {model_name_to_use}")
                except Exception as e:
                    logger.warning(f"Failed to initialize Gemini AI Agent: {e}")
            else:
                logger.info("Skipping Gemini LLM initialization: GEMINI_API_KEY not found.")

            if not _llm_instances_global:
                raise RuntimeError("No LLM could be initialized. Please check your configuration.")
            
        # --- RAG Initialization ---
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
    if _llm_instances_global is None:
        _init_global_llm_and_rag()
    if _llm_instances_global is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="LLM instance not available.")
    return _llm_instances_global

def get_embedding_model_instance():
    if _embedding_model_instance_global is None:
        _init_global_llm_and_rag()
    return _embedding_model_instance_global

def get_pinecone_index_instance():
    if _pinecone_index_instance_global is None:
        _init_global_llm_and_rag()
    return _pinecone_index_instance_global


@app.on_event("startup")
async def startup_event():
    """Initializes global resources when the FastAPI app starts."""
    logger.info("FastAPI starting up...")
    
    # --- PHASE 1: INIT DATABASE ---
    try:
        db_utils.init_db()
        logger.info("SQLite Database Initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
    
    _init_global_llm_and_rag()
    logger.info("Startup complete.")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleans up global resources when the FastAPI app shuts down."""
    global _llm_instances_global, _embedding_model_instance_global, _pinecone_index_instance_global

    logger.info("FastAPI app shutdown event - Cleaning up global resources...")
    
    if _llm_instances_global is not None:
        try:
            if hasattr(_llm_instances_global, 'close') and callable(_llm_instances_global.close):
                _llm_instances_global.close()
                logger.info("Global LLM model closed.")
            _llm_instances_global = None
        except Exception as e:
            logger.error(f"Error during global LLM model closing: {e}")

    _embedding_model_instance_global = None
    _pinecone_index_instance_global = None
    logger.info("Global resources cleanup complete.")

# --- IMPROVED REPORT DETECTION LOGIC ---
def detect_report_type_from_content(text: str) -> str:
    """
    Identifies the report type by scanning ONLY the first line (Header) of the PDF.
    This prevents false positives if keywords appear in the body text.
    """
    if not text:
        logger.warning("Detection failed: Extracted text is empty.")
        return "generic_pdf"
    
    # --- ISOLATE HEADER (FIRST LINE) ---
    # Split by newlines and take the first non-empty line
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    first_line = lines[0].lower() if lines else ""

    # Normalize: Replace multiple spaces/tabs with single space within that line
    clean_header = re.sub(r'\s+', ' ', first_line).strip()

    # --- DEBUGGING ---
    # logger.info(f"DEBUG - PDF Header Detection: '{clean_header}'") 

    # --- HEADER MAPPING ---
    
    # 1. Kill Chain (Exact Match Preference)
    if "kill chain analysis" in clean_header:
        return "killchain"

    # 2. NMAP
    if "network Scan" in clean_header or "nmap scan report" in clean_header:
        return "nmap"
    
    # 3. PCAP
    if "network traffic" in clean_header:
        return "pcap"
    
    # 4. ZAP
    if "web vulnerability" in clean_header or "owasp zap" in clean_header:
        return "zap"
    
    # 5. SSL
    if "ssl/tls assessment" in clean_header or "sslscan" in clean_header:
        return "sslscan"
    
    # 6. SQL Injection
    if "sql injection security" in clean_header or "sqlmap" in clean_header:
        return "sql"

    # Fallback
    logger.info(f"No known report header found in: '{clean_header}'. Defaulting to generic_pdf.")
    return "generic_pdf"
    

def is_report_specific_question_web(question: str, report_data: Dict[str, Any]) -> bool:
    """
    Heuristically determines if a question is specific to the loaded report.
    """
    if not report_data:
        return False

    question_lower = question.lower()
    
    # 1. Check for explicit keywords
    if any(keyword in question_lower for keyword in config.REPORT_SPECIFIC_KEYWORDS):
        return True

    # 2. Get tool type from metadata
    report_tool = report_data.get("scan_metadata", {}).get("tool", "").lower()

    # --- Handle Generic/PCAP/SQL Questions ---
    if "generic" in report_tool or "pcap" in report_tool or "sql" in report_tool or "kill_chain" in report_tool:
        return True

    # 3. Tool-specific Logic
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
            question_lower = question_lower.lower().strip()
            risk_keywords = ["risk", "vulnerability", "finding", "issue", "security", "alerts"]
            
            if any(keyword in question_lower for keyword in risk_keywords) or \
            any(level in question_lower for level in ["high", "medium", "low", "informational"]):
                return True

            for vuln in report_data.get("vulnerabilities", []):
                vuln_name = vuln.get("name")
                if vuln_name and vuln_name.lower() in question_lower:
                    return True
                if vuln.get("cwe_id") and f"cwe {vuln['cwe_id']}" in question_lower:
                    return True
                if vuln.get("plugin_id") and f"plugin {vuln['plugin_id']}" in question_lower:
                    return True
                root_url = vuln.get("url")
                if root_url and root_url.lower() in question_lower:
                    return True
        
    elif "sslscan" in report_tool:
        ssl_metadata = report_data.get("scan_metadata", {})
        if ssl_metadata.get("target_host") and ssl_metadata["target_host"].lower() in question_lower:
            return True
        if "tls" in question_lower or "ssl" in question_lower or "certificate" in question_lower:
            return True
        
    elif "pcap" in report_tool or "traffic" in report_tool:
        # Check for traffic keywords
        traffic_keywords = ["bandwidth", "throughput", "packet", "volume", "protocol", "conversation", "layer", "bytes"]
        if any(k in question_lower for k in traffic_keywords):
            return True
            
        # Check against active conversations (IPs)
        for conv in report_data.get("active_conversations", []):
            src = conv.get("src_ip", "")
            dst = conv.get("dst_ip", "")
            if src and src in question_lower: return True
            if dst and dst in question_lower: return True
            
        # Check against protocols found
        for proto in report_data.get("protocol_hierarchy", []):
            p_name = proto.get("protocol", "").lower()
            if p_name and p_name in question_lower: return True
    
    elif "sql" in report_tool or "database" in report_tool:
        # 1. Check for generic SQL Injection keywords
        sql_keywords = [
            "injection", "sqli", "database", "query", "payload", "vulnerability",
            "sanitize", "parameter", "waf", "union", "blind", "error-based",
            "time-based", "boolean", "sleep", "benchmark", "schema", "column"
        ]
        if any(k in question_lower for k in sql_keywords):
            return True

        # 2. Check against the specific Target URL
        # Matches: "Is testphp.vulnweb.com vulnerable?"
        target = report_data.get("metadata", {}).get("target_url", "").lower()
        if target and target in question_lower: 
            return True

        # 3. Check against Database Fingerprint details
        # Matches: "What version of MySQL is running?", "Is the 'acuart' user exposed?"
        fingerprint = report_data.get("database_fingerprint", {})
        dbms = fingerprint.get("detected_dbms", "").lower()      # e.g., "mysql >= 5.6"
        db_user = fingerprint.get("current_user", "").lower()    # e.g., "acuart@localhost"
        db_name = fingerprint.get("current_database", "").lower() # e.g., "acuart"

        # Simple substring checks usually suffice here
        if dbms and (dbms.split()[0] in question_lower): return True # Check just "mysql" part
        if db_user and db_user in question_lower: return True
        if db_name and db_name in question_lower: return True

        # 4. Check against specific Vulnerability Types found
        # Matches: "Explain the boolean-blind injection found."
        for vuln in report_data.get("vulnerabilities", []):
            inj_type = vuln.get("injection_type", "").lower()
            if inj_type and inj_type in question_lower:
                return True        
    
    elif "killchain" in report_tool or "kill_chain" in report_tool or "full_audit" in report_tool:
        # 1. Generic Kill Chain & Phase Keywords
        kc_keywords = [
            "kill chain", "killchain", "reconnaissance", "recon", "weaponization", 
            "delivery", "exploitation", "phase", "attack surface", "risk profile", 
            "critical", "severity", "audit", "security posture", "subdomain", 
            "technology", "stack", "fingerprint"
        ]
        if any(k in question_lower for k in kc_keywords):
            return True

        # 2. Check against Target Identity (Hostname & IP)
        # Matches: "What is the risk for testphp.vulnweb.com?", "Is 44.228... exposed?"
        meta = report_data.get("metadata", {})
        recon = report_data.get("phase_analysis", {}).get("recon", {})
        
        target = meta.get("target", "").lower()
        target_ip = recon.get("target_ip", "")
        
        if target and target in question_lower: return True
        if target_ip and target_ip in question_lower: return True

        # 3. Check against Open Ports found in Recon
        # Matches: "Is port 80 open?", "What services are running on tcp?"
        if "port" in question_lower: return True
        
        for port_entry in recon.get("open_ports", []):
            # entry format example: "80/TCP (HTTP)"
            # Check if the port number (e.g., "80") appears specifically in the question
            port_num = port_entry.split('/')[0]
            if port_num and f" {port_num} " in f" {question_lower} ": # basic boundary check
                return True

        # 4. Check against Tech Stack (Phase 2)
        # Matches: "Is the Nginx version vulnerable?", "What PHP exploits were found?"
        tech = report_data.get("phase_analysis", {}).get("weaponization", {})
        server = tech.get("server", "").lower()   # e.g., "nginx/1.19.0"
        lang = tech.get("language", "").lower()   # e.g., "php"
        
        # Check base names (e.g. check "nginx" from "nginx/1.19.0")
        if server and (server.split('/')[0] in question_lower): return True
        if lang and lang in question_lower: return True

        # 5. Check against Specific Vulnerabilities Found
        # Matches: "Explain the SSRF finding", "How do I fix the SQL Injection?"
        # The Kill Chain report aggregates many types, so we check the 'title' field.
        for vuln in report_data.get("vulnerabilities", []):
            title = vuln.get("title", "").lower()
            if title and title in question_lower:
                return True
            
            # Helper: Check for common acronyms if they appear in the title (e.g. XSS, CSRF, IDOR)
            # This handles cases where user asks "Fix XSS" and title is "Cross Site Scripting"
            # (Assuming the title itself might contain the acronym or the user knows it)
            if "xss" in question_lower and "cross site scripting" in title: return True
            if "sqli" in question_lower and "sql injection" in title: return True
            if "csrf" in question_lower and "cross-site request forgery" in title: return True
    
    return False


@app.post("/upload_report")
async def upload_report(
    file: Optional[UploadFile] = File(None, alias="file"),
    llm_mode: str = Query(config.DEFAULT_LLM_MODE, description=f"Choose LLM mode: {config.SUPPORTED_LLM_MODES}"),
    user_id: str = Query(..., description="Unique user identifier from the client"),
    file_path: Optional[str] = Query(None, description="Direct absolute path to the PDF on the server's disk")
):
    """
    Handles file uploads OR path-based analysis. 
    Path-based analysis (file_path) is faster as it skips binary transfer.
    """
    logger.info(f"Report Request - User: {user_id}, Path-based: {bool(file_path)}")

    # 1. Validation: We need EITHER a file upload OR a local file path
    if not file and not file_path:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={'success': False, 'summary': 'No file or file path provided.', 'report_loaded': False}
        )
    
    # 2. Path-based Logic (SHARED STORAGE)
    if file_path:
        if not os.path.exists(file_path):
             return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={'success': False, 'summary': f'File not found on server disk: {file_path}', 'report_loaded': False}
            )
        target_file_to_process = file_path
        original_filename = os.path.basename(file_path)
        is_temporary_file = False # Don't delete files that exist on disk elsewhere
    
    # 3. Upload-based Logic (TRADITIONAL)
    else:
        if not file.filename or not file.filename.lower().endswith('.pdf'):
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={'success': False, 'summary': 'Invalid file. Please upload a PDF.', 'report_loaded': False}
            )
        
        filename = f"{uuid.uuid4()}_{file.filename}"
        target_file_to_process = os.path.join(UPLOAD_FOLDER, filename)
        original_filename = file.filename
        is_temporary_file = True # Clean up after processing

        try:
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            with open(target_file_to_process, "wb") as buffer:
                content = await file.read()
                buffer.write(content)
        except Exception as e:
            logger.error(f"Failed to save uploaded file: {e}")
            return JSONResponse(status_code=500, content={'success': False, 'summary': 'Internal server error saving file.'})

    if llm_mode not in config.SUPPORTED_LLM_MODES:
         return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={'success': False, 'summary': f"Invalid LLM mode. Supported modes are: {config.SUPPORTED_LLM_MODES}", 'report_loaded': False}
        )

    try:
        # --- PROCESSING PIPELINE ---
        
        # 1. Extract text immediately
        extracted_text = extract_text_from_pdf(target_file_to_process)
        
        # 2. Run detection on the extracted text
        report_type = detect_report_type_from_content(extracted_text)
        
        # GENERATE NEW SESSION ID FOR THIS REPORT
        session_id = str(uuid.uuid4())
        logger.info(f"New session {session_id} - Type: {report_type}")

        parsed_data = None
        
        # 3. Parsing Logic (Dispatch based on detected content)
        if report_type == 'nmap':
            parsed_data = process_nmap_report_file(target_file_to_process)
        elif report_type == 'zap':
            parsed_data = process_zap_report_file(target_file_to_process)
        elif report_type == 'sslscan':
            parsed_data = process_sslscan_report_file(target_file_to_process)
        elif report_type == 'pcap':
            parsed_data = process_pcap_report_file(target_file_to_process)
        elif report_type == 'killchain':
            parsed_data = process_killchain_report_file(target_file_to_process)
        elif report_type == 'sql':
            parsed_data = process_sql_report_file(target_file_to_process)
        else:
            # Fallback to Generic PDF
            if extracted_text and len(extracted_text.strip()) > 50:
                parsed_data = {
                    "raw_text": extracted_text,
                    "scan_metadata": {
                        "tool": "generic_pdf", 
                        "filename": original_filename
                    }
                }
            else:
                parsed_data = None

        if parsed_data:
            report_namespace = None
            
            # --- RAG: Embed and Store ---
            embedding_model = get_embedding_model_instance()
            pinecone_index = get_pinecone_index_instance()

            if embedding_model and pinecone_index:
                report_namespace = load_report_chunks_and_embeddings(parsed_data, report_type, session_id)
            else:
                logger.warning("RAG components not available.")

            # --- Persist Session to Database ---
            try:
                initial_title = f"{report_type.upper()} Analysis" if report_type != "generic_pdf" else original_filename
                db_utils.update_or_create_session(
                    user_id=user_id,
                    session_id=session_id,
                    report_type=report_type,
                    pinecone_namespace=report_namespace,
                    parsed_report_data=parsed_data,
                    title=initial_title
                )
            except Exception as e:
                 logger.error(f"Failed to persist session to database: {e}")

            # --- Generate Summary ---
            llm_instance = _llm_instances_global.get(llm_mode)
            llm_generate_func = _llm_generate_funcs_global.get(llm_mode)
            
            initial_summary = await execute_with_retry(
                summarize_report_with_llm, 
                llm_instance, 
                llm_generate_func, 
                parsed_data, 
                report_type
            )
            
            db_utils.add_message(session_id, "assistant", initial_summary)
            
            return JSONResponse(content={'success': True, 'summary': initial_summary, 'report_loaded': True, 'session_id': session_id})
        else:
            logger.error(f"Failed to parse data from {original_filename}.")
            return JSONResponse(
                status_code=200,
                content={'success': False, 'summary': "The file could not be parsed.", 'report_loaded': False}
            )

    except Exception as e:
        logger.error(f"Unexpected error processing {original_filename}: {e}", exc_info=True)
        return JSONResponse(
            status_code=200,
            content={'success': False, 'summary': f'An unexpected error occurred: {str(e)}', 'report_loaded': False}
        )
    finally:
        # Only cleanup if it was a temporary upload
        if is_temporary_file and os.path.exists(target_file_to_process):
            os.remove(target_file_to_process)
            logger.info(f"Cleaned up temporary upload: {target_file_to_process}")


@app.post("/chat")
async def chat(chat_message: ChatMessage):
    """Handles user chat messages and returns AI responses (BLOCKING MODE)."""
    user_question = chat_message.message
    session_id = chat_message.session_id
    user_id = chat_message.user_id 
    verbosity = chat_message.verbosity
    is_incognito = chat_message.is_incognito

    # --- PHASE 1: DB Retrieval ---
    session_data = None
    
    # 1. Try fetching specific session by ID
    if session_id:
        session_data = db_utils.get_session_by_id(session_id)
        
    # 2. If no ID or not found, try getting the user's last active session
    if not session_data:
        session_data = db_utils.get_user_session(user_id)

    # 3. If still no session, create a fresh "General Chat" session
    if not session_data:
        logger.info(f"No existing session found for user {user_id}. Creating new general session.")
        new_session_id = str(uuid.uuid4())
        db_utils.update_or_create_session(
            user_id=user_id, 
            session_id=new_session_id, 
            report_type="General",
            title="General Chat"
        )
        session_id = new_session_id
        session_data = db_utils.get_session_by_id(session_id)
    else:
        # If we found data, ensure we use its ID
        session_id = session_data['session_id']
        # Update timestamp (only if not incognito)
        if not is_incognito:
            db_utils.update_or_create_session(user_id=user_id, session_id=session_id)

    # Extract context from DB
    current_parsed_report = session_data.get('parsed_report_data')
    current_report_type = session_data.get('report_type')
    current_report_namespace = session_data.get('pinecone_namespace')
    
    # Retrieve chat history from DB
    chat_history_db = db_utils.get_chat_history(session_id, limit=config.CHAT_HISTORY_MAX_TURNS + 2)
    chat_history = [{"role": row['role'], "content": row['content']} for row in chat_history_db]

    llm_mode = config.DEFAULT_LLM_MODE
    llm_instance_for_session = _llm_instances_global.get(llm_mode)
    llm_generate_func_for_session = _llm_generate_funcs_global.get(llm_mode)

    if not llm_instance_for_session or not llm_generate_func_for_session:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"LLM mode '{llm_mode}' is not initialized."
        )

    logger.info(f"Chat request - Session: {session_id}, Mode: {llm_mode}, Incognito: {is_incognito}")

    chat_history.append({"role": "user", "content": user_question})
    
    # --- PHASE 1: Persist User Message (Skip if Incognito) ---
    if not is_incognito:
        db_utils.add_message(session_id, "user", user_question)

    # --- Verbosity & System Instruction ---
    system_instruction = ""
    if verbosity == "concise":
        system_instruction = "System: Provide a very brief, concise answer. Avoid fluff.\n"
    elif verbosity == "detailed":
        system_instruction = "System: Provide a detailed, technical deep-dive response with code examples and step-by-step remediation if applicable.\n"

    # --- Summarization Check ---
    summarized_context_str = ""
    if len(chat_history) > config.CHAT_HISTORY_MAX_TURNS:
        logger.info(f"Chat history long. Generating prompt context summary.")
        segment_to_summarize = chat_history[:-1] 
        try:
            summarized_segment_text = await execute_with_retry(
                summarize_chat_history_segment,
                llm_instance_for_session, 
                llm_generate_func_for_session, 
                segment_to_summarize,
                max_tokens=config.DEFAULT_SUMMARIZE_MAX_TOKENS
            )
            summarized_context_str = f"System: Summary of previous conversation: {summarized_segment_text}\n"
        except Exception as e:
            logger.warning(f"Summarization failed: {e}. using raw history.")

    # --- ORCHESTRATOR SYSTEM PROMPT ---
    orchestrator_prompt = (
        "System: You are the NetShieldAI Security Orchestrator AI Agent. Your mission is to assist users in securing their digital assets.\n"
        "1. Identify Intent: Look for intent to scan (e.g., 'scan my site', 'nmap this ip').\n"
        "2. Parameter Gathering: If a tool is needed but parameters are missing, ask for them. DO NOT execute with placeholders.\n"
        "3. Safety: NEVER scan 'localhost' or '127.0.0.1'.\n"
    )

    llm_prompt_content = orchestrator_prompt + system_instruction
    rag_context = ""

    # Determine if Internal RAG is needed
    if current_parsed_report and is_report_specific_question_web(user_question, current_parsed_report):
        logger.info(f"Using Internal RAG context for session {session_id}")
        embedding_model = get_embedding_model_instance()
        pinecone_index = get_pinecone_index_instance()

        if current_report_namespace and embedding_model and pinecone_index:
            rag_context = retrieve_internal_rag_context(user_question, current_report_namespace, top_k=config.DEFAULT_RAG_TOP_K)
            if rag_context:
                llm_prompt_content += f"Here is some relevant information from the current report:\n{rag_context}\n\n"
            else:
                llm_prompt_content += "No specific relevant information found in the current report for this query. "
        else:
            llm_prompt_content += "Internal RAG components not available. Answering based on initial summary and general knowledge.\n"
        
        llm_prompt_content += f"The user is asking a question related to the previously provided {str(current_report_type).upper()} document/report. Please refer to the content and your previous summary to answer.\n"
    else:
        # External RAG
        logger.info(f"Using External RAG context for session {session_id}")
        embedding_model = get_embedding_model_instance()
        pinecone_index = get_pinecone_index_instance()

        if embedding_model and pinecone_index:
            rag_context = retrieve_rag_context(user_question, top_k=config.DEFAULT_RAG_TOP_K, namespace="owasp-cybersecurity-kb") 
            if rag_context:
                llm_prompt_content += f"Here is some relevant information from a cybersecurity knowledge base:\n{rag_context}\n\n"
            else:
                llm_prompt_content += "No specific relevant information found in the knowledge base. "
        else:
            llm_prompt_content += "RAG components not loaded. Answering based on general knowledge.\n"

    concatenated_prompt = ""
    
    if summarized_context_str:
        concatenated_prompt += summarized_context_str
        msg = chat_history[-1]
        concatenated_prompt += f"User: {msg['content']}\n"
    else:
        for msg in chat_history:
            if msg["role"] == "user":
                concatenated_prompt += f"User: {msg['content']}\n"
            elif msg["role"] == "assistant":
                concatenated_prompt += f"Assistant: {msg['content']}\n"
            elif msg["role"] == "system":
                concatenated_prompt += f"System: {msg['content']}\n"
    
    final_llm_prompt = f"{llm_prompt_content}\n{concatenated_prompt}\nAssistant:"

    try:
        # Standard chat call now returns a dict {"text": ..., "tool_call": ...}
        llm_result = await execute_with_retry(
            llm_generate_func_for_session,
            llm_instance_for_session, 
            final_llm_prompt, 
            max_tokens=config.DEFAULT_MAX_TOKENS
        )
        
        llm_response_text = llm_result.get("text", "")
        tool_action = llm_result.get("tool_call")

        # --- PHASE 1: Persist Assistant Response (Skip if Incognito) ---
        if not is_incognito:
            db_utils.add_message(session_id, "assistant", llm_response_text)
        
        return JSONResponse(content={
            'success': True, 
            'response': llm_response_text, 
            'action': tool_action,
            'chat_history': db_utils.get_chat_history(session_id), 
            'session_id': session_id
        })

    except Exception as e:
        logger.error(f"Error generating LLM response for session {session_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f'An error occurred while generating response: {e}')


# --- NEW STREAMING CHAT ENDPOINT ---
@app.post("/chat_stream")
async def chat_stream(chat_message: ChatMessage):
    """
    Handles user chat messages via STREAMING.
    """
    user_question = chat_message.message
    session_id = chat_message.session_id
    user_id = chat_message.user_id 
    verbosity = chat_message.verbosity
    is_incognito = chat_message.is_incognito

    # --- 1. Session Retrieval & Creation ---
    session_data = None
    
    if session_id:
        session_data = db_utils.get_session_by_id(session_id)
        
    if not session_data:
        session_data = db_utils.get_user_session(user_id)

    if not session_data:
        logger.info(f"No existing session found for user {user_id}. Creating new general session.")
        new_session_id = str(uuid.uuid4())
        db_utils.update_or_create_session(
            user_id=user_id, 
            session_id=new_session_id, 
            report_type="General",
            title="General Chat"
        )
        session_id = new_session_id
        session_data = db_utils.get_session_by_id(session_id)
    else:
        session_id = session_data['session_id']
        if not is_incognito:
            db_utils.update_or_create_session(user_id=user_id, session_id=session_id)

    # --- 2. Persist User Message Immediately (Skip if Incognito) ---
    if not is_incognito:
        db_utils.add_message(session_id, "user", user_question)

    # --- 3. Build Context ---
    current_parsed_report = session_data.get('parsed_report_data')
    current_report_type = session_data.get('report_type')
    current_report_namespace = session_data.get('pinecone_namespace')

    # Fetch History
    chat_history_db = db_utils.get_chat_history(session_id, limit=config.CHAT_HISTORY_MAX_TURNS + 2)
    chat_history = [{"role": row['role'], "content": row['content']} for row in chat_history_db]
    
    # System Instruction
    system_instruction = ""
    if verbosity == "concise":
        system_instruction = "System: Provide a very brief, concise answer. Avoid fluff.\n"
    elif verbosity == "detailed":
        system_instruction = "System: Provide a detailed, technical deep-dive response.\n"

    # --- ORCHESTRATOR SYSTEM PROMPT ---
    orchestrator_prompt = (
        "System: You are the NetShieldAI Security Orchestrator AI Agent. Your mission is to assist users in securing their digital assets.\n"
        "1. Identify Intent: Look for intent to scan (e.g., 'scan my site', 'nmap this ip').\n"
        "2. Parameter Gathering: If a tool is needed but parameters are missing, ask for them. DO NOT execute with placeholders.\n"
        "3. Safety: NEVER scan 'localhost' or '127.0.0.1'.\n"
    )

    llm_prompt_content = orchestrator_prompt + system_instruction
    rag_context = ""

    # RAG Logic
    if current_parsed_report and is_report_specific_question_web(user_question, current_parsed_report):
        embedding_model = get_embedding_model_instance()
        pinecone_index = get_pinecone_index_instance()

        if current_report_namespace and embedding_model and pinecone_index:
            rag_context = retrieve_internal_rag_context(user_question, current_report_namespace, top_k=config.DEFAULT_RAG_TOP_K)
            if rag_context:
                llm_prompt_content += f"Here is some relevant information from the current report:\n{rag_context}\n\n"
        
        llm_prompt_content += f"The user is asking a question related to the previously provided {str(current_report_type).upper()} document/report.\n"
    else:
        # External RAG
        embedding_model = get_embedding_model_instance()
        pinecone_index = get_pinecone_index_instance()

        if embedding_model and pinecone_index:
            rag_context = retrieve_rag_context(user_question, top_k=config.DEFAULT_RAG_TOP_K, namespace="owasp-cybersecurity-kb") 
            if rag_context:
                llm_prompt_content += f"Here is some relevant information from a cybersecurity knowledge base:\n{rag_context}\n\n"

    # Build Prompt String
    concatenated_prompt = ""
    for msg in chat_history:
        concatenated_prompt += f"{msg['role'].capitalize()}: {msg['content']}\n"
    
    concatenated_prompt += f"User: {user_question}\n"
    final_llm_prompt = f"{llm_prompt_content}\n{concatenated_prompt}\nAssistant:"

    # --- 4. Stream Generator ---
    async def response_generator():
        llm_mode = config.DEFAULT_LLM_MODE
        full_response_accumulator = ""
        action_found = None
        
        try:
            llm_instance = _llm_instances_global.get(llm_mode)
            if not llm_instance:
                yield "Error: LLM model not loaded."
                return

            if llm_mode == "gemini":
                async for chunk in gemini_llm_module.generate_response_stream(llm_instance, final_llm_prompt):
                    if chunk.startswith("__TOOL_CALL__:"):
                        try:
                            # Format: __TOOL_CALL__:tool_name:{args_dict}
                            parts = chunk.split(":", 2)
                            tool_name = parts[1]
                            import ast
                            args = ast.literal_eval(parts[2])
                            action_found = {"tool": tool_name, "parameters": args}
                            yield f" [Action: Triggering {tool_name}...]"
                        except:
                            logger.error("Failed to parse tool call")
                    else:
                        full_response_accumulator += chunk
                        yield chunk
                        await asyncio.sleep(0.01) 

            elif llm_mode == "local":
                sync_gen = local_llm_module.generate_response_stream(llm_instance, final_llm_prompt)
                async for chunk in iterate_in_threadpool(sync_gen):
                    full_response_accumulator += chunk
                    yield chunk
            
            # Save to DB (Skip if Incognito)
            if full_response_accumulator and not is_incognito:
                db_utils.add_message(session_id, "assistant", full_response_accumulator)
            
            if action_found:
                yield f"\n__METADATA_ACTION__:{json.dumps(action_found)}"
                
        except Exception as e:
            logger.error(f"Streaming Error: {e}")
            yield f"\n\n[System Error: {str(e)}]"

    return StreamingResponse(response_generator(), media_type="text/plain", headers={"X-Session-ID": session_id})


@app.post("/clear_history")
async def clear_history_endpoint(request: ClearHistoryRequest):
    """Wipes chat history but keeps the session/report metadata."""
    logger.info(f"Clearing history for session: {request.session_id}")
    db_utils.clear_chat_history(request.session_id)
    return JSONResponse(content={'success': True})

@app.post("/delete_all_sessions")
async def delete_all_sessions_endpoint(request: DeleteAllSessionsRequest):
    """Wipes everything for a user across all sessions."""
    user_id = request.user_id
    logger.info(f"Bulk cleanup for user: {user_id}")
    
    # 1. DB Cleanup
    session_ids = db_utils.delete_all_user_sessions(user_id)
    
    # 2. RAG Cleanup
    for sid in session_ids:
        delete_namespace(f"report-{sid}")
        clear_uploaded_files(sid)
        
    return JSONResponse(content={'success': True})


# --- NEW ENDPOINTS FOR SESSION MANAGEMENT ---

@app.post("/delete_session")
async def delete_session_endpoint(request: DeleteSessionRequest):
    """
    Deletes a specific session (Chat + DB + RAG).
    """
    session_id = request.session_id
    logger.info(f"Deleting session: {session_id}")
    
    # 1. Clear Pinecone
    delete_namespace(session_id)
    # 2. Clear Files
    clear_uploaded_files(session_id)
    # 3. Clear DB
    db_utils.delete_session(session_id)
    
    return JSONResponse(content={'success': True, 'message': 'Session deleted successfully'})

@app.post("/rename_session")
async def rename_session_endpoint(request: RenameRequest):
    """
    Renames the title of a specific session.
    """
    try:
        db_utils.rename_session(request.session_id, request.new_title)
        return JSONResponse(content={'success': True})
    except Exception as e:
        return JSONResponse(content={'success': False, 'error': str(e)})

@app.post("/toggle_pin")
async def toggle_pin_endpoint(request: PinRequest):
    """
    Pins or Unpins a session.
    """
    try:
        db_utils.toggle_pin_session(request.session_id, request.is_pinned)
        return JSONResponse(content={'success': True})
    except Exception as e:
        return JSONResponse(content={'success': False, 'error': str(e)})

# Legacy Endpoint - Can direct to delete_session logic or master reset
@app.post("/clear_chat")
async def clear_chat(request: Request, request_body: ClearChatRequest):
    """
    Legacy: Clears session. Now maps to deleting the specific session.
    """
    return await delete_session_endpoint(DeleteSessionRequest(session_id=request_body.session_id))


@app.get("/get_history")
async def get_history(
    user_id: str = Query(..., description="Unique user identifier"),
    session_id: str = Query(..., description="Current session ID")
):
    """
    Retrieves chat history and session metadata to restore client state.
    """
    logger.info(f"Fetching history for Session: {session_id}, User: {user_id}")
    
    # 1. Verify Session by ID
    session_data = db_utils.get_session_by_id(session_id)
    
    if not session_data:
        # If mismatch/not found, force fresh start
        return JSONResponse(content={'success': True, 'chat_history': [], 'session_metadata': None})

    # 2. Get Messages
    history = db_utils.get_chat_history(session_id, limit=config.CHAT_HISTORY_MAX_TURNS)
    
    # 3. Get Metadata (to restore UI state)
    metadata = {
        'report_type': session_data.get('report_type'),
        'last_active': session_data.get('last_active'),
        'title': session_data.get('title'),
        'is_pinned': session_data.get('is_pinned')
    }

    return JSONResponse(content={
        'success': True, 
        'chat_history': history, 
        'session_metadata': metadata
    })
    

@app.get("/get_user_sessions")
async def get_user_sessions(user_id: str = Query(..., description="Unique user identifier")):
    """Returns list of past sessions for the sidebar."""
    try:
        sessions = db_utils.get_all_user_sessions(user_id)
        return JSONResponse(content={'success': True, 'sessions': sessions})
    except Exception as e:
        logger.error(f"Error fetching sessions: {e}")
        return JSONResponse(content={'success': False, 'sessions': []})

# uvicorn app:app --host 0.0.0.0 --port 5000 --reload