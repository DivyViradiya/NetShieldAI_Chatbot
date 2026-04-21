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
from collections import OrderedDict
import dotenv

# --- FASTAPI & PYDANTIC IMPORTS ---
from fastapi import FastAPI, Request, File, UploadFile, HTTPException, status, Query, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool, iterate_in_threadpool 
from pydantic import BaseModel
from contextlib import asynccontextmanager
from slowapi import Limiter
from slowapi.util import get_remote_address
from apscheduler.schedulers.asyncio import AsyncIOScheduler

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
    import chatbot_modules.graph_utils as graph_utils

    from chatbot_modules.nmap_parser import process_nmap_report_file
    from chatbot_modules.zap_parser import process_zap_report_file
    from chatbot_modules.ssl_parser import process_sslscan_report_file
    from chatbot_modules.pcap_parser import process_pcap_report_file
    from chatbot_modules.sql_parser import process_sql_report_file
    from chatbot_modules.killchain_parser import process_killchain_report_file
    from chatbot_modules.api_scanner_parser import process_api_scan_report_file
    
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

# Visual Logging Colors
class LogColors:
    EXTERNAL = "\033[94m" # Blue
    INTERNAL = "\033[92m" # Green
    AGENT = "\033[93m"    # Yellow
    HYBRID = "\033[95m"   # Magenta
    ROUTER = "\033[96m"   # Cyan
    INIT = "\033[97m"     # White
    SUCCESS = "\033[92m"  # Green
    RESET = "\033[0m"

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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

# --- NEW: Summary Cache (Persisted in-memory for the lifecycle of the process) ---
# Format: { "session_id:filename": "summary_text" }
# Uses OrderedDict to enforce LRU cache eviction and prevent unbounded memory growth.
MAX_SUMMARY_CACHE_SIZE = 50
_summary_cache: OrderedDict[str, str] = OrderedDict()

# --- Pydantic Models for Request Bodies ---
class ChatMessage(BaseModel):
    """Pydantic model for incoming chat messages with options."""
    message: str
    session_id: Optional[str] = None
    user_id: str 
    verbosity: Optional[str] = "standard" # concise, standard, detailed
    is_incognito: Optional[bool] = False
    llm_mode: Optional[str] = config.DEFAULT_LLM_MODE

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

class ClearMemoryRequest(BaseModel):
    """Model for clearing agentic long-term memory."""
    user_id: str

# --- SECURITY: PROMPT INJECTION SANITIZATION ---
INJECTION_PATTERNS = [r'ignore (all )?previous', r'system:\s*you are now', r'forget (everything|above)']

def sanitize_input(text: str) -> str:
    if not text:
        return text
    for p in INJECTION_PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            logger.warning(f"{LogColors.AGENT}[SECURITY] Prompt injection intercepted in user query.{LogColors.RESET}")
            return "[INPUT_SANITIZED_DUE_TO_SECURITY_POLICY]"
    return text

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
    Supports both standard exceptions and Google API specific ResourceExhausted.
    """
    from google.api_core import exceptions as google_exceptions
    
    max_retries = 4
    base_delay = 15 # Start with 15s delay for 429s on free tier
    
    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except (google_exceptions.ResourceExhausted, Exception) as e:
            error_str = str(e).lower()
            is_quota_error = isinstance(e, google_exceptions.ResourceExhausted) or \
                             any(hit in error_str for hit in ["429", "quota", "exhausted", "rate limit"])
            
            if is_quota_error:
                if attempt < max_retries - 1:
                    wait_time = base_delay * (2 ** attempt) # Exponential backoff: 15, 30, 60, 120
                    logger.warning(f"{LogColors.AGENT}[RETRY] Gemini Quota hit. Waiting {wait_time}s before attempt {attempt + 2}/{max_retries}...{LogColors.RESET}")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"{LogColors.EXTERNAL}[FATAL] Max retries reached for Gemini API. Quota is fully exhausted.{LogColors.RESET}")
                    raise e
            else:
                # Not a quota error, re-raise immediately
                raise e


def _init_global_llm_and_rag():
    """
    Initializes global LLM and RAG components if they haven't been already.
    """
    global _llm_instances_global, _llm_generate_funcs_global, _embedding_model_instance_global, _pinecone_index_instance_global

    with _init_lock:
        if not _llm_instances_global: 
            logger.info(f"{LogColors.INIT}[INIT] Initializing global LLM instances...{LogColors.RESET}")
            
            # --- Initialize Local LLM ---
            try:
                local_model_instance = local_llm_module.load_model(
                    model_id=config.LLM_MODEL_ID,
                    model_basename=config.LLM_MODEL_BASENAME,
                    local_dir=config.LLM_MODEL_DIR
                )
                _llm_instances_global["local"] = local_model_instance
                _llm_generate_funcs_global["local"] = local_llm_module.generate_response
                logger.info(f"{LogColors.SUCCESS}[SUCCESS] Local LLM initialized successfully.{LogColors.RESET}")
            except Exception as e:
                logger.error(f"Failed to initialize Local LLM: {e}")

            # --- Initialize Gemini Models with Tools ---
            if config.GEMINI_API_KEY:
                for m_name in config.SUPPORTED_LLM_MODES:
                    if m_name == "local":
                        continue
                    try:
                        gemini_model_instance = gemini_llm_module.load_model(
                            api_key=config.GEMINI_API_KEY,
                            model_name=m_name,
                            tools=SECURITY_TOOLS
                        )
                        _llm_instances_global[m_name] = gemini_model_instance
                        _llm_generate_funcs_global[m_name] = gemini_llm_module.generate_response
                        logger.info(f"{LogColors.SUCCESS}[SUCCESS] Gemini Model initialized: {m_name}{LogColors.RESET}")
                    except Exception as e:
                        logger.warning(f"Failed to initialize Gemini Model {m_name}: {e}")
            else:
                logger.info("Skipping Gemini LLM initialization: GEMINI_API_KEY not found.")

            if not _llm_instances_global:
                raise RuntimeError("No LLM could be initialized. Please check your configuration.")
            
        # --- RAG Initialization ---
        if _embedding_model_instance_global is None:
            logger.info(f"{LogColors.INIT}[INIT] Initializing global embedding model...{LogColors.RESET}")
            try:
                _embedding_model_instance_global = load_embedding_model()
                logger.info(f"{LogColors.SUCCESS}[SUCCESS] Global embedding model loaded.{LogColors.RESET}")
            except Exception as e:
                logger.error(f"Failed to load global embedding model: {e}")
                _embedding_model_instance_global = None

        if _pinecone_index_instance_global is None and _embedding_model_instance_global is not None:
            logger.info(f"{LogColors.INIT}[INIT] Initializing global Pinecone index...{LogColors.RESET}")
            try:
                _pinecone_index_instance_global = initialize_pinecone_index()
                logger.info(f"{LogColors.SUCCESS}[SUCCESS] Global Pinecone index initialized.{LogColors.RESET}")
            except Exception as e:
                logger.error(f"Failed to initialize global Pinecone index: {e}")
                _pinecone_index_instance_global = None

def get_llm_instance():
    if not _llm_instances_global:
        _init_global_llm_and_rag()
    if not _llm_instances_global:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="LLM instances not initialized.")
    return _llm_instances_global

def get_embedding_model_instance():
    if _embedding_model_instance_global is None:
        _init_global_llm_and_rag()
    return _embedding_model_instance_global

def get_pinecone_index_instance():
    if _pinecone_index_instance_global is None:
        _init_global_llm_and_rag()
    return _pinecone_index_instance_global


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for global resources in the FastAPI app."""
    logger.info(f"{LogColors.INIT}[INIT] FastAPI starting up...{LogColors.RESET}")
    
    # --- PHASE 1: INIT DATABASE ---
    try:
        db_utils.init_db()
        logger.info(f"{LogColors.SUCCESS}[SUCCESS] SQLite Database Initialized.{LogColors.RESET}")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
    
    _init_global_llm_and_rag()
    
    # --- PHASE 2: AUTO-CLEANUP SCHEDULER ---
    async def cleanup_stale_sessions():
        logger.info(f"{LogColors.ROUTER}[SCHEDULER] Running Pinecone TTL Garbage Collection...{LogColors.RESET}")
        try:
            stale_ids = await run_in_threadpool(db_utils.get_stale_sessions, 7)
            for sid in stale_ids:
                try:
                    logger.info(f"Auto-cleanup: Purging stale session {sid}")
                    await run_in_threadpool(delete_namespace, sid)
                    await run_in_threadpool(db_utils.delete_session, sid)
                except Exception as e:
                    logger.error(f"Failed to cleanup session {sid}: {e}")
        except Exception as e:
            logger.error(f"Scheduler failed to fetch stale sessions: {e}")

    scheduler = AsyncIOScheduler()
    scheduler.add_job(cleanup_stale_sessions, 'interval', minutes=60) # Run hourly to check for 7-day stale sessions
    scheduler.start()
    
    logger.info("Startup complete.")
    
    yield  # Application runs while yielded
    
    scheduler.shutdown()
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

# --- APP INITIALIZATION ---
# Initializing app after lifespan and other dependent objects are defined
app = FastAPI(lifespan=lifespan)

# --- SECURITY: Rate Limiting ---
limiter = Limiter(key_func=lambda request: request.query_params.get("user_id", get_remote_address(request)))
app.state.limiter = limiter

# --- SECURITY: Configure CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5100"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mounting static files
app.mount("/chatbot_uploads", StaticFiles(directory=UPLOAD_FOLDER), name="chatbot_uploads")

# --- SECURITY: RFC 7807 Error Responses ---
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"type": "about:blank", "title": "HTTP Exception", "status": exc.status_code, "detail": exc.detail, "instance": request.url.path}
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled server error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"type": "about:blank", "title": "Internal Server Error", "status": 500, "detail": "An unexpected error occurred.", "instance": request.url.path}
    )

# --- HEALTH & READINESS PROBE ---
@app.get("/health")
async def health_check():
    """Essential for Docker health checks and load balancer probes."""
    return {
        "status": "ok" if _llm_instances_global else "degraded",
        "llm_ready": bool(_llm_instances_global),
        "rag_ready": _embedding_model_instance_global is not None,
        "active_models": list(_llm_instances_global.keys()) if isinstance(_llm_instances_global, dict) else []
    }

# --- IMPROVED REPORT DETECTION LOGIC ---
def detect_report_type_from_content(text: str, filename: Optional[str] = None) -> str:
    """
    Identifies the report type by scanning the first few lines of the text.
    Uses multi-line keyword matching for robustness.
    """
    if not text:
        logger.warning("Detection failed: Extracted text is empty.")
        return "generic_pdf"
    
    # 0. Filename Hinting (High Reliability)
    if filename:
        fn_lower = filename.lower()
        if "nmap" in fn_lower or "network_scanner" in fn_lower: return "nmap"
        if "ssl" in fn_lower or "ssl_scanner" in fn_lower: return "sslscan"
        if "zap" in fn_lower or "web_scanner" in fn_lower: return "zap"
        if "pcap" in fn_lower or "sniffer" in fn_lower or "packet_sniffer" in fn_lower: return "pcap"
        if "sql" in fn_lower or "sql_scanner" in fn_lower: return "sql"
        if "killchain" in fn_lower or "full_audit" in fn_lower: return "killchain"
        if "api" in fn_lower or "api_scanner" in fn_lower: return "api"
        if "semgrep" in fn_lower or "semgrep_scanner" in fn_lower: return "semgrep"

    # Scan first 20 lines for better accuracy in complex layouts
    lines = [line.strip().lower() for line in text.splitlines() if line.strip()][:20]
    full_header_context = " ".join(lines)

    # --- HEADER MAPPING (Ordered by specificity) ---
    
    # 1. SSL/TLS Assessment
    if "ssl/tls assessment" in full_header_context or "sslscan" in full_header_context:
        return "sslscan"

    # 2. Kill Chain Analysis
    if "kill chain" in full_header_context:
        return "killchain"

    # 3. NMAP / Network Scanner (New & Old formats)
    if any(k in full_header_context for k in ["network intelligence", "nmap scan report", "network scan report"]):
        return "nmap"
    
    # 4. PCAP / Sniffer
    if any(k in full_header_context for k in ["network traffic", "tshark", "packet sniffer"]):
        return "pcap"
    
    # 5. ZAP / Web Vulnerability
    if any(k in full_header_context for k in ["web security audit", "web vulnerability report", "web vulnerability", "owasp zap"]):
        # Check for API hint specifically if it's ZAP-templated or has common API markers
        if "api" in full_header_context:
            return "api"
        return "zap"
    
    # 6. SQL Injection
    if any(k in full_header_context for k in ["sql injection audit", "sql injection security", "sqlmap"]):
        return "sql"

    # 7. SAST / Semgrep
    if any(k in full_header_context for k in ["source code security", "static analysis", "semgrep"]):
        return "semgrep"

    # 8. API Scan (Backup/Explicit)
    if any(k in full_header_context for k in ["api security audit", "api security", "api scan", "api_scan"]):
        return "api"

    # Final Fallback
    if "nmap" in full_header_context:
        return "nmap"
    
    logger.info(f"No specific report header matched in first 20 lines. Defaulting to generic_pdf.")
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

    elif "zap" in report_tool or "api" in report_tool:
            question_lower = question_lower.lower().strip()
            risk_keywords = ["risk", "vulnerability", "finding", "issue", "security", "alerts", "api"]
            
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
            if "xss" in question_lower and "cross site scripting" in title: return True
            if "sqli" in question_lower and "sql injection" in title: return True
            if "csrf" in question_lower and "cross-site request forgery" in title: return True
    
    return False


# --- NEW HELPER: Parse Local LLM Text for Actions ---
def parse_local_llm_action(text: str) -> Optional[Dict[str, Any]]:
    """
    Attempts to heuristically detect if the local LLM is trying to trigger a scan
    by looking for keywords and targets in its response.
    """
    text_lower = text.lower()
    
    # Helper to find potential targets (IPs, Domains, or URLs)
    def find_target(content: str):
        # 1. Try to find a full URL with scheme
        url_match = re.search(r'(https?://[^\s\)]+)', content)
        if url_match:
            return url_match.group(1).rstrip('.:,')
        
        # 2. Try to find something that looks like a domain or IP after common labels
        label_match = re.search(r'(target|url|host|ip|domain)\s*[:=]\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3})', content, re.IGNORECASE)
        if label_match:
            return label_match.group(2).rstrip('.:,')
            
        # 3. Fallback to general domain/IP regex
        gen_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3})', content)
        if gen_match:
            return gen_match.group(1).rstrip('.:,')
        return None

    target = find_target(text)

    # 1. ZAP Scan Detection
    if "zap" in text_lower or "web application scan" in text_lower:
        if target:
            # Ensure URL has a scheme for ZAP
            final_url = target if target.startswith("http") else f"http://{target}"
            scan_mode = "Full Scan" if "full" in text_lower or "deep" in text_lower else "Quick Scan"
            return {
                "name": "zap_scan",
                "args": {"target_url": final_url, "scan_mode": scan_mode, "use_ajax": "ajax" in text_lower},
                "monitor_mode": "terminal"
            }

    # 2. Nmap Scan Detection
    if "nmap" in text_lower or "network scan" in text_lower or "port scan" in text_lower:
        if target:
            # Strip scheme if present for Nmap
            clean_ip = re.sub(r'^https?://', '', target)
            
            # Extract scan type
            scan_type = "default"
            for t in ["os", "fragmented", "aggressive", "tcp_syn", "vuln", "udp", "ping_sweep", "tcp_connect", "null", "fin", "xmas", "ack", "window", "decoy"]:
                if t in text_lower:
                    scan_type = t
                    break
            
            # Extract timing
            timing = 4
            timing_match = re.search(r't([0-5])', text_lower)
            if timing_match:
                timing = int(timing_match.group(1))
            
            return {
                "name": "nmap_scan",
                "args": {"target_ip": clean_ip, "scan_type": scan_type, "protocol_type": "UDP" if "udp" in text_lower else "TCP", "timing": timing},
                "monitor_mode": "terminal"
            }

    # 3. SSL Scan Detection
    if "ssl" in text_lower or "tls" in text_lower or "certificate check" in text_lower:
        if target:
            clean_host = re.sub(r'^https?://', '', target).split('/')[0]
            return {
                "name": "ssl_scan",
                "args": {"target_host": clean_host},
                "monitor_mode": "terminal"
            }

    # 4. SQL Injection Detection
    if "sql injection" in text_lower or "sqli" in text_lower:
        if target:
            final_url = target if target.startswith("http") else f"http://{target}"
            scan_mode = "full" if "full" in text_lower else "deep" if "deep" in text_lower else "quick"
            
            # Extract risk and level
            risk = "3"
            risk_match = re.search(r'risk\s*[:=]?\s*([1-3])', text_lower)
            if risk_match: risk = risk_match.group(1)
            
            level = "3"
            level_match = re.search(r'level\s*[:=]?\s*([1-5])', text_lower)
            if level_match: level = level_match.group(1)

            return {
                "name": "sql_injection_scan",
                "args": {
                    "target_url": final_url, 
                    "scan_mode": scan_mode,
                    "risk_level": risk,
                    "scan_level": level,
                    "check_waf": "waf" in text_lower
                },
                "monitor_mode": "terminal"
            }

    # 5. Kill Chain Detection
    if "kill chain" in text_lower or "full audit" in text_lower or "penetration test" in text_lower:
        if target:
            # Extract profile
            profile = "Full Scan"
            if "recon" in text_lower: profile = "Recon Only"
            elif "network" in text_lower: profile = "Network Audit"
            elif "web" in text_lower: profile = "Web Audit"
            
            # Extract aggression
            aggression = "Normal"
            if "stealth" in text_lower: aggression = "Stealth"
            elif "attack" in text_lower or "aggressive" in text_lower: aggression = "Attack"

            return {
                "name": "killchain_audit",
                "args": {"target": target, "profile": profile, "aggression": aggression},
                "monitor_mode": "terminal"
            }

    # 6. API Security Scan
    if "api scan" in text_lower or "swagger" in text_lower or "openapi" in text_lower:
        if target:
            # For API scan, we often need a definition URL. 
            # If not explicitly found, we might guess or ask, but here we'll try to find another URL.
            urls = re.findall(r'(https?://[^\s\)]+)', text)
            def_url = urls[1] if len(urls) > 1 else target # Fallback
            
            return {
                "name": "api_security_scan",
                "args": {"target_url": target, "definition_url": def_url},
                "monitor_mode": "terminal"
            }

    # 7. Semgrep SAST Scan
    if "sast" in text_lower or "semgrep" in text_lower or "source code" in text_lower:
        # Look for a git URL
        git_match = re.search(r'(https?://github\.com/[^\s\)]+)', text)
        if git_match:
            return {
                "name": "semgrep_sast_scan",
                "args": {"git_url": git_match.group(1)},
                "monitor_mode": "terminal"
            }

    # 8. Packet Sniffer
    if "sniff" in text_lower or "capture" in text_lower or "traffic" in text_lower:
        if target:
            clean_ip = re.sub(r'^https?://', '', target)
            return {
                "name": "packet_sniffer",
                "args": {"target_ip": clean_ip, "duration": 30, "max_packets": 50},
                "monitor_mode": "terminal"
            }

    # 9. Analysis Trigger
    if "analyze" in text_lower or "summary" in text_lower or "report" in text_lower:
        scanner_type = None
        for s in ["zap", "api", "nmap", "killchain", "sql", "ssl", "semgrep"]:
            if s in text_lower:
                scanner_type = s
                break
        if scanner_type:
            return {
                "name": "scanner_analysis",
                "args": {"scanner_type": scanner_type},
                "monitor_mode": "terminal"
            }


    return None

@app.get("/chatbot/session/{session_id}/graph")
async def get_session_graph(session_id: str):
    """
    Returns the JSON representation of the NetworkX graph for the given session.
    """
    try:
        graph_json = db_utils.get_session_graph(session_id)
        if not graph_json:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"success": False, "message": "No graph context found for this session."}
            )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"success": True, "graph_data": json.loads(graph_json)}
        )
    except Exception as e:
        logger.error(f"Error fetching graph for session {session_id}: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": "Failed to retrieve graph data."}
        )

# --- NEW: AGENTIC MEMORY EXTRACTION ---
async def extract_and_store_memory(user_id: str, message_text: str, llm_mode: str = None):
    """
    Background worker that runs a lightweight LLM call to extract semantic rules
    and facts from the user's message, storing them in SQL and Pinecone.
    """
    try:
        if "SCAN_COMPLETE_SIGNAL" in message_text or len(message_text.strip()) < 5:
            return

        # Use the provided llm_mode, falling back to global default
        mode = llm_mode if llm_mode in config.SUPPORTED_LLM_MODES else config.DEFAULT_LLM_MODE
        instance = _llm_instances_global.get(mode) or _llm_instances_global.get(config.DEFAULT_LLM_MODE) or _llm_instances_global.get("local")
        gen_func = _llm_generate_funcs_global.get(mode) or _llm_generate_funcs_global.get(config.DEFAULT_LLM_MODE) or _llm_generate_funcs_global.get("local")
        
        if not instance or not gen_func:
            return

        prompt = (
            "System: You are an internal memory extraction subsystem. Analyze the following user message.\n"
            "If the user states a permanent fact about their infrastructure (e.g. '192.168.1.10 is the prod DB'), "
            "a long-term preference (e.g. 'I prefer concise answers'), or a firm exclusion rule (e.g. 'Never scan 10.0.0.5'), "
            "extract it. Otherwise, output 'NO_MEMORY'.\n"
            "Format your output ONLY as a strict JSON array of objects with keys: \n"
            "'type' (either 'exclusion', 'preference', or 'fact') AND 'content' (the extracted detail).\n"
            f"User Message: {message_text}\n"
        )

        result = await execute_with_retry(gen_func, instance, prompt, max_tokens=150)
        output = result.get("text", "").strip()
        
        if "NO_MEMORY" in output or not output:
            return

        try:
            # Clean up markdown code blocks if any
            clean_output = output.strip('` \n')
            if clean_output.lower().startswith("json"):
                clean_output = clean_output[4:]
            
            items = json.loads(clean_output)
            pinecone_texts = []
            
            for item in items:
                rtype = item.get("type", "fact")
                content = item.get("content", "")
                if content:
                    if rtype in ["exclusion", "preference"]:
                        await run_in_threadpool(db_utils.add_user_memory_rule, user_id, rtype, content)
                        logger.info(f"Background: Stored hard {rtype} rule for user {user_id}")
                    else:
                        pinecone_texts.append(content)
            
            if pinecone_texts:
                from chatbot_modules.utils import upsert_user_memory
                await run_in_threadpool(upsert_user_memory, user_id, pinecone_texts)
                logger.info(f"Background: Upserted {len(pinecone_texts)} memory facts for user {user_id}")

        except json.JSONDecodeError:
            logger.warning(f"Memory extraction failed to parse JSON: {output}")

    except Exception as e:
        logger.error(f"Error in background memory extraction: {e}")

# --- BACKGROUND TASK HELPERS ---
async def run_post_upload_processing(session_id: str, user_id: str, parsed_data: Dict[str, Any], report_type: str, original_filename: str, llm_mode: str):
    """
    Background worker for heavy post-upload tasks (Summarization, Graph Building).
    """
    try:
        # 1. Hybrid RAG: Build and Persist Logical Graph
        if report_type != "generic_pdf":
            logger.info(f"Background: Building graph for session {session_id}")
            existing_graph_json = await run_in_threadpool(db_utils.get_session_graph, session_id)
            current_graph = graph_utils.deserialize_graph(existing_graph_json) if existing_graph_json else graph_utils.create_base_graph()
            
            new_graph = await run_in_threadpool(graph_utils.build_graph_from_report, current_graph, parsed_data, report_type)
            serialized_graph = graph_utils.serialize_graph(new_graph)
            
            await run_in_threadpool(db_utils.save_session_graph, session_id, serialized_graph)
            logger.info(f"Background: Graph built ({new_graph.number_of_nodes()} nodes)")

        # 2. Generate Summary with Failover
        cache_key = f"{session_id}:{original_filename}"
        if cache_key in _summary_cache:
            initial_summary = _summary_cache[cache_key]
            # Move to end to mark as recently used
            _summary_cache.move_to_end(cache_key)
            logger.info(f"Background: Using cached summary for {original_filename} in session {session_id}")
        else:
            initial_summary = "Report parsed successfully, but summarization failed."
            requested_mode = llm_mode
            if requested_mode in config.LLM_FAILOVER_PRIORITY:
                idx = config.LLM_FAILOVER_PRIORITY.index(requested_mode)
                failover_sequence = config.LLM_FAILOVER_PRIORITY[idx:]
            else:
                failover_sequence = [requested_mode] + config.LLM_FAILOVER_PRIORITY

            for current_mode in failover_sequence:
                llm_instance = _llm_instances_global.get(current_mode)
                llm_generate_func = _llm_generate_funcs_global.get(current_mode)
                if not llm_instance or not llm_generate_func:
                    continue
                try:
                    initial_summary = await execute_with_retry(
                        summarize_report_with_llm,
                        llm_instance,
                        llm_generate_func,
                        parsed_data,
                        report_type
                    )
                    if current_mode != requested_mode:
                        initial_summary = f"[Note: Summary generated using {current_mode} failsafe]\n\n" + initial_summary
                    
                    # Cache the result and enforce LRU size limit
                    _summary_cache[cache_key] = initial_summary
                    if len(_summary_cache) > MAX_SUMMARY_CACHE_SIZE:
                        _summary_cache.popitem(last=False)
                    break
                except Exception as e:
                    logger.warning(f"Background: Summarization failed for {current_mode}: {e}")
                    continue

        # 3. Inject report content info into history (Role: system)
        report_msg = f"SYSTEM_NOTIFICATION: Scan Complete. {report_type.upper()} Report successfully synchronized. Summary: {initial_summary}"
        await run_in_threadpool(db_utils.add_message, session_id, "system", report_msg)
        logger.info(f"Background: Processing complete for session {session_id}")
        return initial_summary

    except Exception as e:
        logger.error(f"Error in background upload processing: {e}", exc_info=True)
        return "Report parsed successfully, but summarization failed due to an error."

@app.post("/upload_report")
async def upload_report(
    background_tasks: BackgroundTasks,
    file: Optional[UploadFile] = File(None, alias="file"),
    llm_mode: str = Query(config.DEFAULT_LLM_MODE, description=f"Choose LLM mode: {config.SUPPORTED_LLM_MODES}"),
    user_id: str = Query(..., description="Unique user identifier from the client"),
    session_id: Optional[str] = Query(None, description="Existing session ID to attach this report to"),
    file_path: Optional[str] = Query(None, description="Direct absolute path to the PDF on the server's disk"),
    background: bool = Query(True, description="Whether to run summarization and graph building in the background")
):
    """
    Handles file uploads OR path-based analysis.
    Path-based analysis (file_path) is faster as it skips binary transfer.
    """
    logger.info(f"Report Request - User: {user_id}, Session: {session_id}, Path-based: {bool(file_path)}, Background: {background}")
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
        report_type = detect_report_type_from_content(extracted_text, original_filename)
        # USE PROVIDED SESSION ID OR GENERATE NEW ONE
        if not session_id:
            session_id = str(uuid.uuid4())
            logger.info(f"New session {session_id} - Type: {report_type}")
        else:
            logger.info(f"Updating session {session_id} with report type: {report_type}")
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
        elif report_type == 'api':
            parsed_data = process_api_scan_report_file(target_file_to_process)
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
                # Chunking and embedding is heavy, but we need it done to mark "report loaded"
                # so we keep it in the main call but run it in a threadpool
                report_namespace = await run_in_threadpool(load_report_chunks_and_embeddings, parsed_data, report_type, session_id)
            else:
                logger.warning("RAG components not available.")

            # --- Persist Session to Database ---
            try:
                initial_title = f"{report_type.upper()} Analysis" if report_type != "generic_pdf" else original_filename
                await run_in_threadpool(
                    db_utils.update_or_create_session,
                    user_id=user_id,
                    session_id=session_id,
                    report_type=report_type,
                    pinecone_namespace=report_namespace,
                    parsed_report_data=parsed_data,
                    title=initial_title,
                    status="ACTIVE"
                )
            except Exception as e:
                logger.error(f"Failed to persist session to database: {e}")

            # --- PROCESS WITH SYNC/ASYNC OPTION ---
            if background:
                background_tasks.add_task(
                    run_post_upload_processing, 
                    session_id, 
                    user_id, 
                    parsed_data, 
                    report_type, 
                    original_filename, 
                    llm_mode
                )
                summary_text = "Report received. Analysis and summary are being generated in the background."
            else:
                summary_text = await run_post_upload_processing(
                    session_id,
                    user_id,
                    parsed_data,
                    report_type,
                    original_filename,
                    llm_mode
                )

            return JSONResponse(content={
                'success': True, 
                'summary': summary_text, 
                'report_loaded': True, 
                'session_id': session_id, 
                'llm_mode': llm_mode
            })
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
        if is_temporary_file and target_file_to_process and os.path.exists(target_file_to_process):
            os.remove(target_file_to_process)
            logger.info(f"Cleaned up temporary upload: {target_file_to_process}")

# =============================================================================
# SHARED SERVICE LAYER — Single Source of Truth for all Chat Endpoints
# =============================================================================

def get_orchestrated_system_prompt() -> str:
    """
    Returns the single, authoritative orchestrator system prompt.
    Merges: Categorized Grid (legacy /chat), Smart Actions (chat_stream),
    Summarization Protocol, Memory Acknowledgment, and Safety Rules.
    Used by BOTH /chat and /chat_stream to guarantee identical intelligence.
    """
    return (
        "System: You are the NetShieldAI Security Orchestrator. Your goal is to guide the user through security audits and analyze technical telemetry.\n"
        "1. Identify Intent: Look for scan requests (Nmap, ZAP, SSL, etc.).\n"
        "2. Terminal Protocol: ONLY WHEN INITIATING an actual scan (triggering a tool), inform the user: 'Deploying module. You can monitor the live telemetry synchronization below. I will Lightspeed the data upon completion.' DO NOT say this when asking for input or settings.\n"
        "3. Scan Options & Information Structure: When listing scans or providing details, use the following structure for each tool:\n"
        "   - **Tool Name**\n"
        "   - **Description**: Concise explanation of what the scan does.\n"
        "   - **Target Requirements**: Precise target needed (e.g., IP, URL, Host).\n"
        "   - **Configuration Options**: List of available parameters (e.g., Scan Type, Duration, Profile).\n"
        "4. Tool Requirements Reference:\n"
        "   - Nmap Scan: Requires 'target_ip'. Options: Protocol (TCP/UDP), Scan Type (default, os, aggressive, vuln, etc.), Timing (0-5).\n"
        "   - ZAP Scan: Requires 'target_url'. Options: Scan Mode (Quick, Full, Deep), AJAX Spider (true/false).\n"
        "   - SSL/TLS Scan: Requires 'target_host'.\n"
        "   - SQL Injection Scan: Requires 'target_url'. Options: Scan Mode (quick, full, deep), Risk Level (1-3), Scan Level (1-5), Check WAF (true/false).\n"
        "   - Packet Sniffer: Requires 'target_ip'. Options: Duration, Max Packets.\n"
        "   - API Security Scan: Requires 'target_url' and 'definition_url' (Swagger). Options: Auth Token.\n"
        "   - Kill Chain Audit: Requires 'target'. Options: Profile (Recon Only, Network Audit, Web Audit, Full Scan), Aggression (Normal, Stealth, Attack).\n"
        "   - Semgrep SAST Scan: Requires 'git_url'.\n"
        "5. MANDATORY: ALWAYS ask the user for the specific target and any required/optional configurations before initiating a scan. If the user only says 'run a scan', do NOT guess parameters. Explicitly list the requirements and configurations for the requested tool and wait for their reply before triggering the scan.\n"
        "6. Formatting Excellence: Structure your output for maximum readability. Use bolding to highlight key technical terms, bullet points for lists, and frequent paragraph breaks to separate distinct thoughts. Never output a 'wall of text'.\n"
        "7. Safety & Boundaries: Strictly prohibit any operations or scans against 'localhost', '127.0.0.1', or internal loopback interfaces to prevent self-disruption.\n"
        "8. Synchronization: When you receive the trigger '[ANALYSIS_TRIGGER]', analyze the summary in 'SYSTEM_NOTIFICATION' and provide a professional breakdown.\n"
        "9. Scheduling Missions: When the user wants to run a scan in the future or on a recurring basis, follow the **SCHEDULING PROTOCOL**:\n"
        "   - **Acknowledge**: Inform the user you can orchestrate the persistence logic for their audit.\n"
        "   - **Frequency Selection**: Output the tag `[MISSION_PRESETS]` followed by a bulleted list of options: One-Shot (Once), Daily, Weekly, Monthly, and Periodic. Format: `- Name: Description`.\n"
        "   - **Structure**: Present tool options in a clear, structured list with bold headers.\n"
        "   - **Tool Mapping**: Briefly list the 8 scanners available for scheduling (Nmap, ZAP, SSL, etc.).\n"
        "   - **Trigger**: Only call `schedule_scan` once user provides Frequency, Time, Tool, and Target.\n"
        "   - **Confirmation**: Inform them: 'Mission scheduled. I have orchestrated the persistence parameters for this audit.'\n"
        "10. Scan Consultation & Grid UI:\n"
        "    - **General Inquiry**: ONLY if the user asks generically (e.g., 'what scans are available', 'show me tools', or 'help me scan'):\n"
        "       - Acknowledge by outputting EXACTLY THIS marker on its own line: `[GRID_INTRO]`.\n"
        "       - Output EXACTLY `[SCAN_PRESETS]` and list ALL 8 tools categorized under bold headers (Network Infrastructure, Web Application Scanners, Audit & Verification).\n"
        "       - Under the grid, provide the full `### 🛡️ Tactical Scanner Configuration` mapping out the `Audit Scope`, `Target Requirements`, and `Operational Config` for EVERY tool.\n"
        "    - **Specific Tool Request**: If the user specifically names a tool (e.g., 'help me perform an nmap scan', 'run zap'), DO NOT output the Grid or the catalogue of all 8 tools. Instead, acknowledge their choice, explain the tool's Audit Scope, list ONLY its specific Target Requirements and Operational Config from step 4, and directly ask them to provide those parameters to proceed.\n"
        "11. Smart Guidance (Follow-ups & Actions): After your core response, you MUST provide proactive guidance separated into two exact categories.\n"
        "   - **Suggestions (Informational Guidance)**: Provide 2-3 strategic recommendations on what the user should read, review, or consider next. These are purely instructional text.\n"
        "      Example: `__SUGGESTION__: Review the open ports reported to see if any are unnecessary.`\n"
        "      Example: `__SUGGESTION__: Use a deeper Nmap scan (-p-) to ensure no high-number ports are missed.`\n"
        "   - **Actions (Proactive Commands)**: Provide 1-2 actionable tool triggers written from the USER'S perspective. These will become clickable buttons.\n"
        "      Example: `__ACTION__: Start Deep Scan | Run an aggressive Nmap scan on this host.`\n"
        "      Example: `__ACTION__: Analyze Findings | Synthesize the Nmap results into an executive report.`\n"
        "   Separate each tag with a newline.\n"
        "12. Memory Acknowledgment: If the user provides a permanent fact, rule, or preference in their message (e.g. 'Never scan 10.0.0.1'), you MUST first acknowledge it in a brief, professional sentence (e.g., 'I have noted that restriction for all future scans.'), and ONLY THEN output EXACTLY: `[MEMORY_UPDATED]` at the very end of your response.\n"
    )


async def _build_chat_context(
    user_question: str,
    user_id: str,
    session_id: str,
    session_data: dict,
    verbosity: str,
    is_incognito: bool,
    llm_instance,
    llm_generate_func,
    chat_history: list
) -> str:
    """
    Shared context builder used by ALL chat endpoints.
    Handles: history summarization, verbosity, status flags, memory injection, RAG routing, topology graph.
    Returns the fully-assembled llm_prompt_content string ready for final prompt construction.
    """
    current_parsed_report = session_data.get('parsed_report_data')
    current_report_type = session_data.get('report_type')
    current_report_namespace = session_data.get('pinecone_namespace')
    current_status = session_data.get('status', 'ACTIVE')

    # --- Verbosity & System Instruction ---
    system_instruction = ""
    if verbosity == "concise":
        system_instruction = "System: Provide a very brief, concise answer. Avoid fluff.\n"
    elif verbosity == "detailed":
        system_instruction = "System: Provide a detailed, technical deep-dive response with code examples and step-by-step remediation if applicable.\n"

    # --- Status-Specific Context ---
    if current_status == "STATUS_WAITING_FOR_REPORT":
        system_instruction += "System: A security scan is currently running in the terminal. If the user asks about progress, inform them it is still processing and you will analyze it as soon as it finishes.\n"

    # --- Active Report Injection ---
    if current_parsed_report:
        system_instruction += f"System: CURRENT ACTIVE REPORT: A {str(current_report_type).upper()} report is already loaded in this session. Prioritize this data for analysis, breakdowns, or recommendations.\n"

    # --- Assembles the base prompt from the unified prompt + situational instruction ---
    llm_prompt_content = get_orchestrated_system_prompt() + system_instruction

    # --- Summarization Check (Restored from legacy /chat — prevents context overflow) ---
    summarized_context_str = ""
    if len(chat_history) > config.CHAT_HISTORY_MAX_TURNS:
        logger.info(f"Chat history long ({len(chat_history)} turns). Generating context summary.")
        segment_to_summarize = chat_history[:-1]  # Everything except the latest user message
        try:
            summarized_segment_text = await execute_with_retry(
                summarize_chat_history_segment,
                llm_instance,
                llm_generate_func,
                segment_to_summarize,
                max_tokens=config.DEFAULT_SUMMARIZE_MAX_TOKENS
            )
            summarized_context_str = f"System: Summary of previous conversation: {summarized_segment_text}\n"
        except Exception as e:
            logger.warning(f"Summarization failed: {e}. Using raw history as fallback.")

    # --- CONTEXT ROUTING: Memory Injection ---
    is_objective_analysis = "[ANALYSIS_TRIGGER]" in user_question or "SCAN_COMPLETE_SIGNAL" in user_question
    if not is_incognito and not is_objective_analysis:
        logger.info(f"Injecting long-term memory for user {user_id}")
        user_memory_context = ""
        # 1. Hard Rules (SQLite)
        rules = db_utils.get_user_memory_rules(user_id)
        if rules:
            rule_texts = [f"[{r['rule_type'].upper()}] {r['content']}" for r in rules]
            user_memory_context += f"\n--- FIRM USER RULES & GUARDRAILS ---\nThese rules MUST be followed:\n" + "\n".join(rule_texts) + "\n------------------------------------\n"
        # 2. Semantic Facts (Pinecone)
        from chatbot_modules.utils import retrieve_user_memory
        semantic_memory = await run_in_threadpool(retrieve_user_memory, user_question, user_id)
        if semantic_memory:
            user_memory_context += semantic_memory
        llm_prompt_content += user_memory_context
    elif is_objective_analysis:
        logger.info("Objective analysis requested. Bypassing Agentic Memory to ensure unbiased reporting.")

    # --- RAG Routing ---
    rag_context = ""
    if current_parsed_report and is_report_specific_question_web(user_question, current_parsed_report):
        logger.info(f"{LogColors.ROUTER}[QUERY ROUTER] Query triggers INTERNAL {str(current_report_type).upper()} RAG.{LogColors.RESET}")
        embedding_model = get_embedding_model_instance()
        pinecone_index = get_pinecone_index_instance()
        if current_report_namespace and embedding_model and pinecone_index:
            rag_context = await run_in_threadpool(retrieve_internal_rag_context, user_question, current_report_namespace, top_k=config.DEFAULT_RAG_TOP_K)
        if rag_context:
            llm_prompt_content += f"Here is some relevant information from the current report:\n{rag_context}\n\n"
            llm_prompt_content += f"The user is asking a question related to the previously provided {str(current_report_type).upper()} document/report.\n"
        else:
            llm_prompt_content += "No specific relevant information found in the current report for this query. "
    else:
        # --- TIER 0: CVE/CWE Local Knowledge Base Lookup ---
        from chatbot_modules.cve_knowledge_base import detect_cve_cwe_query
        cve_match = await run_in_threadpool(detect_cve_cwe_query, user_question)
        cve_resolved = False
        if cve_match:
            cve_context = await run_in_threadpool(cve_match["handler"], **cve_match["args"])
            if cve_context and not cve_context.startswith("No local"):
                logger.info(f"{LogColors.ROUTER}[CVE KB] Local CVE/CWE context retrieved for query.{LogColors.RESET}")
                llm_prompt_content += f"\n\n--- CVE/CWE INTELLIGENCE (Local KB) ---\n{cve_context}\n---\n"
                cve_resolved = True
        # External RAG (fallback)
        if not cve_resolved:
            logger.info(f"{LogColors.ROUTER}[QUERY ROUTER] Query is general. Searching EXTERNAL KNOWLEDGE BASE.{LogColors.RESET}")
            embedding_model = get_embedding_model_instance()
            pinecone_index = get_pinecone_index_instance()
            if embedding_model and pinecone_index:
                rag_context = await run_in_threadpool(retrieve_rag_context, user_question, top_k=config.DEFAULT_RAG_TOP_K, namespace="owasp-cybersecurity-kb")
                if rag_context:
                    llm_prompt_content += f"Here is some relevant information from a cybersecurity knowledge base:\n{rag_context}\n\n"
                else:
                    llm_prompt_content += "No specific relevant information found in the knowledge base. "
            else:
                llm_prompt_content += "RAG components not loaded. Answering based on general knowledge.\n"

    # --- HYBRID RAG: Inject Logical Topology Graph Context ---
    if current_parsed_report and current_report_type != "generic_pdf":
        graph_json = db_utils.get_session_graph(session_id)
        if graph_json:
            session_graph = graph_utils.deserialize_graph(graph_json)
            graph_summary = graph_utils.generate_graph_summary(session_graph)
            if graph_summary:
                logger.info(f"{LogColors.HYBRID}[HYBRID RAG] Injected Topological Graph Context for session {session_id}{LogColors.RESET}")
                llm_prompt_content += f"\n--- LOGICAL TOPOLOGY GRAPH (Hybrid RAG) ---\nThe following explains the relationships between identified host machines, ports, services, URLs, and vulnerabilities for this session. Use this to trace attack vectors and lateral movement logic.\n{graph_summary}\n-------------------------------------------\n"

    # --- Build History String (with summarization awareness) ---
    if summarized_context_str:
        llm_prompt_content += summarized_context_str
        # Only append the very last user message
        if chat_history:
            llm_prompt_content += f"User: {chat_history[-1]['content']}\n"
    else:
        for msg in chat_history:
            role_label = msg["role"].capitalize()
            if msg["role"] in ["assistant", "ai"]:
                role_label = "Assistant"
            elif msg["role"] in ["system", "system_hidden"]:
                role_label = "System"
            llm_prompt_content += f"{role_label}: {msg['content']}\n"

    return llm_prompt_content


# Deleted legacy @app.post("/chat") (was L1111-L1408).
# Its unique logic (summarization, categorized prompts, local failover) has been
# absorbed into get_orchestrated_system_prompt() and _build_chat_context() above.
# Both /chat_stream and /chat (Unified) now use these shared helpers.



    # --- PHASE 1: DB Retrieval ---
    session_data = None
    # 1. Try fetching specific session by ID
    if session_id:
        session_data = db_utils.get_session_by_id(session_id)
    # 2. If still no session (or session_id was null), create a fresh "General Chat" session
    if not session_data:
        logger.info(f"Creating new session for user {user_id}.")
        session_id = str(uuid.uuid4())
        db_utils.update_or_create_session(
            user_id=user_id,
            session_id=session_id,
            report_type="General",
            title="General Chat"
        )
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
    current_status = session_data.get('status', 'ACTIVE')
    # Retrieve chat history from DB
    chat_history_db = db_utils.get_chat_history(session_id, limit=config.CHAT_HISTORY_MAX_TURNS + 2)
    chat_history = [{"role": row['role'], "content": row['content']} for row in chat_history_db]
    llm_mode = chat_message.llm_mode if chat_message.llm_mode in config.SUPPORTED_LLM_MODES else config.DEFAULT_LLM_MODE
    llm_instance_for_session = _llm_instances_global.get(llm_mode)
    llm_generate_func_for_session = _llm_generate_funcs_global.get(llm_mode)
    if not llm_instance_for_session or not llm_generate_func_for_session:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"LLM mode '{llm_mode}' is not initialized."
        )
    logger.info(f"Chat request - Session: {session_id}, Mode: {llm_mode}, Incognito: {is_incognito}, Status: {current_status}")
    # --- HANDLE SCANNER ANALYSIS TOOL CALL FROM USER ---
    # If the user is reporting that a scan is complete (usually via frontend auto-call)
    if "SCAN_COMPLETE_SIGNAL" in user_question:
        # This is a hidden trigger from the frontend
        # We can extract the file path if provided
        # Example: SCAN_COMPLETE_SIGNAL: /path/to/report.pdf
        parts = user_question.split(":", 1)
        if len(parts) > 1:
            file_path = parts[1].strip()
            # Redirect to upload_report logic (internal call or similar)
            # For simplicity, we'll just acknowledge and wait for the frontend to call /upload_report
            # But the prompt says the AI should trigger scanner_analysis.
            pass
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
    # --- Status-Specific Context ---
    if current_status == "STATUS_WAITING_FOR_REPORT":
        system_instruction += "System: A security scan is currently running in the terminal. If the user asks about progress, inform them it is still processing and you will analyze it as soon as it finishes.\n"
    # --- Active Report Injection ---
    if current_parsed_report:
        system_instruction += f"System: CURRENT ACTIVE REPORT: A {str(current_report_type).upper()} report is already loaded in this session. Prioritize this data for analysis, breakdowns, or recommendations.\n"
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
        "System: You are the NetShieldAI Security Orchestrator. Your goal is to guide the user through security audits and analyze technical telemetry.\n"
        "1. Identify Intent: Look for scan requests (Nmap, ZAP, SSL, etc.).\n"
        "2. Terminal Protocol: ONLY WHEN INITIATING an actual scan (triggering a tool), inform the user: 'Deploying module. You can monitor the live telemetry synchronization below. I will Lightspeed the data upon completion.' DO NOT say this when asking for input or settings.\n"
        "3. Scan Options & Information Structure: When listing scans or providing details, use the following structure for each tool:\n"
        "   - **Tool Name**\n"
        "   - **Description**: Concise explanation of what the scan does.\n"
        "   - **Target Requirements**: Precise target needed (e.g., IP, URL, Host).\n"
        "   - **Configuration Options**: List of available parameters (e.g., Scan Type, Duration, Profile).\n"
        "4. Tool Requirements Reference:\n"
        "   - Nmap Scan: Requires 'target_ip'. Options: Protocol (TCP/UDP), Scan Type (default, os, aggressive, vuln, etc.), Timing (0-5).\n"
        "   - ZAP Scan: Requires 'target_url'. Options: Scan Mode (Quick, Full, Deep), AJAX Spider (true/false).\n"
        "   - SSL/TLS Scan: Requires 'target_host'.\n"
        "   - SQL Injection Scan: Requires 'target_url'. Options: Scan Mode (quick, full, deep), Risk Level (1-3), Scan Level (1-5), Check WAF (true/false).\n"
        "   - Packet Sniffer: Requires 'target_ip'. Options: Duration, Max Packets.\n"
        "   - API Security Scan: Requires 'target_url' and 'definition_url' (Swagger). Options: Auth Token.\n"
        "   - Kill Chain Audit: Requires 'target'. Options: Profile (Recon Only, Network Audit, Web Audit, Full Scan), Aggression (Normal, Stealth, Attack).\n"
        "   - Semgrep SAST Scan: Requires 'git_url'.\n"
        "5. MANDATORY: ALWAYS ask the user for the specific target and any required/optional configurations before initiating a scan. If the user only says 'run a scan', do NOT guess parameters. Explicitly list the requirements and configurations for the requested tool and wait for their reply before triggering the scan.\n"
        "6. Formatting: Use separate paragraphs for your instructions and questions to the user. Do not clump information together.\n"
        "7. Safety: Prohibit scanning 'localhost' or loopback addresses.\n"
        "7. Synchronization: When you receive the trigger '[ANALYSIS_TRIGGER]', analyze the summary in 'SYSTEM_NOTIFICATION' and provide a professional breakdown.\n"
        "8. Scheduling Missions: When the user wants to run a scan in the future or on a recurring basis, follow the **SCHEDULING PROTOCOL**:\n"
        "   - **Acknowledge**: Inform the user you can orchestrate the persistence logic for their audit.\n"
        "   - **Frequency Selection**: Output the tag `[MISSION_PRESETS]` followed by a bulleted list of options: One-Shot (Once), Daily, Weekly, Monthly, and Periodic. Format: `- Name: Description`.\n"
        "   - **Structure**: Present tool options in a clear, structured list with bold headers.\n"
        "   - **Tool Mapping**: Briefly list the 8 scanners available for scheduling (Nmap, ZAP, SSL, etc.).\n"
        "   - **Trigger**: Only call `schedule_scan` once user provides Frequency, Time, Tool, and Target.\n"
        "   - **Confirmation**: Inform them: 'Mission scheduled. I have orchestrated the persistence parameters for this audit.'\n"
        "9. Scan Consultation: When the user wants to perform a scan or asks for scan help, follow the **SCAN PROTOCOL**:\n"
        "   - **Acknowledge**: Acknowledge the request distinctly by outputting EXACTLY THIS marker on its own line: `[GRID_INTRO]`.\n"
        "   - **Tool Selection**: Output the tag `[SCAN_PRESETS]` on a new line. Then, list the 8 scanners properly segregated into these 3 categories using bold headers and bulleted lists:\n"
        "      - **Network Infrastructure**: Nmap Scan, Packet Sniffer.\n"
        "      - **Web Application Scanners**: ZAP Scan, SQL Injection Scan, API Security Scan.\n"
        "      - **Audit & Verification**: SSL/TLS Scan, Kill Chain Audit, Semgrep SAST Scan.\n"
        "      Format each group as: `**Category Name**` followed immediately by its bulleted list: `- Name: Description`.\n"
        "   - **Consultation**: Below the card grid, provide a detailed textual reference with the header `### 🛡️ Tactical Scanner Configuration`. For each tool, use the following structured bullet-point format:\n"
        "      - **Tool Name**\n"
        "        - **Audit Scope**: Detailed technical purpose.\n"
        "        - **Target Requirements**: Mandatory parameters.\n"
        "        - **Operational Config**: Available modes, timings, and flags.\n"
        "10. Smart Follow-ups: At the very end of your response in standard chat, proactively suggest exactly one logical next step or action based on the findings or past memory. Provide it on a new line formatted exactly as: `__SUGGESTION__: <actionable text>`.\n"
        "11. Memory Acknowledgment: If the user provides a permanent fact, rule, or preference in their message (e.g. 'Never scan 10.0.0.1'), you MUST first acknowledge it in a brief, professional sentence (e.g., 'I have noted that restriction for all future scans.'), and ONLY THEN output EXACTLY: `[MEMORY_UPDATED]` at the very end of your response.\n"
    )
    llm_prompt_content = orchestrator_prompt + system_instruction

    # --- PHASE 3: CONTEXT ROUTING (MEMORY INJECTION) ---
    is_objective_analysis = "[ANALYSIS_TRIGGER]" in user_question or "SCAN_COMPLETE_SIGNAL" in user_question
    if not is_incognito and not is_objective_analysis:
        logger.info(f"Injecting long-term memory for user {user_id}")
        user_memory_context = ""
        # 1. Hard Rules (SQLite)
        rules = db_utils.get_user_memory_rules(user_id)
        if rules:
            rule_texts = [f"[{r['rule_type'].upper()}] {r['content']}" for r in rules]
            user_memory_context += f"\n--- FIRM USER RULES & GUARDRAILS ---\nThese rules MUST be followed:\n" + "\n".join(rule_texts) + "\n------------------------------------\n"
        
        # 2. Semantic Facts (Pinecone)
        from chatbot_modules.utils import retrieve_user_memory
        semantic_memory = await run_in_threadpool(retrieve_user_memory, user_question, user_id)
        if semantic_memory:
            user_memory_context += semantic_memory
            
        llm_prompt_content += user_memory_context
    elif is_objective_analysis:
        logger.info("Objective analysis requested. Bypassing Agentic Memory to ensure unbiased reporting.")

    rag_context = ""
    # Determine if Internal RAG is needed
    if current_parsed_report and is_report_specific_question_web(user_question, current_parsed_report):
        logger.info(f"{LogColors.ROUTER}[QUERY ROUTER] Query is specific to {current_report_type}. Triggering INTERNAL RAG Context Retrieval.{LogColors.RESET}")
        embedding_model = get_embedding_model_instance()
        pinecone_index = get_pinecone_index_instance()
        if current_report_namespace and embedding_model and pinecone_index:
            rag_context = await run_in_threadpool(retrieve_internal_rag_context, user_question, current_report_namespace, top_k=config.DEFAULT_RAG_TOP_K)
        if rag_context:
            llm_prompt_content += f"Here is some relevant information from the current report:\n{rag_context}\n\n"
        else:
            llm_prompt_content += "No specific relevant information found in the current report for this query. "
    else:
        # --- TIER 0: CVE/CWE Local Knowledge Base Lookup ---
        from chatbot_modules.cve_knowledge_base import detect_cve_cwe_query
        cve_match = await run_in_threadpool(detect_cve_cwe_query, user_question)
        cve_resolved = False
        
        if cve_match:
            cve_context = await run_in_threadpool(cve_match["handler"], **cve_match["args"])
            if cve_context and not cve_context.startswith("No local"):
                logger.info(f"{LogColors.ROUTER}[CVE KB] Local CVE/CWE context retrieved for query.{LogColors.RESET}")
                llm_prompt_content += f"\n\n--- CVE/CWE INTELLIGENCE (Local KB) ---\n{cve_context}\n---\n"
                cve_resolved = True

        # External RAG
        if not cve_resolved:
            logger.info(f"{LogColors.ROUTER}[QUERY ROUTER] Query is general. Searching EXTERNAL KNOWLEDGE BASE.{LogColors.RESET}")
            embedding_model = get_embedding_model_instance()
            pinecone_index = get_pinecone_index_instance()
            if embedding_model and pinecone_index:
                rag_context = await run_in_threadpool(retrieve_rag_context, user_question, top_k=config.DEFAULT_RAG_TOP_K, namespace="owasp-cybersecurity-kb")
                if rag_context:
                    llm_prompt_content += f"Here is some relevant information from a cybersecurity knowledge base:\n{rag_context}\n\n"
                else:
                    llm_prompt_content += "No specific relevant information found in the knowledge base. "
            else:
                llm_prompt_content += "RAG components not loaded. Answering based on general knowledge.\n"
            
    # --- HYBRID RAG: Inject Logical Topology Graph Context ---
    if current_parsed_report and current_report_type != "generic_pdf":
        graph_json = db_utils.get_session_graph(session_id)
        if graph_json:
            session_graph = graph_utils.deserialize_graph(graph_json)
            graph_summary = graph_utils.generate_graph_summary(session_graph)
            if graph_summary:
                logger.info(f"{LogColors.HYBRID}[HYBRID RAG] Injected Topological Graph Context for session {session_id}{LogColors.RESET}")
                llm_prompt_content += f"\n--- LOGICAL TOPOLOGY GRAPH (Hybrid RAG) ---\nThe following explains the relationships between identified host machines, ports, services, URLs, and vulnerabilities for this session. Use this to trace attack vectors and lateral movement logic.\n{graph_summary}\n-------------------------------------------\n"
    concatenated_prompt = ""
    if summarized_context_str:
        concatenated_prompt += summarized_context_str
        msg = chat_history[-1]
        concatenated_prompt += f"User: {msg['content']}\n"
    else:
        for msg in chat_history:
            if msg["role"] == "user":
                concatenated_prompt += f"User: {msg['content']}\n"
            elif msg["role"] in ["assistant", "ai"]:
                concatenated_prompt += f"Assistant: {msg['content']}\n"
            elif msg["role"] in ["system", "system_hidden"]:
                concatenated_prompt += f"System: {msg['content']}\n"
    final_llm_prompt = f"{llm_prompt_content}\n{concatenated_prompt}\nAssistant:"
    # --- PHASE 2: Generation with Failover ---
    llm_result = None
    last_error = None
    requested_mode = chat_message.llm_mode if chat_message.llm_mode in config.SUPPORTED_LLM_MODES else config.DEFAULT_LLM_MODE
    # Determine failover sequence
    if requested_mode in config.LLM_FAILOVER_PRIORITY:
        idx = config.LLM_FAILOVER_PRIORITY.index(requested_mode)
        failover_sequence = config.LLM_FAILOVER_PRIORITY[idx:]
    else:
        failover_sequence = [requested_mode] + config.LLM_FAILOVER_PRIORITY
    used_mode = requested_mode
    for mode in failover_sequence:
        instance = _llm_instances_global.get(mode)
        gen_func = _llm_generate_funcs_global.get(mode)
        if not instance or not gen_func:
            continue
        try:
            llm_result = await execute_with_retry(
                gen_func,
                instance,
                final_llm_prompt,
                max_tokens=config.DEFAULT_MAX_TOKENS
            )
            used_mode = mode
            break
        except Exception as e:
            last_error = e
            err_msg = str(e).lower()
            if any(x in err_msg for x in ["429", "quota", "limit", "503", "exhausted"]):
                logger.warning(f"Model {mode} failed (Quota/Limit). Failing over...")
                continue
            else:
                logger.error(f"Model {mode} failed with error: {e}. Trying failsafe...")
                continue
    if not llm_result:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"All AI models exhausted or failed. Last error: {last_error}")
    try:
        llm_response_text = llm_result.get("text", "")
        tool_action = llm_result.get("tool_call")
        # If we failed over to local, manually check for actions
        if used_mode == "local" and not tool_action:
            local_action = parse_local_llm_action(llm_response_text)
            if local_action:
                tool_action = {
                    "tool": local_action["name"],
                    "parameters": local_action["args"],
                    "monitor_mode": "terminal"
                }
                logger.info(f"{LogColors.AGENT}[AGENT] Tool Triggered (Local Failover): {tool_action.get('tool')} with parameters {tool_action.get('parameters')}{LogColors.RESET}")
        elif tool_action:
             logger.info(f"{LogColors.AGENT}[AGENT] Tool Triggered: {tool_action.get('tool')} with parameters {tool_action.get('parameters')}{LogColors.RESET}")
        
        # Inject failsafe notification if we switched models
        if used_mode != requested_mode:
            llm_response_text = f"[System: Model {requested_mode} unavailable. Switched to {used_mode} failsafe.]\n\n" + llm_response_text
        # Inject monitor_mode for scan tools
        if tool_action and tool_action.get("name") in ["nmap_scan", "zap_scan", "ssl_scan", "sql_injection_scan", "packet_sniffer", "api_security_scan", "killchain_audit", "semgrep_sast_scan"]:
            tool_action["monitor_mode"] = "terminal"
        # Set session status to waiting
        db_utils.update_or_create_session(user_id=user_id, session_id=session_id, status="STATUS_WAITING_FOR_REPORT")
        # --- PHASE 1: Persist Assistant Response (Skip if Incognito) ---
        if not is_incognito:
            content_to_save = llm_response_text
            if tool_action:
                content_to_save += f"\n__METADATA_ACTION__:{json.dumps(tool_action)}"
            db_utils.add_message(session_id, "assistant", content_to_save)
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
# --- NEW MULTIMODAL HELPER ---
async def process_attachments(files: List[UploadFile]) -> List[Dict[str, Any]]:
    """
    Processes uploaded files for multimodal analysis.
    Images -> Binary + Mime + Save for persistence
    Logs/PCAPs/IaC/Data -> Extract text and format as context parts.
    """
    processed = []
    chatbot_upload_dir = os.path.join(UPLOAD_FOLDER, "chatbot")
    os.makedirs(chatbot_upload_dir, exist_ok=True)
    for file in files:
        if file.size and file.size > MAX_CONTENT_LENGTH:
            logger.warning(f"File {file.filename} exceeds MAX_CONTENT_LENGTH. Skipping.")
            continue
            
        content = await file.read()
        ext = os.path.splitext(file.filename)[1].lower()
        mime = file.content_type

        # 1. Images (True Multimodal)
        is_image = mime.startswith('image/') or ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff', '.svg', '.heic', '.heif']
        
        if is_image:
            # Persistent Storage for Chat History
            unique_filename = f"{uuid.uuid4()}{ext}"
            file_path = os.path.join(chatbot_upload_dir, unique_filename)
            
            with open(file_path, "wb") as f:
                f.write(content)
            
            # Ensure mime-type is correct if we fell back to extension
            final_mime = mime if mime.startswith('image/') else f"image/{ext.replace('.', '')}"
            processed.append({
                "type": "image", 
                "mime_type": final_mime, 
                "data": content,
                "url": f"/chatbot_uploads/chatbot/{unique_filename}",
                "name": file.filename
            })
            logger.info(f"Multimodal: Attached Image {file.filename} (Mime: {final_mime}, {len(content)} bytes)")
        
        # 2. Network Captures (Requires parsing)
        elif ext in ['.pcap', '.pcapng']:
            try:
                # Save temporarily to parse
                tmp_path = os.path.join(UPLOAD_FOLDER, f"tmp_{uuid.uuid4()}{ext}")
                with open(tmp_path, "wb") as f:
                    f.write(content)
                
                # Use existing pcap parser
                pcap_data = process_pcap_report_file(tmp_path)
                os.remove(tmp_path)
                
                # Convert to text block
                text_block = f"\n--- ATTACHED NETWORK CAPTURE: {file.filename} ---\n"
                text_block += json.dumps(pcap_data, indent=2)
                text_block += "\n-------------------------------------------\n"
                processed.append({"type": "text", "content": text_block})
                logger.info(f"Multimodal: Parsed PCAP {file.filename}")
            except Exception as e:
                logger.error(f"Failed to parse attached PCAP {file.filename}: {e}")

        # 3. Code/Logs/Configs/Data (Direct Text Extraction)
        elif ext in ['.log', '.txt', '.yaml', '.json', '.tf', '.py', '.js', '.html', '.md', '.csv', '.jsonl', '.xml']:
            try:
                text = content.decode('utf-8', errors='ignore')
                text_block = f"\n--- ATTACHED FILE: {file.filename} ---\n{text}\n---------------------------\n"
                processed.append({"type": "text", "content": text_block})
                logger.info(f"Multimodal: Extracted text from {file.filename}")
            except Exception as e:
                logger.error(f"Failed to read attached file {file.filename}: {e}")
                
    return processed

def parse_local_llm_action(text: str) -> Optional[dict]:
    """
    Parses potential security tool actions from local LLM text output.
    Uses regex to find 'ACTION: tool_name(parameters)' pattern.
    Returns CANONICAL schema: {"tool": str, "parameters": dict, "monitor_mode": "terminal"}
    """
    try:
        # Example output: "I will now run ACTION: nmap_scan(target_ip='192.168.1.1')"
        pattern = r"ACTION:\s*([a-zA-Z0-9_]+)\((.*?)\)"
        match = re.search(pattern, text)
        if match:
            tool_name = match.group(1)
            params_str = match.group(2)
            
            # Simple param parser for key='value' or key=value
            params = {}
            for param_match in re.finditer(r"([a-zA-Z0-9_]+)\s*=\s*['\"]?(.*?)['\"]?(?:,|$)", params_str):
                params[param_match.group(1)] = param_match.group(2)
                
            return {
                "tool": tool_name,
                "parameters": params,
                "monitor_mode": "terminal"
            }
    except Exception as e:
        logger.error(f"Error parsing local action: {e}")
    return None

# --- UPDATED CHAT STREAM ENDPOINT ---
@app.post("/chat_stream")
@limiter.limit("30/minute")
async def chat_stream(
    request: Request,
    background_tasks: BackgroundTasks,
    message: Optional[str] = Form(None),
    session_id: Optional[str] = Form(None),
    user_id: Optional[str] = Form(None),
    verbosity: Optional[str] = Form("standard"),
    is_incognito: Optional[bool] = Form(False),
    llm_mode: Optional[str] = Form(config.DEFAULT_LLM_MODE),
    files: List[UploadFile] = File([])
):
    """
    Handles user chat messages via STREAMING.
    Supports both JSON and Multipart Form Data for multimodal input.
    """
    # 1. Handle JSON Failsafe (if no files are sent, client might send JSON)
    if not message and not files:
        try:
            body = await request.json()
            chat_message = ChatMessage(**body)
            user_question = chat_message.message
            session_id = chat_message.session_id
            user_id = chat_message.user_id
            verbosity = chat_message.verbosity
            is_incognito = chat_message.is_incognito
            llm_mode = chat_message.llm_mode
        except Exception:
            raise HTTPException(status_code=400, detail="Missing message or invalid JSON body")
    else:
        user_question = message
        # Convert string bools from form data
        is_incognito = str(is_incognito).lower() == 'true'
        llm_mode = llm_mode if llm_mode in config.SUPPORTED_LLM_MODES else config.DEFAULT_LLM_MODE
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    # --- PHASE 2: Background Memory Extraction ---
    if not is_incognito and user_question:
        background_tasks.add_task(extract_and_store_memory, user_id, user_question, llm_mode)

    # --- SECURITY: Sanitize Input ---
    user_question = sanitize_input(user_question)

    # --- 2. Session Retrieval & Creation ---
    session_data = None
    if session_id:
        session_data = db_utils.get_session_by_id(session_id)
    if not session_data:
        logger.info(f"Creating new session for user {user_id}.")
        session_id = str(uuid.uuid4())
        db_utils.update_or_create_session(
            user_id=user_id,
            session_id=session_id,
            report_type="General",
            title="General Chat"
        )
        session_data = db_utils.get_session_by_id(session_id)
    else:
        session_id = session_data['session_id']

    if not is_incognito:
        db_utils.update_or_create_session(user_id=user_id, session_id=session_id)

    # --- 3. Process Attachments ---
    multimodal_parts = await process_attachments(files)
    
    # Prepend text attachments to the question
    augmented_question = user_question
    image_attachments = []
    
    for part in multimodal_parts:
        if part["type"] == "text":
            augmented_question = part["content"] + "\n" + augmented_question
        elif part["type"] == "image":
            image_attachments.append({
                "mime_type": part["mime_type"], 
                "data": part["data"],
                "url": part["url"],
                "name": part["name"]
            })

    # --- 4. Persist User Message (Skip if Incognito) ---
    if not is_incognito:
        # Note: We save the original question, but history will include the multimodal context for the LLM
        # We also store the image metadata for visual persistence on refresh
        attachment_json = json.dumps([{"url": a["url"], "name": a["name"], "type": "image"} for a in image_attachments]) if image_attachments else None
        db_utils.add_message(session_id, "user", user_question, attachments=attachment_json)

    # --- 5. Build Context & Prompt (Unified Logic) ---
    llm_instance = _llm_instances_global.get(llm_mode)
    llm_gen_func = _llm_generate_funcs_global.get(llm_mode)

    if not llm_instance or not llm_gen_func:
        raise HTTPException(status_code=503, detail=f"LLM mode '{llm_mode}' not initialized")

    # Fetch History
    chat_history_db = db_utils.get_chat_history(session_id, limit=config.CHAT_HISTORY_MAX_TURNS + 2)
    chat_history = [{"role": row['role'], "content": row['content']} for row in chat_history_db]

    # Use the shared context builder (Single Source of Truth)
    llm_prompt_content = await _build_chat_context(
        user_question=user_question,
        user_id=user_id,
        session_id=session_id,
        session_data=session_data,
        verbosity=verbosity,
        is_incognito=is_incognito,
        llm_instance=llm_instance,
        llm_generate_func=llm_gen_func,
        chat_history=chat_history
    )
    
    # Final Prompt Assembly
    final_prompt = f"{llm_prompt_content}Assistant:"
    
    requested_mode = llm_mode
    if requested_mode in config.LLM_FAILOVER_PRIORITY:
        idx = config.LLM_FAILOVER_PRIORITY.index(requested_mode)
        failover_sequence = config.LLM_FAILOVER_PRIORITY[idx:]
    else:
        failover_sequence = [requested_mode] + config.LLM_FAILOVER_PRIORITY

    async def response_generator():
        # nonlocal not strictly needed if only reading, but kept for clarity if session_id were to be modified
        nonlocal session_id
        full_response_accumulator = ""
        action_found = None 
        used_mode = requested_mode
        
        for mode in failover_sequence:
            instance = _llm_instances_global.get(mode)
            if not instance:
                continue

            try:
                if mode != requested_mode:
                    yield f"[System: Model {requested_mode} unavailable. Switched to {mode} failsafe.]\n\n"

                if mode == "local":
                    gen_func = _llm_generate_funcs_global.get(mode)
                    result = await execute_with_retry(gen_func, instance, final_prompt)
                    text = result.get("text", "")
                    full_response_accumulator = text
                    yield text
                    
                    local_action = parse_local_llm_action(full_response_accumulator)
                    if local_action:
                        action_found = {
                            "tool": local_action["tool"],
                            "parameters": local_action["parameters"],
                            "monitor_mode": "terminal",
                            "action_id": str(uuid.uuid4())
                        }
                else:
                    # Gemini Multimodal Streaming
                    async for chunk in gemini_llm_module.generate_response_stream(instance, final_prompt, attachments=image_attachments):
                        if chunk:
                            if chunk.startswith("__TOOL_CALL__:"):
                                # Format: __TOOL_CALL__:tool_name:json_args
                                parts = chunk.split(":", 2)
                                tool_name = parts[1]
                                tool_args = json.loads(parts[2])
                                action_found = {
                                    "tool": tool_name, 
                                    "parameters": tool_args, 
                                    "monitor_mode": "terminal",
                                    "action_id": str(uuid.uuid4())
                                }
                                logger.info(f"{LogColors.AGENT}[AGENT] Tool Triggered in stream: {tool_name}{LogColors.RESET}")
                            else:
                                full_response_accumulator += chunk
                                yield chunk
                
                # Success
                used_mode = mode
                break
            except Exception as e:
                logger.error(f"Streaming failed for {mode}: {e}")
                if mode == failover_sequence[-1]:
                    yield f"\n[Critical Error: All models failed. {str(e)}]"
                continue

        # --- Post-Stream Persistence ---
        if action_found:
             yield f"__METADATA_ACTION__:{json.dumps(action_found)}"

        if not is_incognito and full_response_accumulator:
            content_to_save = full_response_accumulator
            if action_found:
                 content_to_save += f"\n__METADATA_ACTION__:{json.dumps(action_found)}"
            db_utils.add_message(session_id, "assistant", content_to_save)

    headers = {"X-Session-ID": session_id}
    return StreamingResponse(response_generator(), media_type="text/plain", headers=headers, background=background_tasks)

# --- Unified Chat Endpoint ---
@app.post("/chat")
@limiter.limit("30/minute")
async def chat(
    request: Request,
    background_tasks: BackgroundTasks,
    message: Optional[str] = Form(None),
    session_id: Optional[str] = Form(None),
    user_id: Optional[str] = Form(None),
    verbosity: Optional[str] = Form("standard"),
    is_incognito: Optional[bool] = Form(False),
    llm_mode: Optional[str] = Form(config.DEFAULT_LLM_MODE),
    files: List[UploadFile] = File([])
):
    """
    Unified endpoint for blocking chat. 
    Detects if request is JSON or Multipart/Form-data automatically.
    """
    # 1. Poly-Input Handling (JSON vs Form-data)
    if not message and not files:
        try:
            body = await request.json()
            user_question = body.get("message")
            session_id = body.get("session_id")
            user_id = body.get("user_id")
            verbosity = body.get("verbosity", "standard")
            is_incognito = body.get("is_incognito", False)
            llm_mode = body.get("llm_mode", config.DEFAULT_LLM_MODE)
        except Exception:
             raise HTTPException(status_code=400, detail="Missing message or content")
    else:
        user_question = message
        is_incognito = str(is_incognito).lower() == 'true'
        llm_mode = llm_mode if llm_mode in config.SUPPORTED_LLM_MODES else config.DEFAULT_LLM_MODE

    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    # --- PHASE 2: Background Memory Extraction ---
    if not is_incognito and user_question:
        background_tasks.add_task(extract_and_store_memory, user_id, user_question, llm_mode)

    # --- SECURITY: Sanitize Input ---
    user_question = sanitize_input(user_question)

    # 2. Session Logic
    session_data = None
    if session_id:
        session_data = db_utils.get_session_by_id(session_id)
    if not session_data:
        session_id = str(uuid.uuid4())
        db_utils.update_or_create_session(user_id=user_id, session_id=session_id, report_type="General", title="General Chat")
        session_data = db_utils.get_session_by_id(session_id)
    else:
        session_id = session_data['session_id']

    # 3. Process Attachments
    multimodal_parts = await process_attachments(files)
    augmented_question = user_question
    image_attachments = []
    for part in multimodal_parts:
        if part["type"] == "text":
            augmented_question = part["content"] + "\n" + augmented_question
        elif part["type"] == "image":
            image_attachments.append({"mime_type": part["mime_type"], "data": part["data"], "url": part["url"], "name": part["name"]})

    if not is_incognito:
        attachment_json = json.dumps([{"url": a["url"], "name": a["name"], "type": "image"} for a in image_attachments]) if image_attachments else None
        db_utils.add_message(session_id, "user", user_question, attachments=attachment_json)

    # --- 4. Build Context & Prompt (Unified Logic) ---
    llm_instance = _llm_instances_global.get(llm_mode)
    llm_gen_func = _llm_generate_funcs_global.get(llm_mode)

    if not llm_instance or not llm_gen_func:
        raise HTTPException(status_code=503, detail=f"LLM mode '{llm_mode}' not initialized")

    # Fetch History
    chat_history_db = db_utils.get_chat_history(session_id, limit=config.CHAT_HISTORY_MAX_TURNS + 2)
    chat_history = [{"role": row['role'], "content": row['content']} for row in chat_history_db]

    # Use the shared context builder (Single Source of Truth)
    llm_prompt_content = await _build_chat_context(
        user_question=user_question,
        user_id=user_id,
        session_id=session_id,
        session_data=session_data,
        verbosity=verbosity,
        is_incognito=is_incognito,
        llm_instance=llm_instance,
        llm_generate_func=llm_gen_func,
        chat_history=chat_history
    )
    
    # Final Prompt Assembly
    final_prompt = f"{llm_prompt_content}Assistant:"

    # 5. Generation
    used_mode = llm_mode
    llm_result = None
    failover_sequence = [llm_mode] + [m for m in config.SUPPORTED_LLM_MODES if m != llm_mode]
    
    for mode in failover_sequence:
        instance = _llm_instances_global.get(mode)
        gen_func = _llm_generate_funcs_global.get(mode)
        if not instance or not gen_func: continue
        try:
            if mode != "local":
                llm_result = await execute_with_retry(gen_func, instance, final_prompt, attachments=image_attachments)
            else:
                llm_result = await execute_with_retry(gen_func, instance, final_prompt)
            
            # Map Tool Actions for Local Mode if text-based tools are found
            if mode == "local" and llm_result and not llm_result.get("tool_call"):
                local_tool = parse_local_llm_action(llm_result.get("text", ""))
                if local_tool:
                    llm_result["tool_call"] = local_tool
            
            used_mode = mode
            break
        except Exception: continue

    if not llm_result:
        raise HTTPException(status_code=500, detail="Generation failed")

    llm_response_text = llm_result.get("text", "")
    tool_action = llm_result.get("tool_call")
    if tool_action and not tool_action.get("action_id"):
        tool_action["action_id"] = str(uuid.uuid4())

    if not is_incognito:
        content_to_save = llm_response_text
        if tool_action:
            content_to_save += f"\n__METADATA_ACTION__:{json.dumps(tool_action)}"
        db_utils.add_message(session_id, "assistant", content_to_save)

    return JSONResponse(content={
        'success': True,
        'response': llm_response_text,
        'action': tool_action,
        'session_id': session_id,
        'mode': used_mode
    })

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

@app.post("/clear_memory")
async def clear_memory_endpoint(request: ClearMemoryRequest):
    """Wipes the agentic long-term memory (Rules & Facts) for a user."""
    user_id = request.user_id
    logger.info(f"Clearing Agentic Memory for user: {user_id}")
    try:
        # 1. Clear Pinecone semantic memory
        from chatbot_modules.utils import clear_user_pinecone_memory
        await run_in_threadpool(clear_user_pinecone_memory, user_id)
        
        # 2. Clear SQLite hard rules
        await run_in_threadpool(db_utils.clear_user_memory_rules, user_id)
        
        return JSONResponse(content={'success': True, 'message': 'Memory cleared successfully'})
    except Exception as e:
        logger.error(f"Error clearing memory for user {user_id}: {e}")
        return JSONResponse(status_code=500, content={'success': False, 'message': str(e)})

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
    history = db_utils.get_chat_history(session_id, limit=100)
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

