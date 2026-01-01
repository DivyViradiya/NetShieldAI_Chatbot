import os
import dotenv

dotenv.load_dotenv()

# Define the base directory for the project.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_LLM_MODE = "gemini"
SUPPORTED_LLM_MODES = ["local", "gemini"]

# --- LLM Model Configuration ---
# Local LLM (llama-cpp-python)
LLM_MODEL_ID = "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF"
LLM_MODEL_BASENAME = "openhermes-2.5-mistral-7b.Q4_K_M.gguf"
LLM_MODEL_DIR = os.path.join(PROJECT_ROOT, "pretrained_language_model")

# Gemini API Configuration
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# --- CRITICAL FIX: Model Name ---
# "gemini-3-pro-preview" might not be available to your account or public yet.
# Use "gemini-1.5-flash" for the best speed/quota balance on Free Tier.
# Use "gemini-1.5-pro" for higher reasoning capability.
GEMINI_MODEL_NAME = "gemini-3-flash-preview"
# --- RAG Configuration ---
RAG_EMBEDDING_MODEL_PATH = os.path.join(PROJECT_ROOT, "fine_tuned_owasp_model_advanced")

# Pinecone Configuration
PINECONE_INDEX_NAME = "owasp-qa"
PINECONE_ENVIRONMENT = "gcp-starter"
PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY")
PINECONE_EMBEDDING_DIMENSION = 768
PINECONE_METRIC = "cosine"
PINECONE_CLOUD = "aws"
PINECONE_REGION = "us-east-1"

# --- Chatbot Settings ---

# --- CRITICAL FIX: Token Limits ---
# High values here (like 100,000) trigger "429 Quota Exceeded" instantly on Free Tier.
DEFAULT_MAX_TOKENS = 8192  # Safe limit for standard responses
DEFAULT_RAG_TOP_K = 3
UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, "uploads")

# --- Chat History Management Settings ---
CHAT_HISTORY_MAX_TURNS = 8
CHAT_HISTORY_SUMMARIZE_THRESHOLD = 4

# --- CRITICAL FIX: Summarization Limit ---
# Previous value (10,000,000) caused the API to reject the request.
DEFAULT_SUMMARIZE_MAX_TOKENS = 16000 

# --- Heuristic Keywords for Report-Specific Questions ---
REPORT_SPECIFIC_KEYWORDS = [
    # General Report/Scan Keywords
    "report", "scan", "host", "ip", "port", "vulnerability", "alert", "cve",
    "solution", "remediation", "finding", "risk", "instance", "site", "version",
    "target", "implications", "remediation steps", "summary", "key findings",
    "this report", "the report", "current report", "this scan", "the scan",
    "on the report", "in this report", "from this scan", "overall posture",

    # Tool-Specific Identifiers
    "nikto", "sslscan", "mobsf", "zap", "nmap", "mobsf_android", "mobsf_ios",

    # Nikto-specific
    "web server", "http server", "header", "headers", "x-frame-options", 
    "strict-transport-security", "x-content-type-options", "anti-clickjacking",
    "uncommon header", "x-served-by", "x-github-request-id", "x-fastly-request-id",
    "x-timer", "varnish", "cache", "cdn", "fastly", "clickjacking", "mime type",
    "mime-sniffing", "web vulnerability", "server configuration", "http methods", "uri",

    # Nmap-specific
    "nmap scan", "port scan", "service detection", "os detection", "os fingerprinting",
    "mac address", "os guesses", "traceroute", "tcp", "udp", "open port",
    "filtered port", "closed port", "script output", "version detection", 
    "aggressive scan", "syn scan", "udp scan", "service", "script", "latency",
    "port state", "host status", "firewall", "router", "hop", "vendor",

    # ZAP (OWASP ZAP) specific
    "zap scan", "owasp zap", "active scan", "passive scan", "spider", "ajax spider",
    "api scan", "rest api", "soap api", "graphql", "authentication", "session management",
    "broken access control", "sql injection", "xss", "cross-site scripting", 
    "csrf", "cross-site request forgery", "ssrf", "server-side request forgery",
    "insecure deserialization", "vulnerable component", "misconfiguration", 
    "security misconfiguration", "sensitive data exposure", "logging and monitoring",
    "external redirect", "directory listing", "header missing", "cookie flag",
    "alert message", "risk level", "confidence level", "plugin", "rule", "context",
    "authenticated scan", "unauthenticated scan", "scan policy", "automation",

    # MobSF specific
    "mobsf scan", "mobile app", "android", "ios", "apk", "ipa", "app security",
    "static analysis", "dynamic analysis", "malware analysis", "permissions", 
    "api calls", "certificate analysis", "code analysis", "binary analysis",
    "manifest analysis", "network security", "privacy", "data leakage",
    "hardcoded secret", "insecure storage", "encryption", "obfuscation",
    "debugger detection", "root detection", "jailbreak detection", "frida", "objection",
    "security score", "code quality", "info leak", "ssl pinning", "webview",
    "deeplink", "firebase", "api key", "exported component", "vulnerable function"
]