import os
import dotenv

dotenv.load_dotenv()

# Define the base directory for the project.
# This assumes config.py is in chatbot_modules, and project root is one level up.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_LLM_MODE = "gemini"  # or "gemini"
SUPPORTED_LLM_MODES = ["local", "gemini"]

# --- LLM Model Configuration ---
# Local LLM (llama-cpp-python)
LLM_MODEL_ID = "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF"
LLM_MODEL_BASENAME = "openhermes-2.5-mistral-7b.Q4_K_M.gguf"
# Path to store the downloaded GGUF model, relative to PROJECT_ROOT
LLM_MODEL_DIR = os.path.join(PROJECT_ROOT, "pretrained_language_model")

# Gemini API Configuration
# IMPORTANT: Store your Gemini API key as an environment variable for security.
# Example: GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "") # Default to empty string if not set
GEMINI_MODEL_NAME = "gemini-2.5-pro" # Or "gemini-pro", etc.

# --- RAG (Retrieval Augmented Generation) Configuration ---
# Path to your fine-tuned SentenceTransformer model, relative to PROJECT_ROOT
# This should match the save path from S1-2_Model_Retraining.ipynb
RAG_EMBEDDING_MODEL_PATH = os.path.join(PROJECT_ROOT,"fine_tuned_owasp_model_advanced")

# Pinecone Configuration
PINECONE_INDEX_NAME = "owasp-qa"
PINECONE_ENVIRONMENT = "gcp-starter"

# You MUST set PINECONE_API_KEY and PINECONE_ENVIRONMENT as system environment variables.
PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY")
# Example: PINECONE_ENVIRONMENT = os.environ.get("PINECONE_ENVIRONMENT") # e.g., "gcp-starter" or your specific environment
# These are retrieved in chatbot_utils.py
PINECONE_EMBEDDING_DIMENSION = 768 # Dimension of your SentenceTransformer embeddings (e.g., for all-mpnet-base-v2)
PINECONE_METRIC = "cosine" # Metric used in Pinecone index (e.g., "cosine")
PINECONE_CLOUD = "aws" # Your Pinecone cloud provider (e.g., "aws", "gcp", "azure")
PINECONE_REGION = "us-east-1" # Your Pinecone region

# --- Chatbot Settings ---
DEFAULT_MAX_TOKENS = 100000 # Max tokens for LLM responses
DEFAULT_RAG_TOP_K = 3 # Number of top results to retrieve from Pinecone
UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, "uploads")

# --- Chat History Management Settings ---
CHAT_HISTORY_MAX_TURNS = 8 # Maximum number of turns (user+assistant) to keep in full detail
CHAT_HISTORY_SUMMARIZE_THRESHOLD = 4 # Number of oldest turns to summarize when MAX_TURNS is reached
DEFAULT_SUMMARIZE_MAX_TOKENS = 10000000 # Max tokens for generated chat history summaries

# --- Heuristic Keywords for Report-Specific Questions ---
# These keywords help determine if a question is about the uploaded report.
# Refined from previous version to avoid overly generic terms.
REPORT_SPECIFIC_KEYWORDS = [
    # General Report/Scan Keywords (common across tools)
    "report", "scan", "host", "ip", "port", "vulnerability", "alert", "cve",
    "solution", "remediation", "finding", "risk", "instance", "site", "version",
    "target", "implications", "remediation steps", "summary", "key findings",
    "this report", "the report", "current report", "this scan", "the scan",
    "on the report", "in this report", "from this scan", "overall posture",

    # Tool-Specific Identifiers (for routing questions to the correct report)
    "nikto", "sslscan", "mobsf", "zap", "nmap", "mobsf_android", "mobsf_ios",

    # Nikto-specific keywords
    "web server", "http server", "header", "headers", "x-frame-options", 
    "strict-transport-security", "x-content-type-options", "anti-clickjacking",
    "uncommon header", "x-served-by", "x-github-request-id", "x-fastly-request-id",
    "x-timer", "varnish", "cache", "cdn", "fastly", "clickjacking", "mime type",
    "mime-sniffing", "web vulnerability", "server configuration", "http methods", "uri",

    # Nmap-specific keywords
    "nmap scan", "port scan", "service detection", "os detection", "os fingerprinting",
    "mac address", "os guesses", "traceroute", "tcp", "udp", "open port",
    "filtered port", "closed port", "script output", "version detection", 
    "aggressive scan", "syn scan", "udp scan", "service", "script", "latency",
    "port state", "host status", "firewall", "router", "hop", "vendor",

    # ZAP (OWASP ZAP) specific keywords
    "zap scan", "owasp zap", "active scan", "passive scan", "spider", "ajax spider",
    "api scan", "rest api", "soap api", "graphql", "authentication", "session management",
    "broken access control", "sql injection", "xss", "cross-site scripting", 
    "csrf", "cross-site request forgery", "ssrf", "server-side request forgery",
    "insecure deserialization", "vulnerable component", "misconfiguration", 
    "security misconfiguration", "sensitive data exposure", "logging and monitoring",
    "external redirect", "directory listing", "header missing", "cookie flag",
    "alert message", "risk level", "confidence level", "plugin", "rule", "context",
    "authenticated scan", "unauthenticated scan", "scan policy", "automation",

    # MobSF (Mobile Security Framework) specific keywords
    "mobsf scan", "mobile app", "android", "ios", "apk", "ipa", "app security",
    "static analysis", "dynamic analysis", "malware analysis", "permissions", 
    "api calls", "certificate analysis", "code analysis", "binary analysis",
    "manifest analysis", "network security", "privacy", "data leakage",
    "hardcoded secret", "insecure storage", "encryption", "obfuscation",
    "debugger detection", "root detection", "jailbreak detection", "frida", "objection",
    "security score", "code quality", "info leak", "ssl pinning", "webview",
    "deeplink", "firebase", "api key", "exported component", "vulnerable function"
]
