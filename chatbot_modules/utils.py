import os
import json
import logging
from sentence_transformers import SentenceTransformer, util # Added util for cosine similarity
from pinecone import Pinecone, ServerlessSpec, PodSpec
from typing import Dict, Any, List, Optional
import dotenv
import uuid # Added for generating unique namespace IDs
import sys
import re
import datetime

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

# Initialize module logger
logger = logging.getLogger(__name__)

# Load environment variables from a .env file (if present)
dotenv.load_dotenv()

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import configuration settings from the config module
from chatbot_modules.config import (
    RAG_EMBEDDING_MODEL_PATH,
    PINECONE_INDEX_NAME,
    PINECONE_EMBEDDING_DIMENSION,
    PINECONE_METRIC,
    PINECONE_CLOUD,
    PINECONE_REGION,
    DEFAULT_RAG_TOP_K
)

# Pinecone API Key and Environment are still fetched from os.environ
# as recommended for sensitive information
PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY")
PINECONE_ENVIRONMENT = os.environ.get("PINECONE_ENVIRONMENT")


# Global variables to store loaded RAG components
_embedding_model: Optional[SentenceTransformer] = None
_pinecone_index: Optional[Any] = None # Using Any as Pinecone Index object type might vary


def load_embedding_model() -> SentenceTransformer:
    """
    Loads the fine-tuned SentenceTransformer model.
    Loads only once and caches the instance.
    """
    global _embedding_model
    if _embedding_model is None:
        logger.info(f"Loading embedding model from: {RAG_EMBEDDING_MODEL_PATH}")
        try:
            _embedding_model = SentenceTransformer(RAG_EMBEDDING_MODEL_PATH)
            logger.info("Embedding model loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading embedding model: {e}")
            raise
    return _embedding_model

def initialize_pinecone_index() -> Any: # Returns a pinecone.Index object
    """
    Initializes the Pinecone connection and returns the index object.
    Initializes only once and caches the instance.
    """
    global _pinecone_index
    if _pinecone_index is None:
        if not PINECONE_API_KEY or not PINECONE_ENVIRONMENT:
            raise ValueError(
                "Pinecone API Key or Environment not set."
            )
        try:
            pc = Pinecone(api_key=PINECONE_API_KEY, environment=PINECONE_ENVIRONMENT)
            
            # Check if index exists, if not, create it
            existing_indexes = [index_info.name for index_info in pc.list_indexes()]
            if PINECONE_INDEX_NAME not in existing_indexes:
                logger.info(f"{LogColors.INIT}Creating Pinecone index '{PINECONE_INDEX_NAME}'...{LogColors.RESET}")
                
                # Determine spec based on your setup (Serverless vs PodSpec)
                # This should match how you created your index in S2_Embedding_Generation.ipynb
                if PINECONE_CLOUD and PINECONE_REGION: # Assuming Serverless if cloud/region are provided
                    spec = ServerlessSpec(cloud=PINECONE_CLOUD, region=PINECONE_REGION)
                else: # Fallback to PodSpec if specific cloud/region for Serverless are not set
                    spec = PodSpec(environment=PINECONE_ENVIRONMENT)

                pc.create_index(
                    name=PINECONE_INDEX_NAME,
                    dimension=PINECONE_EMBEDDING_DIMENSION,
                    metric=PINECONE_METRIC,
                    spec=spec
                )
            
            _pinecone_index = pc.Index(PINECONE_INDEX_NAME)
            logger.info(f"{LogColors.SUCCESS}Pinecone index '{PINECONE_INDEX_NAME}' initialized.{LogColors.RESET}")
        except Exception as e:
            logger.error(f"Error initializing Pinecone index: {e}")
            raise
    return _pinecone_index

def retrieve_rag_context(query: str, top_k: int = DEFAULT_RAG_TOP_K, namespace: str = "owasp-cybersecurity-kb") -> str:
    """
    Generates an embedding for the query, queries Pinecone, and returns formatted context.

    Args:
        query (str): The user's question.
        top_k (int): The number of top relevant results to retrieve.
        namespace (str): The Pinecone namespace to query. (Kept hardcoded as it's a specific logical unit)

    Returns:
        str: Formatted retrieved context from the knowledge base, or an empty string if none found.
    """
    embedding_model = load_embedding_model()
    pinecone_index = initialize_pinecone_index()

    try:
        # Generate embedding for the query
        query_embedding = embedding_model.encode(query).tolist()

        # Query Pinecone
        response = pinecone_index.query(
            vector=query_embedding,
            top_k=top_k,
            include_metadata=True,
            namespace=namespace
        )

        context_parts = []
        for match in response.matches:
            metadata = match.metadata
            if metadata and "answer" in metadata:
                context_parts.append(f"Q: {metadata.get('question', 'N/A')}\nA: {metadata['answer']}")
            elif metadata and "text" in metadata: # Fallback if you stored general text
                context_parts.append(f"Context: {metadata['text']}")

        if context_parts:
            logger.info(f"{LogColors.EXTERNAL}[EXTERNAL RAG] Retrieved {len(context_parts)} relevant knowledge base chunks for query.{LogColors.RESET}")
            return "\n\nRelevant Information from Knowledge Base:\n" + "\n---\n".join(context_parts)
        else:
            logger.info(f"{LogColors.EXTERNAL}[EXTERNAL RAG] No relevant context found.{LogColors.RESET}")
            return "" # No relevant context found

    except Exception as e:
        logger.error(f"Error during RAG context retrieval: {e}")
        return f"Error retrieving context: {e}"


def _chunk_nmap_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts granular text chunks from parsed NetShieldAI (Nmap) report data 
    optimized for RAG similarity search.
    """
    chunks = []
    
    # --- 1. Extract Core Objects ---
    metadata = parsed_data.get("scan_metadata", {})
    summary = parsed_data.get("summary", {})
    open_ports = parsed_data.get("open_ports", [])
    
    target_ip = metadata.get('target_ip', 'Unknown Target')
    scan_date = metadata.get('scan_date', 'Unknown Date')
    
    # --- 2. Determine Scan Type ---
    scan_args = metadata.get('scan_arguments') or ''
    args_lower = scan_args.lower()
    
    if "-a" in args_lower:
        scan_type = "Aggressive Scan (-A)"
    elif "--script vuln" in args_lower:
        scan_type = "Vulnerability Scan (--script vuln)"
    elif "-ss" in args_lower:
        scan_type = "TCP SYN Scan (Stealth) (-sS)"
    else:
        scan_type = "Standard TCP/Port Scan"

    # --- 3. Chunk: Operational Metadata (How & When) ---
    # Good for queries like: "What command was used?", "When was the scan?", "What tool?"
    operational_text = (
        f"NetShieldAI Scan Operational Data for {target_ip}. "
        f"Tool Used: {metadata.get('tool', 'Nmap')}. "
        f"Report ID: {metadata.get('report_id', 'N/A')}. "
        f"Scan Date: {scan_date}. "
        f"Scan Arguments/Command: {scan_args}. "
        f"Scan Duration: {summary.get('scan_duration_sec', 0)} seconds."
    )
    chunks.append({
        "text": operational_text,
        "id_suffix": "nmap_operational_metadata"
    })

    # --- 4. Chunk: Executive Security Summary (The Verdict) ---
    # Good for queries like: "Is the host secure?", "How many threats found?"
    security_verdict_text = (
        f"NetShieldAI Security Verdict for {target_ip}. "
        f"Host Status: {metadata.get('host_status', 'Down')}. "
        f"Security Posture: {metadata.get('security_posture', 'Unknown')}. "
        f"Total Threats Detected: {summary.get('threats_detected', 0)}. "
        f"Total Open Ports Found: {summary.get('ports_found', 0)}. "
        f"Scan Type Performed: {scan_type}."
    )
    chunks.append({
        "text": security_verdict_text,
        "id_suffix": "nmap_security_summary"
    })

    # --- 5. Chunk: Open Ports List (High-Level Overview) ---
    # Good for queries like: "List all open ports", "What services are running?"
    # (Prevents needing to retrieve 5+ separate chunks just to get a list)
    port_list = [f"{p.get('port')}/{p.get('protocol')} ({p.get('service_name')})" for p in open_ports]
    ports_summary_text = (
        f"Overview of Open Ports for {target_ip}: "
        f"The following {len(open_ports)} ports were found open: "
        f"{', '.join(port_list)}."
    )
    chunks.append({
        "text": ports_summary_text,
        "id_suffix": "nmap_ports_overview"
    })

    # --- 6. Chunks: Detailed Individual Port Findings ---
    # Good for queries like: "What version of HTTP is on port 80?", "Is port 443 open?"
    for i, port_data in enumerate(open_ports):
        port_num = port_data.get('port', 'N/A')
        protocol = port_data.get('protocol', 'tcp')
        service_name = port_data.get('service_name', 'Unknown')
        version = port_data.get('service_version', 'Unknown')
        
        if version == service_name:
            version_text = "Version not explicitly identified"
        else:
            version_text = f"Version: {version}"

        # Create safe ID
        safe_service = str(service_name).replace(' ', '_').replace('?', '').replace('|', '_')

        # NOTE: Including target_ip in EVERY chunk is critical for RAG 
        # so the model knows which IP this port belongs to without retrieving metadata.
        port_chunk_text = (
            f"Detailed Port Finding for {target_ip}: "
            f"Port {port_num} ({protocol}) is {port_data.get('state', 'Open')}. "
            f"Service Name: {service_name}. "
            f"Service Version: {version_text}. "
            f"Local Process: {port_data.get('local_process', 'No PID found')}. "
            f"AI Threat Magnitude: {port_data.get('tctr_magnitude_percent', 'N/A')}%. "
            f"Intelligence Context: {port_data.get('intelligence_breakdown', 'N/A')}."
        )
        
        chunks.append({
            "text": port_chunk_text,
            "id_suffix": f"nmap_port_{port_num}_{safe_service}"
        })

    return chunks

def _chunk_traffic_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts text chunks from Traffic Analysis data for grounding.
    Separates Metrics, Protocols, and specific Conversations.
    """
    chunks = []
    
    metadata = parsed_data.get("scan_metadata", {})
    metrics = parsed_data.get("traffic_metrics", {})
    protocols = parsed_data.get("protocol_hierarchy", [])
    conversations = parsed_data.get("active_conversations", [])
    security_insights = parsed_data.get("security_insights", "N/A")

    # --- Chunk 1: Overview & Metrics ---
    # Good for "How much data was transferred?" or "Was the network busy?"
    overview_text = (
        f"Traffic Analysis Overview for {metadata.get('target_node', 'Target')}. "
        f"Timestamp: {metadata.get('capture_timestamp', 'N/A')}. "
        f"Duration: {metrics.get('duration_sec', 0)}s. "
        f"Volume: {metrics.get('data_volume', '0 KB')}. "
        f"Throughput: {metrics.get('throughput', '0 bps')}. "
        f"Anomalies Detected: {metadata.get('anomalies_detected', 'Unknown')}. "
        f"Automated Verdict: {security_insights}."
    )
    chunks.append({
        "text": overview_text,
        "id_suffix": "traffic_overview_metrics"
    })

    # --- Chunk 2: Dominant Protocols ---
    # Good for "What kind of traffic was detected?"
    # We aggregate the top 3-5 protocols into one text block for context.
    if protocols:
        # Sort by bytes desc
        sorted_protos = sorted(protocols, key=lambda x: x.get('bytes', 0), reverse=True)
        top_protos = [
            f"{p['protocol']} ({p['bytes']} bytes)" 
            for p in sorted_protos if p['protocol'] not in ['frame', 'eth', 'ip', 'data']
        ]
        proto_text = f"Dominant Application Protocols Detected: {', '.join(top_protos)}."
        
        chunks.append({
            "text": proto_text,
            "id_suffix": "traffic_protocol_summary"
        })

    # --- Chunk 3+: Active Conversations (Individual Chunks) ---
    # Critical for "Who did it talk to?" queries.
    # Each conversation gets its own chunk so vector search hits the specific IP.
    for i, conv in enumerate(conversations):
        src = f"{conv.get('src_ip')}:{conv.get('src_port')}"
        dst = f"{conv.get('dst_ip')}:{conv.get('dst_port')}"
        
        conv_text = (
            f"Traffic Connection Detected: Device {src} communicated with {dst}. "
            f"Source Port: {conv.get('src_port')}, Destination Port: {conv.get('dst_port')}."
        )
        
        # Create a unique ID based on the destination IP for easy filtering later
        safe_dst_ip = str(conv.get('dst_ip')).replace('.', '_')
        
        chunks.append({
            "text": conv_text,
            "id_suffix": f"traffic_conn_{safe_dst_ip}_{i}"
        })

    # --- Chunk 4: AI Analyzed Packet Samples (Individual Chunks) ---
    # Captures specific TCTR magnitude and semantic threats per packet
    packet_samples = parsed_data.get("packet_sample", [])
    for i, pkt in enumerate(packet_samples):
        pkt_text = (
            f"Packet Security Inspection on {metadata.get('target_node', 'Target')}: "
            f"Source: {pkt.get('source')} communicated to Destination: {pkt.get('destination')} "
            f"using Protocol: {pkt.get('protocol')}. "
            f"AI Threat Magnitude: {pkt.get('tctr_magnitude_percent', 'N/A')}%. "
            f"Intelligence Context: {pkt.get('intelligence_breakdown', 'N/A')}."
        )
        chunks.append({
            "text": pkt_text,
            "id_suffix": f"traffic_pkt_{i}"
        })

    return chunks

def _chunk_zap_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Chunks ZAP report data into granular, semantic units to maximize RAG retrieval accuracy.
    
    Strategies applied:
    1. Contextual Splitting: Separates 'What' (Description), 'Where' (URL), and 'How' (Solution).
    2. Atomic Remediation: Breaks multi-step solutions into individual actionable tips.
    3. Priority Weighting: Creates specific chunks for High-Risk items to boost search relevance.
    """
    chunks = []
    
    # --- 1. Global Scan Overview Chunk ---
    # Good for: "Summarize the scan results" or "What tool was used?"
    meta = parsed_data.get("scan_metadata", {})
    summary = parsed_data.get("alert_summary", {})
    
    overview_text = (
        f"OWASP ZAP Scan Report for {meta.get('target_url', 'Target')}. "
        f"Overall Risk Magnitude: {meta.get('risk_magnitude', 'N/A')}. "
        f"Tool: {meta.get('tool', 'OWASP ZAP')}. "
        f"Report ID: {meta.get('report_id', 'N/A')}. "
        f"Date: {meta.get('generated_at', 'N/A')}. "
        f"Risk Breakdown: High={summary.get('High', 0)}, "
        f"Medium={summary.get('Medium', 0)}, "
        f"Low={summary.get('Low', 0)}, "
        f"Info={summary.get('Info', 0)}. "
        f"Total Alerts: {summary.get('Total', 0)}."
    )
    
    chunks.append({
        "text": overview_text,
        "metadata": {"type": "scan_overview", "report_id": meta.get('report_id')},
        "id_suffix": "scan_overview"
    })

    findings = parsed_data.get("findings", [])
    for i, finding in enumerate(findings):
        # Extract fields
        name = finding.get('name') or 'Unknown Vulnerability'
        risk = finding.get('risk_level') or 'Info'
        url = finding.get('url', 'N/A')
        description = finding.get('description', '')
        solution = finding.get('solution', '')
        score = finding.get('predicted_score', 'N/A')
        
        # Helper: Clean newlines for text blocks to improve vector embedding quality
        def clean_text(t): return " ".join(t.split()) if t else "N/A"
        
        # Combine all finding details into a single, dense chunk
        chunk_text = (
            f"Vulnerability Finding: '{name}' (Risk Level: {risk}). "
            f"Affected Asset: {url}. "
            f"Automated Score: {score}. "
            f"AI Threat Magnitude: {finding.get('tctr_magnitude_percent', 'N/A')}%. "
            f"Intelligence Context: {finding.get('intelligence_breakdown', 'N/A')}. "
            f"Description: {clean_text(description)} "
            f"Remediation/Solution: {clean_text(solution)}"
        )
        
        if risk.upper() == "HIGH":
            chunk_text = f"CRITICAL PRIORITY: {chunk_text}"
            
        chunks.append({
            "text": chunk_text,
            "metadata": {"type": "zap_finding", "risk": risk, "name": name, "url": url},
            "id_suffix": f"zap_finding_{i}"
        })

    return chunks

def _chunk_api_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Chunks API Security Audit report data into granular units for vector search.
    """
    chunks = []
    meta = parsed_data.get("metadata", {})
    summary = parsed_data.get("summary", {})
    target_url = meta.get("target_url", "N/A")
    scan_date = meta.get("scan_date", "N/A")

    overview_text = (
        f"API Security Audit Report. Target: {target_url}. "
        f"Scan Date: {scan_date}. "
        f"Risk Breakdown: Critical/High={summary.get('High', 0)}, "
        f"Medium={summary.get('Medium', 0)}, "
        f"Low/Info={summary.get('Low', 0)}. "
        f"Audited Endpoints: {summary.get('audited', 0)}."
    )
    chunks.append({"text": overview_text, "id_suffix": "api_overview"})

    findings = parsed_data.get("findings", [])
    for i, finding in enumerate(findings):
        name = finding.get('name', 'Unknown')
        risk = finding.get('risk_level', 'Info')
        url = finding.get('url', 'N/A')
        method = finding.get('method', 'GET')
        description = finding.get('description', 'N/A')
        priority = finding.get('priority', 'N/A')
        tctr = finding.get('tctr_magnitude', '0%')
        ai_breakdown = finding.get('ai_breakdown', 'N/A')

        chunk_text = (
            f"API Vulnerability: '{name}' on [{method}] {url}. "
            f"Risk: {risk}, Priority: {priority}. "
            f"TCTR Impact: {tctr}. "
            f"AI Analysis: {ai_breakdown} "
            f"Technical Details: {description[:500]}..."
        )

        if risk.upper() in ["CRITICAL", "HIGH"]:
            chunk_text = f"CRITICAL API SECURITY BREACH POINT: {chunk_text}"

        chunks.append({
            "text": chunk_text,
            "id_suffix": f"api_vuln_{i}",
            "metadata": {
                "risk": risk,
                "endpoint": url,
                "tctr": tctr
            }
        })

    return chunks


def _chunk_sslscan_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts high-granularity text chunks from parsed SSLScan data.
    Designed for Vector Search (RAG) to answer specific questions about 
    compliance, remediation, dates, and technical details.
    """
    chunks = []
    
    # --- Context Variables ---
    meta = parsed_data.get("metadata", {})
    target = meta.get("target", "Unknown Host")
    scan_date = meta.get("scan_date", "Unknown Date")
    cert = parsed_data.get("certificate_chain", {})
    protocols = parsed_data.get("protocols", {})
    vulns = parsed_data.get("vulnerabilities", [])

    # 1. [METADATA] Scan Identity & Target
    # Matches: "What port was scanned?", "When was the scan performed?"
    chunks.append({
        "text": (f"SSLScan Target Identity: Host {target} on Port 443. "
                 f"Scan performed on {scan_date}. "
                 f"Overall Security Grade: {meta.get('grade', 'N/A')}."),
        "metadata": {"source": "scan_identity", "target": target}
    })

    # 2. [SUMMARY] Executive Security Status
    # Matches: "Is google.com secure?", "Give me a summary."
    vuln_count = len(vulns)
    status = "Risk Detected" if vuln_count > 0 else "Secure"
    chunks.append({
        "text": (f"Executive Security Summary for {target}: The status is {status}. "
                 f"The scan detected {vuln_count} vulnerability findings. "
                 f"Immediate attention is required for Medium/High severity issues."),
        "metadata": {"source": "exec_summary", "target": target}
    })

    # 3. [VULNERABILITY] Individual Findings (One chunk per finding)
    # Matches: "What is the weak cipher issue?", "Explain the DES vulnerability."
    for idx, v in enumerate(vulns):
        chunks.append({
            "text": (f"Vulnerability Finding #{idx+1} on {target}: {v.get('name')}. "
                     f"Severity: {v.get('severity')}. "
                     f"Technical Detail: {v.get('description')} "
                     f"AI Threat Magnitude: {v.get('tctr_magnitude_percent', 'N/A')}%. "
                     f"Intelligence Context: {v.get('intelligence_breakdown', 'N/A')}. "
                     f"Impact: Attackers may exploit this to intercept encrypted traffic."),
            "metadata": {"source": "vuln_detail", "severity": v.get('severity'), "target": target}
        })

    # 4. [REMEDIATION] Action Plan (Synthetic Chunk)
    # Matches: "How do I fix the SSL issues?", "What are the remediation steps?"
    if vulns:
        fix_list = set() # Use set to avoid duplicates
        for v in vulns:
            if "Cipher" in v.get('name', ''):
                fix_list.add("Disable weak ciphers (specifically DES/3DES) in the server configuration")
            if "Protocol" in v.get('name', ''):
                fix_list.add("Disable legacy protocols (TLS 1.0/1.1)")
        
        chunks.append({
            "text": (f"Remediation Action Plan for {target}: To secure this server, you must: "
                     f"{'; '.join(fix_list)}. Apply these changes to the web server or load balancer config."),
            "metadata": {"source": "remediation_plan", "target": target}
        })

    # 5. [COMPLIANCE] Legacy Protocol Risk
    # Matches: "Is TLS 1.0 enabled?", "Does it support deprecated protocols?"
    deprecated = [p for p in protocols.keys() if "1.0" in p or "1.1" in p or "Deprecated" in p]
    if deprecated:
        chunks.append({
            "text": (f"Compliance Warning for {target}: The server supports deprecated Legacy Protocols: {', '.join(deprecated)}. "
                     "These protocols are considered insecure by PCI DSS and NIST standards and should be disabled."),
            "metadata": {"source": "compliance_risk", "target": target}
        })

    # 6. [PROTOCOL] Active Protocol Details (One chunk per protocol)
    # Matches: "What ciphers are used for TLS 1.3?", "Is TLS 1.2 supported?"
    for proto, cipher_list in protocols.items():
        chunks.append({
            "text": (f"Protocol Detail: {proto} is ENABLED on {target}. "
                     f"It supports {len(cipher_list)} cipher suites. "
                     f"This protocol version is {'Secure' if '1.3' in proto or '1.2' in proto else 'Insecure'}."),
            "metadata": {"source": "protocol_detail", "protocol": proto, "target": target}
        })

    # 7. [CIPHER] Strong vs Weak Analysis (Synthetic Split)
    # Matches: "Does it support AES256?", "List the weak ciphers."
    strong_ciphers = []
    weak_ciphers = []
    for proto, c_list in protocols.items():
        for c in c_list:
            desc = f"{c['cipher']} ({c['bits']} bits)"
            if c['bits'] < 128 or "DES" in c['cipher'] or "RC4" in c['cipher']:
                weak_ciphers.append(desc)
            else:
                strong_ciphers.append(desc)
    
    if weak_ciphers:
        chunks.append({
            "text": (f"Weak Cipher Inventory for {target}: The following insecure ciphers are active: "
                     f"{', '.join(weak_ciphers)}. These pose a security risk."),
            "metadata": {"source": "weak_ciphers", "target": target}
        })
    
    if strong_ciphers:
        chunks.append({
            "text": (f"Strong Cipher Inventory for {target}: The server correctly supports modern encryption: "
                     f"{', '.join(strong_ciphers[:10])}... (and others)."),
            "metadata": {"source": "strong_ciphers", "target": target}
        })

    # 8. [CONFIG] Server Hardening Flags
    # Matches: "Is Secure Renegotiation supported?", "Check for CRIME vulnerability."
    conf = parsed_data.get("server_configuration", {})
    if conf:
        chunks.append({
            "text": (f"Server Hardening Configuration for {target}: "
                     f"TLS Compression is {conf.get('tls_compression')}. "
                     f"Secure Renegotiation is {conf.get('secure_renegotiation')}. "
                     f"OCSP Stapling is {conf.get('ocsp_stapling')}."),
            "metadata": {"source": "hardening_config", "target": target}
        })

    # 9. [CERTIFICATE] Identity & Issuer
    # Matches: "Who issued the certificate?", "Is the cert for google.com?"
    chunks.append({
        "text": (f"SSL Certificate Identity: Issued to Common Name (CN) '{cert.get('subject')}'. "
                 f"Issued by '{cert.get('issuer')}'. "
                 f"This certificate validates the identity of {target}."),
        "metadata": {"source": "cert_identity", "target": target}
    })

    # 10. [CERTIFICATE] Technical Validity & Cryptography
    # Matches: "When does the cert expire?", "What is the key size?"
    chunks.append({
        "text": (f"SSL Certificate Technical Details: Expires on {cert.get('leaf_expiry')}. "
                 f"Signature Algorithm: {cert.get('signature_algorithm')}. "
                 f"Key Type: {cert.get('key_type')}. "
                 f"The certificate is currently Valid."),
        "metadata": {"source": "cert_technical", "target": target}
    })

    return chunks

def _chunk_semgrep_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Chunks Semgrep SAST report data into granular units.
    """
    chunks = []
    meta = parsed_data.get("scan_metadata", {})
    summary = parsed_data.get("summary_counts", {})
    
    overview_text = (
        f"Semgrep SAST Security Report. Tool: {meta.get('tool', 'Semgrep')}. "
        f"Summary: Total={summary.get('Total', 0)}, Errors={summary.get('Error', 0)}, "
        f"Warnings={summary.get('Warning', 0)}."
    )
    chunks.append({"text": overview_text, "id_suffix": "semgrep_overview"})

    findings = parsed_data.get("findings", [])
    for i, finding in enumerate(findings):
        rule = finding.get('rule', 'Unknown Rule')
        severity = finding.get('severity', 'INFO')
        file_path = finding.get('file', 'Unknown')
        line = finding.get('line', 'N/A')
        
        # Identity Chunk
        chunks.append({
            "text": (f"SAST Finding: Rule {rule} triggered in {file_path} at line {line}. "
                     f"Severity: {severity}. "
                     f"Vulnerable Code: {finding.get('vulnerable_code', 'N/A')}."),
            "id_suffix": f"semgrep_finding_{i}_id"
        })
        
        # Detail Chunk
        if finding.get('description'):
            chunks.append({
                "text": f"Description for {rule}: {finding.get('description')}",
                "id_suffix": f"semgrep_finding_{i}_desc"
            })
            
        # Code/Fix Chunk
        if finding.get('suggested_fix'):
            chunks.append({
                "text": f"Suggested Fix for {rule} in {file_path}: {finding.get('suggested_fix')}",
                "id_suffix": f"semgrep_finding_{i}_fix"
            })

    return chunks

def _chunk_sql_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts high-granularity text chunks from parsed SQL Injection data.
    Designed for Vector Search (RAG) to answer specific questions about 
    database exposure, injection types, payloads, and remediation.
    """
    chunks = []
    
    # --- Context Variables ---
    meta = parsed_data.get("metadata", {})
    counts = parsed_data.get("summary_counts", {})
    fingerprint = parsed_data.get("database_fingerprint", {})
    vulns = parsed_data.get("vulnerabilities", [])

    target = meta.get("target_url") or "Unknown Target"
    scan_date = meta.get("scan_date") or "Unknown Date"
    db_status = meta.get("database_status") or "Unknown"

    # 1. [METADATA] Scan Identity & Target
    chunks.append({
        "text": (f"SQL Injection Scan Target Identity: URL {target}. "
                 f"Scan performed on {scan_date}. "
                 f"Audit Status: {meta.get('audit_status', 'Unknown')}. "
                 f"ML Threat Index: {meta.get('ml_threat_index', 'N/A')}. "
                 f"Data Extraction Possible: {meta.get('data_exfiltration', 'Unknown')}."),
        "metadata": {"source": "scan_identity", "target": target}
    })

    # 2. [SUMMARY] Executive Security Status
    # Matches: "Is the database exposed?", "How many vulnerabilities were found?"
    vuln_count = counts.get("vulnerabilities_found", 0)
    type_count = counts.get("injection_types_count", 0)
    risk_level = "CRITICAL" if db_status.lower() == "exposed" or vuln_count > 0 else "Safe"
    
    chunks.append({
        "text": (f"Executive Security Summary for {target}: The overall risk level is {risk_level}. "
                 f"The scan detected {vuln_count} vulnerability findings across {type_count} distinct injection types. "
                 f"Immediate remediation is required to prevent data leakage."),
        "metadata": {"source": "exec_summary", "target": target}
    })

    # 3. [FINGERPRINT] Database Technology & User Context
    # Matches: "What database version is running?", "Did the scan get root access?"
    dbms = fingerprint.get("detected_dbms") or "Unknown"
    version = fingerprint.get("version") or "Unknown"
    user = fingerprint.get("current_user") or "Unknown"
    current_db = fingerprint.get("current_database") or "Unknown"
    
    # High-value context for RAG
    is_privileged = any(role in user.lower() for role in ["root", "admin", "dba", "sa"])
    privilege_note = "This is a PRIVILEGED account (High Risk)." if is_privileged else "This appears to be a standard user account."

    chunks.append({
        "text": (f"Database Fingerprint for {target}: The backend DBMS is {dbms} (Version: {version}). "
                 f"The application is connected as user '{user}' to database '{current_db}'. "
                 f"{privilege_note}"),
        "metadata": {"source": "db_fingerprint", "target": target, "dbms": dbms}
    })

    # 4. [VULNERABILITY] Individual Findings (One chunk per finding)
    # Matches: "Explain the boolean-blind injection", "What is the risk of the error-based flaw?"
    for idx, v in enumerate(vulns):
        # Clean payload for readability in text
        payload_clean = v.get('payload', '').replace('\n', ' ').strip()
        
        chunks.append({
            "text": (f"Vulnerability Finding #{idx+1} on {target}: {v.get('title')}. "
                     f"Risk Level: {v.get('risk_level')}. "
                     f"Injection Type: {v.get('injection_type')}. "
                     f"Affected Parameter: {v.get('parameter', 'N/A')}. "
                     f"Technical Detail: This vector allows attackers to manipulate the query using the payload '{payload_clean}'."),
            "metadata": {"source": "vuln_detail", "risk": v.get('risk_level'), "type": v.get('injection_type'), "target": target}
        })

    # 5. [REMEDIATION] Action Plan (Aggregated)
    # Matches: "How do I fix the SQL injection?", "What code changes are needed?"
    if vulns:
        fix_strategies = set()
        for v in vulns:
            if v.get('remediation'):
                fix_strategies.add(v.get('remediation'))
        
        # Default fallback if empty
        if not fix_strategies:
            fix_strategies.add("Use parameterized queries (Prepared Statements)")
            
        chunks.append({
            "text": (f"Remediation Action Plan for {target}: To secure this database, you must: "
                     f"{'; '.join(fix_strategies)}. "
                     f"Sanitize all user inputs and disable verbose error messages in production."),
            "metadata": {"source": "remediation_plan", "target": target}
        })

    # 6. [PAYLOADS] Technical Evidence (Synthetic Chunk for WAF)
    # Matches: "Show me the attack payloads", "Give me WAF rules to block this."
    if vulns:
        # Grab a few distinct payloads to provide context without overloading the chunk
        payload_samples = [v.get('payload', '')[:60] + "..." for v in vulns[:4]] 
        
        chunks.append({
            "text": (f"Attack Payload Evidence for {target}: The scanner successfully executed these malicious SQL patterns: "
                     f"{' || '.join(payload_samples)}. "
                     f"These strings should be blocked by your Web Application Firewall (WAF)."),
            "metadata": {"source": "payload_evidence", "target": target}
        })

    return chunks

def _chunk_generic_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Transforms pre-chunked generic report data into a standardized chunk format.

    This function takes the output of the generic parser (which chunks by word count)
    and reformats it. It creates a primary metadata chunk for overall context and then
    converts each existing text chunk into the standardized format with a unique ID.

    Args:
        parsed_data (Dict[str, Any]): The structured data from a generic report parser.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, where each dictionary
                               represents a standardized text chunk.
    """
    chunks = []
    file_metadata = parsed_data.get("file_metadata", {})
    parsing_metadata = parsed_data.get("parsing_metadata", {})
    filename = file_metadata.get('filename', 'unknown_file')

    # 1. Create an overall summary chunk from the report's metadata.
    # This provides high-level context for the chunks that follow.
    summary_text = (
        f"Summary for report file: '{filename}'. "
        f"Parser type: {parsing_metadata.get('parser_type', 'N/A')}, "
        f"Total words found: {parsing_metadata.get('total_words', 'N/A')}, "
        f"Content is split into {parsing_metadata.get('total_chunks', 'N/A')} parts."
    )
    chunks.append({
        "text": summary_text,
        "id_suffix": "generic_report_metadata_summary"
    })

    # Sanitize the filename to ensure it's valid for use in an ID.
    filename_sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', filename)

    # 2. Iterate through the pre-chunked content and reformat it.
    # Each chunk from the generic parser becomes a new standardized chunk.
    for content_chunk in parsed_data.get("content_chunks", []):
        chunk_id = content_chunk.get('chunk_id', 'N/A')
        chunk_text = content_chunk.get('text', '')

        # Only add chunks that contain actual text content.
        if chunk_text.strip():
            chunks.append({
                # Prepending the text with a part indicator adds context.
                "text": f"Report Content (Part {chunk_id} of {parsing_metadata.get('total_chunks', 'N/A')}): {chunk_text}",
                "id_suffix": f"generic_content_chunk_{filename_sanitized}_{chunk_id}"
            })

    return chunks

def _chunk_killchain_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Converts parsed Kill Chain Analysis data into semantic text chunks 
    optimized for vector embedding and retrieval.
    Returns a list of dictionaries: [{"text": "...", "metadata": {...}}]
    """
    chunks = []
    
    # --- Extract Data Helpers ---
    meta = parsed_data.get("metadata", {})
    risks = parsed_data.get("risk_summary", {})
    phases = parsed_data.get("phase_analysis", {})
    vulns = parsed_data.get("vulnerabilities", [])
    target = meta.get("target", "Target System")

    # --- Chunk 1: Executive Kill Chain Summary ---
    summary_text = (
        f"Kill Chain Audit Summary for {target}. "
        f"Scan Date: {meta.get('scan_date', 'Unknown')}. "
        f"Aggression: {meta.get('aggression', 'N/A')}. "
        f"Total Items: {risks.get('total', 0)}. "
        f"Risk Profile: {risks.get('critical', 0)} Critical, {risks.get('high', 0)} High, "
        f"{risks.get('medium', 0)} Medium / Low findings. "
        f"Verdict: {meta.get('profile', 'Full Audit')}."
    )
    chunks.append({
        "text": summary_text,
        "metadata": {"source": "killchain_summary", "type": "overview"}
    })

    # --- Chunk 2: Multi-Phase Audit Analysis ---
    recon = phases.get("recon", {})
    net = phases.get("network_audit", {})
    web = phases.get("web_audit", {})
    traffic = phases.get("traffic_audit", {})

    audit_text = (
        f"Kill Chain Phased Audit for {target}: "
        f"1. Recon: {recon.get('subdomains_count', 0)} subdomains, Server: {recon.get('server', 'N/A')}. "
        f"2. Network: Status {net.get('status', 'N/A')}, OS {net.get('os', 'N/A')}, Ports: {', '.join(net.get('open_ports', []))[:200]}. "
        f"3. Web: WAF {web.get('waf', 'N/A')}, Surface {web.get('surface', 'N/A')}. "
        f"4. Traffic: {traffic.get('packets', 0)} packets captured."
    )
    chunks.append({
        "text": audit_text,
        "metadata": {"source": "killchain_phases", "type": "technical_audit"}
    })

    # --- Chunk 4+: Phase 3 - Exploitation (Vulnerabilities) ---
    for i, v in enumerate(vulns):
        severity = v.get("severity", "INFO").upper()
        title = v.get("title", "Unknown Issue")
        
        # Clean description
        raw_desc = v.get("description", "").replace("\n", " ")
        description = (raw_desc[:250] + "...") if len(raw_desc) > 250 else raw_desc
        
        # Clean evidence/payload
        evidence = v.get("evidence", "N/A").replace("\n", " ")
        payload = v.get("payload", "")
        
        ml_score = v.get("ml_threat_score", "N/A")
        
        if severity in ["CRITICAL", "HIGH"]:
            chunk_text = (
                f"Confirmed Vulnerability ({severity}): {title} on {target}. "
                f"ML Risk Score: {ml_score}/10.0. "
                f"CWE: {v.get('cwe', 'N/A')}. "
                f"Context: {description} "
                f"Remediation: {v.get('remediation', 'N/A')}."
            )
        else:
            chunk_text = (
                f"Security Finding ({severity}): {title} on {target}. "
                f"ML Risk Score: {ml_score}/10.0. "
                f"CWE: {v.get('cwe', 'N/A')}. "
                f"Action Recommended: {v.get('remediation', 'N/A')}."
            )
        
        chunks.append({
            "text": chunk_text,
            "metadata": {
                "source": "killchain_vuln",
                "finding_index": i,
                "severity": severity,
                "ml_score": ml_score
            }
        })

    return chunks

def load_report_chunks_and_embeddings(parsed_report_data: Dict[str, Any], report_type: str, session_id: str) -> str:
    """
    Orchestrates the chunking and embedding process for a newly loaded report,
    and upserts them into a temporary Pinecone namespace unique to the session.
    Returns the generated namespace ID.
    """
    embedding_model = load_embedding_model() # Ensure model is loaded
    pinecone_index = initialize_pinecone_index() # Ensure index is initialized

    # --- NEW: Pre-upload Lifecycle Cleanup ---
    report_namespace = f"report-{session_id}"
    try:
        # Check if namespace has vectors and wipe them to prevent context pollution
        # from old/previous reports in the same session.
        stats = pinecone_index.describe_index_stats()
        if report_namespace in stats.get('namespaces', {}):
            logger.info(f"Wiping existing vectors in namespace: {report_namespace}")
            pinecone_index.delete(delete_all=True, namespace=report_namespace)
    except Exception as e:
        logger.warning(f"Failed to perform pre-upload cleanup for {report_namespace}: {e}")

    if report_type.lower() == "nmap":
        raw_chunks_with_metadata = _chunk_nmap_report(parsed_report_data)
    elif report_type.lower() == "zap":
        raw_chunks_with_metadata = _chunk_zap_report(parsed_report_data)
    elif report_type.lower() == "sslscan": # New condition for SSLScan
        raw_chunks_with_metadata = _chunk_sslscan_report(parsed_report_data)
    elif report_type.lower() == "pcap":
        raw_chunks_with_metadata = _chunk_traffic_report(parsed_report_data)
    elif report_type.lower() == "sql":
        raw_chunks_with_metadata = _chunk_sql_report(parsed_report_data)
    elif report_type.lower() == "killchain":
        raw_chunks_with_metadata = _chunk_killchain_report(parsed_report_data)
    elif report_type.lower() in ("api_scanner", "api"):
        raw_chunks_with_metadata = _chunk_api_report(parsed_report_data)
    elif report_type.lower() == "semgrep":
        raw_chunks_with_metadata = _chunk_semgrep_report(parsed_report_data)
    elif report_type.lower() in ("generic_security_report", "generic_pdf"):
        # First, we need to transform the raw text into the structure expected by _chunk_generic_report
        # or just create a simple chunk list here.
        # Actually, _chunk_generic_report expects a structure from a generic parser.
        # Let's simplify and just create chunks from raw text for this type.
        raw_text = parsed_report_data.get("raw_text", "")
        # Simple split into ~500 word chunks
        words = raw_text.split()
        chunks_text = [" ".join(words[i:i+500]) for i in range(0, len(words), 500)]
        raw_chunks_with_metadata = [{"text": c, "id_suffix": f"gen_sec_{i}"} for i, c in enumerate(chunks_text)]
    
    else:
        logger.warning(f"Unknown report type '{report_type}'. Cannot chunk report.")
        return ""

    if not raw_chunks_with_metadata:
        logger.warning(f"No chunks generated for the {report_type.upper()} report.")
        return ""

    # Generate a unique namespace ID for this report session
    report_namespace = f"report-{session_id}"
    logger.info(f"Indexing {len(raw_chunks_with_metadata)} chunks into namespace: {report_namespace}")

    vectors_to_upsert = []
    # For batching if many chunks:
    batch_size = 50 

    for i, chunk_data in enumerate(raw_chunks_with_metadata):
        chunk_text = chunk_data["text"]
        # Generate embedding (removed .tolist() as convert_to_numpy=False returns list)
        chunk_embedding = embedding_model.encode(chunk_text, convert_to_numpy=False) # Fix: removed .tolist()
        
        # Create a unique ID for each vector within the namespace
        vector_id = f"{chunk_data.get('id_suffix', f'chunk-{i}')}"
        
        vectors_to_upsert.append({
            "id": vector_id,
            "values": chunk_embedding,
            "metadata": {"text": chunk_text, "report_type": report_type, "chunk_index": i}
        })

        if len(vectors_to_upsert) >= batch_size:
            pinecone_index.upsert(vectors=vectors_to_upsert, namespace=report_namespace)
            vectors_to_upsert = []
    
    # Upsert any remaining vectors
    if vectors_to_upsert:
        pinecone_index.upsert(vectors=vectors_to_upsert, namespace=report_namespace)

    logger.info(f"Successfully indexed report in namespace: {report_namespace}")
    
    return report_namespace # Return the namespace ID for later retrieval


def retrieve_internal_rag_context(query: str, report_namespace: str, top_k: int = 3) -> str:
    """
    Retrieves the most relevant text chunks from the temporary Pinecone namespace
    for the current report, based on the user's query.

    Args:
        query (str): The user's question.
        report_namespace (str): The unique Pinecone namespace for the current report.
        top_k (int): The number of top relevant results to retrieve.

    Returns:
        str: Formatted relevant context from the report, or an empty string if none found.
    """
    if not report_namespace:
        return "" # No report namespace provided

    embedding_model = load_embedding_model()
    pinecone_index = initialize_pinecone_index()

    try:
        query_embedding = embedding_model.encode(query).tolist() # query_embedding should still be a list

        # Query the specific report namespace
        response = pinecone_index.query(
            vector=query_embedding,
            top_k=top_k,
            include_metadata=True,
            namespace=report_namespace # Query the specific report namespace
        )

        context_parts = []
        for match in response.matches:
            # You can set a minimum similarity threshold if desired
            # if match["similarity"] > 0.5: # Example threshold
            metadata = match.metadata
            if metadata and "text" in metadata:
                context_parts.append(metadata["text"])
        
        if context_parts:
            logger.info(f"{LogColors.INTERNAL}[INTERNAL RAG] Retrieved {len(context_parts)} relevant report chunks for query.{LogColors.RESET}")
            return "\n\nRelevant Information from Current Report:\n" + "\n---\n".join(context_parts)
        else:
            logger.info(f"{LogColors.INTERNAL}[INTERNAL RAG] No relevant context found from current report.{LogColors.RESET}")
            return "" # No relevant context found

    except Exception as e:
        logger.error(f"Error during internal RAG context retrieval: {e}")
        return f"Error retrieving report context: {e}"

def delete_report_namespace(report_namespace: str):
    """
    Deletes a specific Pinecone namespace used for a report session.
    Call this when a new report is loaded or the application exits.
    """
    if not report_namespace:
        return

    pinecone_index = initialize_pinecone_index()
    try:
        logger.info(f"Deleting Pinecone namespace: {report_namespace}")
        pinecone_index.delete(delete_all=True, namespace=report_namespace)
    except Exception as e:
        logger.error(f"Error deleting Pinecone namespace '{report_namespace}': {e}")

