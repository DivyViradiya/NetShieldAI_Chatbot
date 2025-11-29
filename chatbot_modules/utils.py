import os
import json
from sentence_transformers import SentenceTransformer, util # Added util for cosine similarity
from pinecone import Pinecone, ServerlessSpec, PodSpec
from typing import Dict, Any, List, Optional
import dotenv
import uuid # Added for generating unique namespace IDs
import sys
import re

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
        print(f"Loading SentenceTransformer model from: {RAG_EMBEDDING_MODEL_PATH}")
        try:
            _embedding_model = SentenceTransformer(RAG_EMBEDDING_MODEL_PATH)
            print("SentenceTransformer model loaded successfully.")
        except Exception as e:
            print(f"Error loading SentenceTransformer model from {RAG_EMBEDDING_MODEL_PATH}: {e}")
            print("Please ensure the model path is correct and the model was saved properly (from S1-2_Model_Retraining.ipynb).")
            raise
    return _embedding_model

def initialize_pinecone_index() -> Any: # Returns a pinecone.Index object
    """
    Initializes the Pinecone connection and returns the index object.
    Initializes only once and caches the instance.
    """
    global _pinecone_index
    if _pinecone_index is None:
        print(f"Initializing Pinecone index: {PINECONE_INDEX_NAME}")
        if not PINECONE_API_KEY or not PINECONE_ENVIRONMENT:
            raise ValueError(
                "Pinecone API Key or Environment not set. "
                "Please set PINECONE_API_KEY and PINECONE_ENVIRONMENT "
                "environment variables."
            )
        try:
            pc = Pinecone(api_key=PINECONE_API_KEY, environment=PINECONE_ENVIRONMENT)
            
            # Check if index exists, if not, create it
            existing_indexes = [index_info.name for index_info in pc.list_indexes()]
            if PINECONE_INDEX_NAME not in existing_indexes:
                print(f"Pinecone index '{PINECONE_INDEX_NAME}' not found. Creating it...")
                
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
                print(f"Pinecone index '{PINECONE_INDEX_NAME}' created.")
            
            _pinecone_index = pc.Index(PINECONE_INDEX_NAME)
            print("Pinecone index initialized successfully.")
        except Exception as e:
            print(f"Error initializing Pinecone index: {e}")
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
            return "\n\nRelevant Information from Knowledge Base:\n" + "\n---\n".join(context_parts)
        else:
            return "" # No relevant context found

    except Exception as e:
        print(f"Error during RAG context retrieval: {e}")
        return f"Error retrieving context: {e}"


def _chunk_nmap_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts meaningful text chunks from parsed Nmap report data for LLM grounding.
    Each chunk represents a specific network finding or high-level summary.
    """
    chunks = []
    metadata = parsed_data.get("scan_metadata", {})
    summary = parsed_data.get("summary", {})
    
    # Determine Scan Type (Logic duplicated from prompt formatter)
    scan_args = metadata.get('scan_arguments', '')
    args_lower = scan_args.lower()
    if "-a" in args_lower:
        scan_type = "Aggressive Scan (-A) - Includes OS/Version/Scripting/Traceroute"
    elif "-sv" in args_lower:
        scan_type = "Service Version Detection (-sV)"
    elif "-ss" in args_lower:
        scan_type = "TCP SYN Scan (Stealth) (-sS)"
    elif "-st" in args_lower:
        scan_type = "TCP Connect Scan (-sT)"
    elif "-sn" in args_lower or "-sp" in args_lower:
        scan_type = "Ping Scan (Host Discovery)"
    elif "-sN" in args_lower or "-sF" in args_lower or "-sX" in args_lower:
        scan_type = "Stealth/FIN/Xmas Scans"
    else:
        scan_type = "Standard TCP/Port Scan"


    # --- Chunk 1: Overall scan metadata ---
    scan_summary_text = (
        f"Nmap Scan Metadata: Target IP: {metadata.get('target_ip', 'N/A')}, "
        f"Host Status: {metadata.get('host_status', 'N/A')}, "
        f"Scan Date: {metadata.get('scan_date', 'N/A')}. "
        f"Scan Type: {scan_type}. "
        f"Total Open Ports: {summary.get('open_ports_count', 0)}."
    )
    chunks.append({
        "text": scan_summary_text,
        "id_suffix": "nmap_metadata_summary"
    })

    # --- Chunk 2 (and subsequent): Detailed Open Port Findings ---
    for i, port_data in enumerate(parsed_data.get("open_ports", [])):
        port = port_data.get('port', 'N/A')
        service = port_data.get('service_name', 'N/A')
        version = port_data.get('service_version', 'N/A')
        state = port_data.get('state', 'N/A')
        local_process = port_data.get('local_process', 'N/A')
        
        # Helper for a clean ID suffix
        safe_service = service.replace(' ', '_').replace('?', '').replace('-', '_')

        port_chunk_text = (
            f"Open Port Finding {i+1}: Port {port}/{port_data.get('protocol', 'tcp')}. "
            f"Service: {service} (Version: {version}). "
            f"State: {state}. Local Process: {local_process}."
        )
        chunks.append({
            "text": port_chunk_text,
            "id_suffix": f"nmap_port_detail_{port}_{safe_service}_{i}"
        })
            
    return chunks

def _chunk_zap_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts meaningful text chunks from parsed ZAP report data.
    Each chunk represents a specific vulnerability finding (Description, Solution, etc.) 
    or a high-level summary.
    """
    chunks = []
    metadata = parsed_data.get("scan_metadata", {})
    
    # Aligning keys with the actual parsed JSON structure
    target_url = metadata.get('target_url', metadata.get('site', 'N/A'))
    tool_info = metadata.get('tool', 'ZAP Scanner')

    # --- Chunk 1: Overall scan metadata (more detailed) ---
    scan_summary_text = (
        f"ZAP Scan Metadata: Target URL: {target_url}, "
        f"Tool: {tool_info}, "
        f"Report ID: {metadata.get('report_id', 'N/A')}, "
        f"Generated At: {metadata.get('generated_at', 'N/A')}. "
        f"Total alerts (Summary Count): {parsed_data.get('summary', {}).get('total_alerts', 0)}."
    )
    chunks.append({
        "text": scan_summary_text,
        "id_suffix": "zap_scan_metadata_summary"
    })

    # --- Chunk 2: Alerts by Risk Counts ---
    risk_counts = parsed_data.get('summary', {}).get('risk_counts', {})
    if risk_counts:
        risk_summary_text = "ZAP Alert Counts by Risk Level: "
        risk_details = [f"{risk_level}: {count}" for risk_level, count in risk_counts.items()]
        
        if risk_details:
            risk_summary_text += ", ".join(risk_details) + "."
            chunks.append({
                "text": risk_summary_text,
                "id_suffix": "zap_risk_counts_summary"
            })

    # --- Chunk 3 (and subsequent): Detailed Vulnerability Findings ---
    for i, vuln in enumerate(parsed_data.get("vulnerabilities", [])):
        vuln_name = vuln.get('name', 'N/A')
        vuln_risk = vuln.get('risk', 'N/A')
        vuln_url = vuln.get('url', 'N/A')
        vuln_desc = vuln.get('description', 'N/A')
        vuln_solution = vuln.get('solution', 'N/A')
        cwe_id = vuln.get('cwe_id', 'N/A')
        plugin_id = vuln.get('plugin_id', 'N/A')
        
        # Helper for a clean ID suffix
        safe_name = vuln_name.replace(' ', '_').replace('(', '').replace(')', '').replace('"', '')

        # --- Chunk 3: Core Vulnerability and Location ---
        core_vuln_chunk = {
            "text": (
                f"Vulnerability Finding {i+1}: '{vuln_name}' (Risk: {vuln_risk}, Score: {vuln.get('predicted_score', 'N/A')}). "
                f"CWE-ID: {cwe_id}, Plugin ID: {plugin_id}. Primary Affected URL: {vuln_url}."
            ),
            "id_suffix": f"zap_vuln_core_{safe_name}_{i}"
        }
        chunks.append(core_vuln_chunk)

        # --- Chunk 4: Vulnerability Description ---
        if vuln_desc and vuln_desc != 'N/A':
            chunks.append({
                "text": f"Description for '{vuln_name}': {vuln_desc}",
                "id_suffix": f"zap_vuln_description_{safe_name}_{i}"
            })

        # --- Chunk 5: Vulnerability Solution ---
        if vuln_solution and vuln_solution != 'N/A':
            chunks.append({
                "text": f"Solution for '{vuln_name}': {vuln_solution}",
                "id_suffix": f"zap_vuln_solution_{safe_name}_{i}"
            })
            
        # --- Chunk 6: Vulnerability References ---
        if vuln.get('references'):
            references_text = f"References for '{vuln_name}': " + ", ".join(vuln['references']) + "."
            chunks.append({
                "text": references_text,
                "id_suffix": f"zap_vuln_references_{safe_name}_{i}"
            })

        # --- Chunk 7: Individual Affected URLs/Instances (Only if detailed instance data exists) ---
        # Note: In your current JSON, vuln.get('urls') is usually [] for header-based alerts, 
        # so this block will only run for instances with deep, specific details.
        if vuln.get('urls'):
            for j, instance in enumerate(vuln['urls']):
                instance_url = instance.get('url', 'N/A')
                instance_method = instance.get('method', 'N/A')
                instance_param = instance.get('parameter', 'N/A')
                
                # Handling potential None values for optional fields
                instance_attack = instance.get('attack') or 'N/A'
                instance_evidence = instance.get('evidence') or 'N/A'
                instance_other = instance.get('other_info') or 'N/A'

                instance_chunk_text = (
                    f"Detailed Instance {j+1} of '{vuln_name}' (Risk: {vuln_risk}): "
                    f"URL: {instance_url}, Method: {instance_method}, Parameter: {instance_param}. "
                    f"Attack Payload (Partial): {instance_attack[:200]}{'...' if len(instance_attack) > 200 else ''}. "
                    f"Evidence (Partial): {instance_evidence[:200]}{'...' if len(instance_evidence) > 200 else ''}. "
                    f"Other Info: {instance_other[:100]}{'...' if len(instance_other) > 100 else ''}."
                )
                chunks.append({
                    "text": instance_chunk_text,
                    "id_suffix": f"zap_vuln_instance_{safe_name}_{i}_{j}"
                })
                
    return chunks

def _chunk_sslscan_report(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts meaningful text chunks from parsed SSLScan report data.
    Each chunk represents a specific finding or detail from the report,
    along with metadata.
    """
    chunks = []
    metadata = parsed_data.get("scan_metadata", {})
    
    # Chunk 1: Overall summary (Streamlined to use available fields)
    chunks.append({
        "text": (f"SSLScan Summary: Target host {metadata.get('target_host', 'N/A')}, "
                 f"Port {metadata.get('port', 'N/A')}. "
                 f"Scan performed at {metadata.get('scan_date', 'N/A')}."
                 ),
        "id_suffix": "sslscan_summary"
    })

    # Chunk 2: Protocols status
    protocols_text = "SSL/TLS Protocols: " + ", ".join([f"{p.get('name', 'N/A')} {p.get('status', 'N/A')}" for p in parsed_data.get('protocols', [])])
    chunks.append({
        "text": protocols_text,
        "id_suffix": "sslscan_protocols"
    })

    # Chunk 3: Security features (Using 'server_configuration' for correct data access)
    security_features_text = "TLS Security Features: "
    features = []
    for feature, status in parsed_data.get('server_configuration', {}).items():
        if isinstance(status, list):
            features.append(f"{feature.replace('_', ' ').title()}: {', '.join(status)}")
        else:
            features.append(f"{feature.replace('_', ' ').title()}: {status}")
    security_features_text += ", ".join(features)
    chunks.append({
        "text": security_features_text,
        "id_suffix": "sslscan_security_features"
    })

    # Chunk 4: Supported Ciphers (Extracting only accepted ciphers)
    ciphers = parsed_data.get('supported_ciphers')
    if ciphers:
        ciphers_text = "Supported Server Ciphers: " + "; ".join([
            f"{c.get('name', 'N/A')} ({c.get('bits', 'N/A')} bits) on {c.get('protocol', 'N/A')}"
            for c in ciphers
        ])
        chunks.append({
            "text": ciphers_text,
            "id_suffix": "sslscan_ciphers"
        })
        
    # Chunk 5: Detected Vulnerabilities
    vulnerabilities = parsed_data.get("vulnerabilities", [])
    if vulnerabilities:
        vuln_text = "Detected Vulnerabilities: " + "; ".join([
            f"[{v.get('severity', 'N/A')}] {v.get('description', 'N/A')}"
            for v in vulnerabilities
        ])
        chunks.append({
            "text": vuln_text,
            "id_suffix": "sslscan_vulnerabilities"
        })


    # Chunk 6: SSL Certificate Details (Streamlined to available fields)
    certificate = parsed_data.get('ssl_certificate', {})
    if certificate:
        cert_details_text = (
            f"SSL Certificate: Common Name '{certificate.get('common_name', 'N/A')}', "
            f"Issuer '{certificate.get('issuer', 'N/A')}', "
            f"Signature Algorithm '{certificate.get('signature_algorithm', 'N/A')}', "
            f"Key Details '{certificate.get('key_details', 'N/A')}'. "
            f"Valid from {certificate.get('not_valid_before', 'N/A')} to {certificate.get('not_valid_after', 'N/A')}. "
        )
        # Note: Altnames is excluded as the field was empty in the last output example and subject/rsa_key_strength are also not present.
        chunks.append({
            "text": cert_details_text,
            "id_suffix": "sslscan_certificate"
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


def load_report_chunks_and_embeddings(parsed_report_data: Dict[str, Any], report_type: str, session_id: str) -> str:
    """
    Orchestrates the chunking and embedding process for a newly loaded report,
    and upserts them into a temporary Pinecone namespace unique to the session.
    Returns the generated namespace ID.
    """
    embedding_model = load_embedding_model() # Ensure model is loaded
    pinecone_index = initialize_pinecone_index() # Ensure index is initialized

    if report_type.lower() == "nmap":
        raw_chunks_with_metadata = _chunk_nmap_report(parsed_report_data)
    elif report_type.lower() == "zap":
        raw_chunks_with_metadata = _chunk_zap_report(parsed_report_data)
    elif report_type.lower() == "sslscan": # New condition for SSLScan
        raw_chunks_with_metadata = _chunk_sslscan_report(parsed_report_data)
    else:
        print(f"Warning: Unknown report type '{report_type}'. Cannot chunk report.")
        return ""

    if not raw_chunks_with_metadata:
        print(f"No chunks generated for the {report_type.upper()} report.")
        return ""

    print(f"Generated {len(raw_chunks_with_metadata)} chunks for the {report_type.upper()} report. Generating embeddings and upserting to Pinecone...")
    
    # Generate a unique namespace ID for this report session
    report_namespace = f"report-{session_id}"
    print(f"Using temporary Pinecone namespace: {report_namespace}")

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

    print(f"Successfully upserted {len(raw_chunks_with_metadata)} embeddings to Pinecone namespace: {report_namespace}")
    
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
            return "\n\nRelevant Information from Current Report:\n" + "\n---\n".join(context_parts)
        else:
            return "" # No relevant context found

    except Exception as e:
        print(f"Error during internal RAG context retrieval: {e}")
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
        print(f"Deleting Pinecone namespace: {report_namespace}...")
        pinecone_index.delete(delete_all=True, namespace=report_namespace)
        print(f"Namespace '{report_namespace}' deleted successfully.")
    except Exception as e:
        print(f"Error deleting Pinecone namespace '{report_namespace}': {e}")
        # import traceback
        # traceback.print_exc() # For debugging, if needed

