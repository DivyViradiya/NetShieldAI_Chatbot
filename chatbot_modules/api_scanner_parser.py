import os
import re
import uuid
import logging
from typing import Dict, Any, List
from datetime import datetime
import json

# Initialize module logger
logger = logging.getLogger(__name__)

# --- PDF Dependency Integration ---
try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    def extract_text_from_pdf(pdf_path: str) -> str:
        raise NotImplementedError("pdf_extractor.py not found.")

def clean_raw_text(text: str) -> str:
    """
    Aggressively cleans the text to handle PDF artifacts, footers, 
    and jammed text.
    """
    text = re.sub(r'\r\n|\r', '\n', text)
    text = re.sub(r'Page \d+ of \d+', '', text)
    
    # Remove footers and standard noise
    text = re.sub(r'NETSHIELDAI REPORTING ENGINE.*?V\d+\.\d+ // GENERATED.*?\n', '\n', text, flags=re.DOTALL)
    text = re.sub(r'NetShieldAI Security Report \| Page \d+ of \d+', '\n', text)
    
    # Fix "Jammed" labels
    text = re.sub(r'([a-z0-9)])(HIGH|MEDIUM|LOW|INFO) RISK', r'\1 \2 RISK', text)
    text = re.sub(r'([^\s])(HTTP METHOD|PREDICTED RISK|PRIORITY LEVEL|CWE MAPPING|TARGET ENDPOINT URL)', r'\1 \2', text)

    return text

def safe_extract(pattern: str, text: str, default: Any = "N/A", group: int = 1, flags: int = 0) -> Any:
    """ Safely extraction with regex """
    try:
        match = re.search(pattern, text, flags)
        if match:
            return match.group(group).strip()
    except Exception as e:
        logger.warning(f"Regex extraction error: {e}")
    return default

def extract_summary_stats(clean_text: str) -> Dict[str, Any]:
    """ Extracts stats from the new header format """
    stats = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
        "Total": 0,
        "audited": 0,
        "critical_endpoints": 0
    }

    # Extract based on new labels
    stats["Total"] = int(safe_extract(r"TOTAL FINDINGS\s*(\d+)", clean_text, "0"))
    stats["High"] = int(safe_extract(r"CRITICAL / HIGH\s*(\d+)", clean_text, "0"))
    stats["Medium"] = int(safe_extract(r"MEDIUM RISK\s*(\d+)", clean_text, "0"))
    stats["Low"] = int(safe_extract(r"LOW / INFO\s*(\d+)", clean_text, "0"))
    
    stats["audited"] = int(safe_extract(r"(\d+)\s*AUDITED", clean_text, "0"))
    stats["critical_endpoints"] = int(safe_extract(r"CRITICAL ENDPOINTS\s*(\d+)", clean_text, "0"))
    
    return stats

def parse_api_scan_report(raw_text: str) -> Dict[str, Any]:
    clean_text = clean_raw_text(raw_text)
    
    # --- STEP 1: Metadata ---
    base_url = safe_extract(r"API BASE URL\s*(.*?)(?:AUDIT DATE|$)", clean_text, "Unknown").replace('\n', '').strip()
    scan_date = safe_extract(r"AUDIT DATE\s*(\d{4}-\d{2}-\d{2})", clean_text, "N/A")
    
    header_stats = extract_summary_stats(clean_text)
    
    findings_list = []

    # --- STEP 2: Findings ---
    # Split by ENDPOINT_IDENT marker
    finding_chunks = re.split(r"ENDPOINT_IDENT:", clean_text)[1:]

    for chunk in finding_chunks:
        # Title and Risk are often on the first line after the marker
        header_line = chunk.split('\n')[0].strip()
        # Format: METHOD → Title
        header_match = re.search(r"([A-Z]+)\s*→\s*(.*?)$", header_line)
        method = header_match.group(1) if header_match else "GET"
        title = header_match.group(2).strip() if header_match else "Unknown Vulnerability"

        # Risk level is usually jammed or right after the title in the chunk
        risk_match = re.search(r"(HIGH|MEDIUM|LOW|INFORMATIONAL)\s*RISK", chunk, re.IGNORECASE)
        risk_level = risk_match.group(1).upper() if risk_match else "UNKNOWN"
        if risk_level == "INFORMATIONAL": risk_level = "INFO"

        finding = {
            "name": title,
            "method": method,
            "risk_level": risk_level,
            "predicted_risk": safe_extract(r"PREDICTED RISK\s*([\d\.]+)", chunk, "0.0"),
            "priority": safe_extract(r"PRIORITY LEVEL\s*(P\d+ \(.*?\))", chunk, "N/A"),
            "cwe": safe_extract(r"CWE MAPPING\s*(CWE-\d+|N/A)", chunk, "N/A"),
            "url": safe_extract(r"TARGET ENDPOINT URL\s*(.*?)(?:VULNERABILITY INTELLIGENCE|$)", chunk, "N/A", flags=re.DOTALL).replace('\n', '').strip(),
            "description": safe_extract(r"VULNERABILITY INTELLIGENCE\s*(.*?)(?:TCTR THREAT MAGNITUDE|$)", chunk, "N/A", flags=re.DOTALL).strip(),
            "tctr_magnitude": safe_extract(r"TCTR THREAT MAGNITUDE \(API_ENRICHED\)\s*([\d\.]+(?:%)?)", chunk, "0%"),
            "ai_breakdown": safe_extract(r"AI Intelligence Breakdown:\s*(.*?)(?=\[ TCTR\.AI_ENGINE|$)", chunk, "N/A", flags=re.DOTALL).strip()
        }
        
        # Clean up URL (sometimes has trailing text from jamming)
        if finding["url"]:
            finding["url"] = finding["url"].split(" ")[0].strip()

        findings_list.append(finding)

    report = {
        "metadata": {
            "tool": "API Security Audit",
            "target_url": base_url,
            "scan_date": scan_date,
            "report_id": str(uuid.uuid4())
        },
        "summary": header_stats,
        "findings": findings_list
    }

    return report

def process_api_scan_report_file(file_path: str) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"API report not found: {file_path}")
    
    try:
        raw_text = extract_text_from_pdf(file_path)
        if not raw_text.strip():
            raise ValueError("No text extracted from PDF.")
            
        report_data = parse_api_scan_report(raw_text)
        report_data["file_metadata"] = {
            "filename": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path)
        }
        return report_data
    except Exception as e:
        logger.error(f"Error processing API report: {e}")
        raise
