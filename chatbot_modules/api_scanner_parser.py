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
    
    # 1. Remove the footer that jams into titles
    text = re.sub(r'NETSHIELDAI.*?GENERATED \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', '\n', text, flags=re.DOTALL)
    
    # 2. Fix "Jammed" Risk Levels (e.g., "15HIGH" -> "15 HIGH")
    text = re.sub(r'([a-z0-9)])(HIGH|MEDIUM|LOW|INFO)', r'\1 \2', text)
    
    # 3. Fix "Jammed" URL/Score fields
    text = re.sub(r'([\d\w])(TARGET URL)', r'\1 \2', text)
    
    # 4. Ensure RISK is separated
    text = re.sub(r'([^\s])(HIGH|MEDIUM|LOW|INFO) RISK', r'\1 \2 RISK', text)

    return text

def safe_extract(pattern: str, text: str, default: Any = "N/A", group: int = 1, flags: int = 0) -> Any:
    """
    Safely attempts to extract a pattern from text.
    Logs a warning if the extraction fails.
    """
    try:
        match = re.search(pattern, text, flags)
        if match:
            return match.group(group).strip()
    except Exception as e:
        logger.warning(f"Regex extraction error for pattern '{pattern}': {e}")
    return default

def extract_summary_stats(clean_text: str) -> Dict[str, int]:
    """
    Extracts the counts directly from the EXECUTIVE SUMMARY section.
    """
    stats = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
        "Total": 0
    }

    # 1. Extract TOTAL
    total_str = safe_extract(r"TOTAL ALERTS\s*(\d+)", clean_text, "0")
    stats["Total"] = int(total_str)

    # 2. Extract HIGH
    high_str = safe_extract(r"(\d+)\s*HIGH RISK", clean_text, "0")
    stats["High"] = int(high_str)

    # 3. Extract MEDIUM
    med_str = safe_extract(r"(\d+)\s*MEDIUM RISK", clean_text, "0")
    stats["Medium"] = int(med_str)

    # 4. Extract LOW / INFO
    low_info_str = safe_extract(r"(\d+)\s*LOW\s*/\s*INFO", clean_text, "0")
    stats["Low"] = int(low_info_str)
    
    return stats

def parse_api_scan_report(raw_text: str) -> Dict[str, Any]:
    clean_text = clean_raw_text(raw_text)
    
    # --- STEP 1: Extract Stats from Header ---
    header_stats = extract_summary_stats(clean_text)
    
    findings_list = []

    # --- STEP 2: Parse Individual Findings ---
    # Findings usually start with a title followed by risk level and then CONFIDENCE
    confidence_markers = list(re.finditer(r"\nCONFIDENCE\s", clean_text))
    
    for i, marker in enumerate(confidence_markers):
        current_conf_start = marker.start()
        
        if i + 1 < len(confidence_markers):
            next_conf_start = confidence_markers[i+1].start()
            search_limit = next_conf_start
        else:
            search_limit = len(clean_text)

        # Backwards Search for Title
        pre_text_chunk = clean_text[max(0, current_conf_start-600):current_conf_start]
        lines = pre_text_chunk.split('\n')
        
        vuln_name = "Unknown Vulnerability"
        risk_level = "Unknown"
        
        for line in reversed(lines):
            line = line.strip()
            if not line: continue
            
            risk_match = re.search(r"(.*)\s+(HIGH|MEDIUM|LOW|INFO)\s+RISK$", line, re.IGNORECASE)
            
            if risk_match:
                possible_name = risk_match.group(1).strip()
                if len(possible_name) < 150:
                    vuln_name = possible_name
                    risk_level = risk_match.group(2).upper()
                    break
            
            if "REFERENCES" in line or "REMEDIATION SOLUTION" in line:
                break

        # Forwards Search for Body
        body_text = clean_text[marker.end():search_limit]
        
        confidence = safe_extract(r"^\s*([A-Za-z]+)", body_text, "Unknown")
        score = safe_extract(r"PREDICTED SCORE\s*([\d\.]+|N/A|Unprofiled)", body_text, "N/A")
        url = safe_extract(r"TARGET URL\s*(.*?)DESCRIPTION", body_text, "Unknown", flags=re.DOTALL).replace('\n', '').replace(' ', '')
        description = safe_extract(r"DESCRIPTION(.*?)(REMEDIATION SOLUTION|SOLUTION)", body_text, "", flags=re.DOTALL)
        solution = safe_extract(r"(REMEDIATION SOLUTION|SOLUTION)(.*?)REFERENCES", body_text, "", group=2, flags=re.DOTALL)

        refs = []
        ref_content = safe_extract(r"REFERENCES(.*)", body_text, "", flags=re.DOTALL)
        if ref_content:
            lines_ref = ref_content.split('\n')
            for line in lines_ref:
                line = line.strip()
                if not line: continue
                if re.search(r"(HIGH|MEDIUM|LOW|INFO)\s+RISK$", line):
                    break
                if "http" in line or "owasp" in line.lower() or "cwe" in line.lower():
                    refs.append(line)

        findings_list.append({
            "name": vuln_name,
            "risk_level": risk_level,
            "confidence": confidence,
            "predicted_score": score,
            "url": url,
            "description": description,
            "solution": solution,
            "references": refs
        })

    # --- STEP 3: Reconcile Stats ---
    final_stats = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
        "Total": header_stats["Total"] if header_stats["Total"] > 0 else 0
    }

    # Count breakdown from findings
    for finding in findings_list:
        if final_stats["Total"] == 0:
             final_stats["Total"] += 1

        r_level = finding['risk_level'].title()
        if r_level in final_stats:
            final_stats[r_level] += 1

    report = {
        "scan_metadata": {
            "tool": "API Scanner",
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now().isoformat()
        },
        "alert_summary": final_stats,
        "findings": findings_list
    }

    return report

def process_api_scan_report_file(file_path: str) -> Dict[str, Any]:
    """
    Orchestrates reading the PDF, extracting text, and parsing the API Scanner data.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"API scan report not found: {file_path}")
    
    logger.info(f"Processing API scan report: {file_path}")
    try:
        raw_text = extract_text_from_pdf(file_path)
        
        if not raw_text.strip():
            raise ValueError("Extracted text from file is empty.")
            
        report_data = parse_api_scan_report(raw_text)
        
        report_data["file_metadata"] = {
            "filename": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }
        return report_data
        
    except Exception as e:
        logger.error(f"Error processing API scan report {file_path}: {e}")
        raise

if __name__ == "__main__":
    # Test block can be added here if needed for debugging
    pass
