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
    Cleans Semgrep PDF text artifacts.
    """
    text = re.sub(r'\r\n|\r', '\n', text)
    text = re.sub(r'Page \d+ of \d+', '', text)
    # Remove footer
    text = re.sub(r'NETSHIELDAI REPORTING ENGINE.*?CONFIDENTIAL', '\n', text, flags=re.DOTALL)
    return text

def safe_extract(pattern: str, text: str, default: Any = "N/A", group: int = 1, flags: int = 0) -> Any:
    """
    Safely attempts to extract a pattern from text.
    """
    try:
        match = re.search(pattern, text, flags)
        if match:
            return match.group(group).strip()
    except Exception as e:
        logger.warning(f"Semgrep Regex extraction error for pattern '{pattern}': {e}")
    return default

def extract_summary_stats(clean_text: str) -> Dict[str, int]:
    """
    Extracts counts from the Semgrep summary boxes.
    """
    stats = {
        "Total": 0,
        "Error": 0,
        "Warning": 0
    }

    # Extract TOTAL FINDINGS
    total_str = safe_extract(r"TOTAL FINDINGS\s*(\d+)", clean_text, "0")
    stats["Total"] = int(total_str)

    # Extract HIGH RISK (ERRORS)
    error_str = safe_extract(r"HIGH RISK \(ERRORS\)\s*(\d+)", clean_text, "0")
    stats["Error"] = int(error_str)

    # Extract MEDIUM RISK (WARNINGS)
    warning_str = safe_extract(r"MEDIUM RISK \(WARNINGS\)\s*(\d+)", clean_text, "0")
    stats["Warning"] = int(warning_str)
    
    return stats

def parse_semgrep_report(raw_text: str) -> Dict[str, Any]:
    clean_text = clean_raw_text(raw_text)
    
    # --- STEP 1: Summary ---
    summary = extract_summary_stats(clean_text)
    
    findings_list = []

    # --- STEP 2: Findings ---
    finding_markers = list(re.finditer(r"\s+(ERROR|WARNING)\s*\n", clean_text))
    
    for i, marker in enumerate(finding_markers):
        tag = marker.group(1)
        start_search = marker.start()
        
        if i + 1 < len(finding_markers):
            end_search = finding_markers[i+1].start()
        else:
            end_search = len(clean_text)

        # Body text between tags
        body = clean_text[marker.end():end_search]
        
        # Pre-text (to find the rule name)
        pre_text = clean_text[max(0, start_search-200):start_search]
        lines_pre = [l.strip() for l in pre_text.split('\n') if l.strip()]
        rule_name = lines_pre[-1] if lines_pre else "Unknown Rule"

        # Extract File and Line
        file_path = safe_extract(r"FILE\s+(.*?)\s+LINE\s+(\d+)", body, "Unknown", group=1)
        line_num = safe_extract(r"FILE\s+(.*?)\s+LINE\s+(\d+)", body, "N/A", group=2)

        # Extract Description
        description = safe_extract(r"DESCRIPTION:\s*(.*?)(VULNERABLE CODE:|SUGGESTED FIX:|Page \d+|$)", body, "", flags=re.DOTALL)

        # Extract Vulnerable Code
        vulnerable_code = safe_extract(r"VULNERABLE CODE:\s*(.*?)(SUGGESTED FIX:|Page \d+|$)", body, "", flags=re.DOTALL)

        # Extract Suggested Fix
        suggested_fix = safe_extract(r"SUGGESTED FIX:\s*(.*?)(Page \d+|$)", body, "", flags=re.DOTALL)

        findings_list.append({
            "rule": rule_name,
            "severity": tag,
            "file": file_path,
            "line": line_num,
            "description": description,
            "vulnerable_code": vulnerable_code,
            "suggested_fix": suggested_fix
        })

    report = {
        "scan_metadata": {
            "tool": "Semgrep SAST",
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now().isoformat()
        },
        "summary_counts": summary,
        "findings": findings_list
    }

    return report

def process_semgrep_report_file(file_path: str) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Semgrep report not found: {file_path}")
    
    logger.info(f"Processing Semgrep report: {file_path}")
    try:
        raw_text = extract_text_from_pdf(file_path)
        if not raw_text.strip():
            raise ValueError("Extracted text is empty.")
            
        report_data = parse_semgrep_report(raw_text)
        report_data["file_metadata"] = {
            "filename": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path)
        }
        return report_data
    except Exception as e:
        logger.error(f"Error processing Semgrep report: {e}")
        raise

if __name__ == "__main__":
    pass
