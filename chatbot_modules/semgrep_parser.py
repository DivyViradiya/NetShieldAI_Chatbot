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
    # Remove footer/header artifacts
    text = re.sub(r'NetShieldAI Security Report \| Page \d+ of \d+', '', text)
    text = re.sub(r'NETSHIELDAI REPORTING ENGINE // SAST MODULE // GENERATED.*?\n', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'// SAST REPORT.*?SEMGREP', '', text, flags=re.IGNORECASE)
    return text.strip()

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
    total_match = re.search(r"TOTAL FINDINGS\s*(\d+)", clean_text, re.IGNORECASE)
    if total_match:
        stats["Total"] = int(total_match.group(1))

    # Extract HIGH RISK (ERRORS)
    error_match = re.search(r"HIGH RISK \(ERRORS\)\s*(\d+)", clean_text, re.IGNORECASE)
    if error_match:
        stats["Error"] = int(error_match.group(1))

    # Extract MEDIUM RISK (WARNINGS)
    warning_match = re.search(r"MEDIUM RISK \(WARNINGS\)\s*(\d+)", clean_text, re.IGNORECASE)
    if warning_match:
        stats["Warning"] = int(warning_match.group(1))
    
    return stats

def parse_semgrep_report(raw_text: str) -> Dict[str, Any]:
    clean_text = clean_raw_text(raw_text)
    
    # --- STEP 1: Summary ---
    summary = extract_summary_stats(clean_text)
    
    findings_list = []

    # --- STEP 2: Findings ---
    # Pattern: [RuleName][ERROR|WARNING] \n File [Path] Line [Num] \n ANALYSIS MESSAGE...
    finding_pattern = re.compile(
        r'(?P<rule>.*?)(?P<tag>ERROR|WARNING)\s*\n'
        r'File\s+(?P<file>[^\n]+)\s+Line\s+(?P<line>\d+)\s*\n'
        r'ANALYSIS MESSAGE\s*(?P<msg>.*?)\s*'
        r'VULNERABLE CODE SEGMENT\s*(?P<code>.*?)(?=\n.*?(?:ERROR|WARNING)\s*\n|NetShieldAI|$)',
        re.DOTALL | re.IGNORECASE
    )
    
    for match in finding_pattern.finditer(clean_text):
        rule_name = match.group("rule").strip()
        # Clean rule name if it has leftovers from a previous section
        if "DETAILED FINDINGS" in rule_name:
            rule_name = rule_name.split("DETAILED FINDINGS")[-1].strip()
        
        # Remove common artifacts like page numbers if they got caught
        rule_name = re.sub(r'NetShieldAI Security Report \| Page \d+ of \d+', '', rule_name).strip()

        findings_list.append({
            "rule": rule_name,
            "severity": match.group("tag").upper(),
            "file": match.group("file").strip(),
            "line": match.group("line").strip(),
            "description": match.group("msg").strip(),
            "vulnerable_code": match.group("code").strip()
        })

    real_generated_at = safe_extract(r"GENERATED:?\s*([\d-]+ [\d:]+)", clean_text, default=datetime.now().isoformat())

    report = {
        "scan_metadata": {
            "tool": "Semgrep SAST",
            "report_id": str(uuid.uuid4()),
            "generated_at": real_generated_at
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
