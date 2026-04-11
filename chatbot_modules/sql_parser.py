import os
import re
import json
import logging
from typing import Dict, Any
from datetime import datetime

# Initialize module logger
logger = logging.getLogger(__name__)

# Import the PDF extractor (Keep your existing import structure)
try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    try:
        from pdf_extractor import extract_text_from_pdf
    except ImportError:
        def extract_text_from_pdf(path):
            raise ImportError("pdf_extractor module not found.")

def parse_sql_report(raw_text: str) -> Dict[str, Any]:
    """
    Parses the "SQL Injection Security Audit" report.
    Updated to be UNIVERSAL (DBMS-agnostic) for tools like sqlmap.
    """
    # --- 1. Clean Text ---
    # Remove "Page X of Y" artifacts
    clean_text = re.sub(r'Page \d+ of \d+', '', raw_text)
    # Remove generated on timestamp
    clean_text = re.sub(r'GENERATED ON \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} // CONFIDENTIAL SECURITY DOCUMENT', '', clean_text)
    # Normalize line endings to simple \n
    clean_text = re.sub(r'\r\n|\r', '\n', clean_text).strip()

    report_data = {
        "metadata": {},
        "summary_counts": {},
        "database_fingerprint": {},
        "vulnerabilities": []
    }

    # --- 2. Extract Metadata (Header Section) ---
    
    # Target Host
    # Non-greedy capture until SCAN DATE
    target_match = re.search(r'TARGET HOST\s+(.*?)(?=\s*SCAN DATE)', clean_text, re.DOTALL | re.IGNORECASE)
    if target_match:
        report_data["metadata"]["target_url"] = re.sub(r'\s+', '', target_match.group(1).strip())

    # Scan Timestamp (SCAN DATE)
    date_match = re.search(r'SCAN DATE\s*(.*?)DATABASE', clean_text, re.DOTALL | re.IGNORECASE)
    if date_match:
        report_data["metadata"]["scan_date"] = date_match.group(1).replace('\n', ' ').strip()

    # ML Threat Index
    ml_match = re.search(r'ML THREAT INDEX\s*([\d\.]+)', clean_text, re.IGNORECASE)
    if ml_match:
        report_data["metadata"]["ml_threat_index"] = float(ml_match.group(1))

    # Audit Status
    status_match = re.search(r'AUDIT STATUS\s*([A-Z]+)', clean_text, re.IGNORECASE)
    if status_match:
        report_data["metadata"]["audit_status"] = status_match.group(1).strip()
    
    # Data Exfiltration Status
    extraction_match = re.search(r'DATA EXFILTRATION\s*([A-Z]+)', clean_text, re.IGNORECASE)
    if extraction_match:
        report_data["metadata"]["data_exfiltration"] = extraction_match.group(1).strip()

    # counts
    total_finds = re.search(r'TOTAL FINDINGS\s*(\d+)', clean_text, re.IGNORECASE)
    if total_finds:
        report_data["summary_counts"]["vulnerabilities_found"] = int(total_finds.group(1))
        
    unique_vectors = re.search(r'UNIQUE VECTORS\s*(\d+)', clean_text, re.IGNORECASE)
    if unique_vectors:
        report_data["summary_counts"]["injection_types_count"] = int(unique_vectors.group(1))

    # --- 3. Database Fingerprinting ---
    def extract_fp(key):
        # Look for the key and capture everything until the next line/key start
        pattern = rf'{key}\s+(.*?)(?:\n|$)'
        match = re.search(pattern, clean_text, re.IGNORECASE)
        return match.group(1).strip() if match else "Unknown"

    report_data["database_fingerprint"] = {
        "detected_dbms": extract_fp("DBMS"),
        "version": extract_fp("Version"),
        "current_user": extract_fp("Instance User"),
        "current_database": extract_fp("Active Database")
    }

    # --- 4. Extract Vulnerabilities ---
    # Pattern: [Name] [Risk] \n ATTACK TYPE ...
    vuln_pattern = re.compile(
        r'(?P<title>[^\n]+?)\s+(?P<risk>CRITICAL|HIGH|MEDIUM|LOW)\s+RISK\s*'
        r'ATTACK TYPE\s*(?P<type>[^\n]+)\s*'
        r'AFFECTED PARAMETER\s*(?P<param>[^\n]+)\s*'
        r'SUCCESSFUL PAYLOAD\s*(?P<payload>.*?)(?=\n[^\n]+\s+(?:CRITICAL|HIGH|MEDIUM|LOW)\s+RISK|NetShieldAI|$)',
        re.DOTALL | re.IGNORECASE
    )

    for match in vuln_pattern.finditer(clean_text):
        if "VULNERABILITY ANALYSIS" in match.group('title'):
            continue
            
        report_data["vulnerabilities"].append({
            "title": match.group("title").strip(),
            "risk_level": match.group("risk").upper(),
            "injection_type": match.group("type").strip(),
            "parameter": match.group("param").strip(),
            "payload": match.group("payload").strip(),
            "remediation": "Apply parameterized queries (Prepared Statements) to mitigate SQL injection."
        })

    return report_data


def process_sql_report_file(file_path: str) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"SQL Report not found: {file_path}")

    logger.info(f"Processing SQL report: {file_path}")

    try:
        raw_text = extract_text_from_pdf(file_path)
        if not raw_text.strip():
            raise ValueError("Extracted text is empty.")

        report_data = parse_sql_report(raw_text)

        report_data["file_metadata"] = {
            "filename": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }

        return report_data

    except Exception as e:
        logger.error(f"Error processing SQL report {file_path}: {str(e)}")
        raise

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        fpath = sys.argv[1]
        try:
            # Debugging mode for text files
            if fpath.endswith(".txt"):
                with open(fpath, "r", encoding="utf-8") as f:
                    txt = f.read()
                print(json.dumps(parse_sql_report(txt), indent=2))
            else:
                # Standard mode for PDF
                print(json.dumps(process_sql_report_file(fpath), indent=2))
        except Exception as e:
            print(f"Failed: {e}")