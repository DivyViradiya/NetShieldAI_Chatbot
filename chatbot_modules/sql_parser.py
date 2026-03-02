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
    
    # Target Host - Handles multiline target host
    target_match = re.search(r'TARGET HOST\s*\n(.*?)\n(.*?)SCAN TIMESTAMP', clean_text, re.DOTALL | re.IGNORECASE)
    if target_match:
        report_data["metadata"]["target_url"] = target_match.group(1).strip() + target_match.group(2).strip()

    # Scan Timestamp
    date_match = re.search(r'SCAN TIMESTAMP\s*\n?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', clean_text)
    if date_match:
        report_data["metadata"]["scan_date"] = date_match.group(1)

    # Database Status (AUDIT STATUS)
    status_match = re.search(r'DATA EXFILTRATION[^\n]*\n?([A-Z]+)\s*\n?AUDIT STATUS', clean_text)
    if status_match:
        report_data["metadata"]["database_status"] = status_match.group(1).strip()
    
    # Data Extraction Status
    extraction_match = re.search(r'UNIQUE VECTORS[^\n]*\n?(No|Yes)(?=\n?DATA EXFILTRATION)', clean_text, re.IGNORECASE)
    if not extraction_match:
        extraction_match = re.search(r'DATA EXFILTRATION(No|Yes)', clean_text, re.IGNORECASE)
    if extraction_match:
        report_data["metadata"]["data_extraction"] = extraction_match.group(1).strip()

    # --- 3. Extract Counts ---
    
    # Vulnerabilities Found (TOTAL FINDINGS)
    vuln_count = re.search(r'TOTAL FINDINGS(\d+)', clean_text)
    if vuln_count:
        report_data["summary_counts"]["vulnerabilities_found"] = int(vuln_count.group(1))

    # Injection Types (UNIQUE VECTORS)
    inj_count = re.search(r'UNIQUE VECTORS(\d+|\w+)?', clean_text)
    if inj_count and inj_count.group(1) and inj_count.group(1).isdigit():
        report_data["summary_counts"]["injection_types_count"] = int(inj_count.group(1))

    # --- 4. Database Fingerprinting ---
    
    # Detected DBMS
    dbms_match = re.search(r'DBMS\s+(.*)', clean_text)
    if dbms_match:
        report_data["database_fingerprint"]["detected_dbms"] = dbms_match.group(1).strip()

    # Database Version 
    ver_match = re.search(r'Version\s+(.*)', clean_text)
    if ver_match:
        report_data["database_fingerprint"]["version"] = ver_match.group(1).strip()

    # Current User
    user_match = re.search(r'Current User\s+(.*)', clean_text)
    if user_match:
        report_data["database_fingerprint"]["current_user"] = user_match.group(1).strip()

    # Current Database
    db_match = re.search(r'Database\s+(.*)', clean_text)
    if db_match:
        report_data["database_fingerprint"]["current_database"] = db_match.group(1).replace('🛡️', '').strip()

    # --- 5. Extract Vulnerabilities ---
    
    # Split "Header" from "Body" to clean up the first title
    parts = clean_text.split("VULNERABILITY ANALYSIS")
    body_text = parts[1] if len(parts) > 1 else clean_text

    vuln_pattern = re.compile(
        r'(?P<title>.+?)(?P<risk>HIGH RISK|MEDIUM RISK|LOW RISK|CRITICAL RISK)\s*'
        r'ATTACK VECTOR TYPE\s*'
        r'(?P<type>.+?)AFFECTED PARAMETER\s*'
        r'(?P<param>.+?)\s*'
        r'INJECTED PAYLOAD\s*'
        r'(?P<payload>.+?)(?=(?:[A-Z].+?(?:HIGH RISK|MEDIUM RISK|LOW RISK|CRITICAL RISK))|$)',
        re.DOTALL
    )

    for match in vuln_pattern.finditer(body_text):
        # Clean title: remove newlines and extra spaces
        raw_title = match.group("title").strip()
        clean_title = re.sub(r'\s+', ' ', raw_title)
        
        # Clean payload/remediation
        clean_payload = re.sub(r'\s+', ' ', match.group("payload").strip())
        
        # New reports don't have remediation section, use default
        clean_remediation = "Apply parameterized queries (Prepared Statements) to mitigate SQL injection."

        risk = match.group("risk").replace(" RISK", "").strip()

        item = {
            "title": clean_title,
            "risk_level": risk,
            "injection_type": match.group("type").strip(),
            "payload": clean_payload,
            "remediation": clean_remediation
        }
        report_data["vulnerabilities"].append(item)

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