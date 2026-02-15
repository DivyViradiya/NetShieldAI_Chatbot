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
    # Normalize line endings to simple \n
    clean_text = re.sub(r'\r\n|\r', '\n', clean_text).strip()

    report_data = {
        "metadata": {},
        "summary_counts": {},
        "database_fingerprint": {},
        "vulnerabilities": []
    }

    # --- 2. Extract Metadata (Header Section) ---
    
    # Target URL - Stops before "SCAN DATE" to handle multiline URLs
    target_match = re.search(r'TARGET URL\s*\n?(.*?)(?=\s*SCAN DATE)', clean_text, re.DOTALL)
    if target_match:
        report_data["metadata"]["target_url"] = target_match.group(1).replace('\n', '').strip()

    # Scan Date
    date_match = re.search(r'SCAN DATE\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', clean_text)
    if date_match:
        report_data["metadata"]["scan_date"] = date_match.group(1)

    # Database Status (e.g., Exposed)
    status_match = re.search(r'DATABASE STATUS\s*([A-Za-z]+)', clean_text, re.IGNORECASE)
    if status_match:
        report_data["metadata"]["database_status"] = status_match.group(1).strip()

    # Data Extraction Status (e.g., No)
    extraction_match = re.search(r'DATA EXTRACTION\s*([A-Za-z]+)', clean_text, re.IGNORECASE)
    if extraction_match:
        report_data["metadata"]["data_extraction"] = extraction_match.group(1).strip()

    # --- 3. Extract Counts ---
    
    # Vulnerabilities Found
    vuln_count = re.search(r'VULNERABILITIES\s*FOUND\s*(\d+)', clean_text)
    if vuln_count:
        report_data["summary_counts"]["vulnerabilities_found"] = int(vuln_count.group(1))

    # Injection Types (looks for number AFTER the label)
    inj_count = re.search(r'INJECTION TYPES\s*(\d+)', clean_text)
    if inj_count:
        report_data["summary_counts"]["injection_types_count"] = int(inj_count.group(1))

    # --- 4. Database Fingerprinting ---
    
    # Detected DBMS
    dbms_match = re.search(r'DETECTED DBMS\s*([^\n]+)', clean_text)
    if dbms_match:
        report_data["database_fingerprint"]["detected_dbms"] = dbms_match.group(1).strip()

    # Database Version 
    db_ver_match = re.search(r'DATABASE\s+VERSION\s*([^\n]+)', clean_text)
    if db_ver_match:
        report_data["database_fingerprint"]["version"] = db_ver_match.group(1).strip()

    # Current User
    user_match = re.search(r'CURRENT USER\s*([^\n]+)(?=\s+CURRENT DATABASE)', clean_text)
    if user_match:
        report_data["database_fingerprint"]["current_user"] = user_match.group(1).strip()

    # Current Database
    curr_db_match = re.search(r'CURRENT DATABASE\s*([^\n]+)', clean_text)
    if curr_db_match:
        report_data["database_fingerprint"]["current_database"] = curr_db_match.group(1).strip()

    # --- 5. Extract Vulnerabilities (Universal Fix) ---
    
    # Split "Header" from "Body" to clean up the first title
    parts = clean_text.split("VULNERABILITY ANALYSIS")
    body_text = parts[1] if len(parts) > 1 else clean_text

    # UNIVERSAL REGEX EXPLANATION:
    # 1. (?P<title>[A-Z].*?)      -> Starts with ANY Capital letter (MySQL, Oracle, PostgreSQL)
    # 2. (?P<sep>[\s\)])          -> Separator (space or closing paren)
    # 3. (?P<risk>HIGH|MEDIUM...) -> Risk Level
    # 4. (?=...[A-Z][a-z]+...)    -> Lookahead stops at next Title (Word starting with Cap)
    
    vuln_pattern = re.compile(
        r'(?P<title>[A-Z].*?)'                          # Title (DBMS Agnostic)
        r'(?P<sep>[\s\)])'                              # Separator
        r'(?P<risk>HIGH|MEDIUM|LOW|CRITICAL)\s*'        # Risk Level
        r'RISK\s*'                                      # Literal "RISK"
        r'INJECTION TYPE\s+(?P<type>.*?)\s+'            # Injection Type
        r'INJECTION PAYLOAD\s+(?P<payload>.*?)\s+'      # Payload
        r'REMEDIATION\s+(?P<remediation>.*?)'           # Remediation
        # Stop at Footer, NetShieldAI, or Next Vulnerability Title (Capitalized word)
        r'(?=\s+NETSHIELDAI|\s+[A-Z][a-z]+|\s+Page|$)',       
        re.DOTALL | re.IGNORECASE
    )

    for match in vuln_pattern.finditer(body_text):
        # Clean title: remove newlines and extra spaces
        raw_title = match.group("title").strip()
        clean_title = re.sub(r'\s+', ' ', raw_title)
        
        # Clean payload/remediation
        clean_payload = re.sub(r'\s+', ' ', match.group("payload").strip())
        clean_remediation = re.sub(r'\s+', ' ', match.group("remediation").strip())

        item = {
            "title": clean_title,
            "risk_level": match.group("risk").strip(),
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