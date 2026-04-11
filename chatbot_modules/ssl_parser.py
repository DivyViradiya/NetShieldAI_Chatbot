import os
import re
import json
import uuid
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Initialize module logger
logger = logging.getLogger(__name__)

# Import the PDF extractor for text extraction
try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    from pdf_extractor import extract_text_from_pdf



def parse_sslscan_report(raw_text: str) -> Dict[str, Any]:
    """
    Parses the "SSL/TLS Assessment" style report (NetShieldAI) where ciphers 
    are listed in detailed tables under protocol headers.
    """
    # --- 1. Clean and Standardize Text ---
    # Remove Page artifacts
    clean_text = re.sub(r'Page \d+ of \d+', '', raw_text)
    # Normalize line endings
    clean_text = re.sub(r'\r\n|\r', '\n', clean_text).strip()
    
    report_data = {
        "metadata": {},
        "server_configuration": {},
        "vulnerabilities": [],
        "protocols": {},  
        "certificate_chain": {}
    }

    # --- 2. Extract Header/Metadata ---
    # Target
    target_match = re.search(r'TARGET:\s*([^\n]+)', clean_text)
    if target_match:
        report_data["metadata"]["target"] = target_match.group(1).strip()

    # Scan Date
    date_match = re.search(r'SCAN DATE\s*(\d{4}-\d{2}-\d{2})', clean_text)
    if date_match:
        report_data["metadata"]["scan_date"] = date_match.group(1)
        
    # Grade [FIXED]
    # Added lookahead (?=) to stop before "SCAN DATE" or newline
    grade_match = re.search(r'OVERALL GRADE\s+(.*?)(?=\s*SCAN DATE|\n)', clean_text)
    if grade_match:
        report_data["metadata"]["grade"] = grade_match.group(1).strip()

    # --- 3. Extract Server Configuration [FIXED] ---
    # Looks for specific known keys and stops capturing when it hits another key
    
    config_keys = ["TLS Compression", "Secure Renegotiation", "OCSP Stapling", "Fallback SCSV"]

    def extract_config(target_key, text):
        # Build regex: Target Key -> capture -> Stop at (Next Key OR Newline)
        other_keys = "|".join([k for k in config_keys if k != target_key])
        pattern = rf'{target_key}\s+(.*?)(?=\s+(?:{other_keys})|\n|$)'
        
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    report_data["server_configuration"] = {
        "tls_compression": extract_config("TLS Compression", clean_text),
        "secure_renegotiation": extract_config("Secure Renegotiation", clean_text),
        "ocsp_stapling": extract_config("OCSP Stapling", clean_text),
        "fallback_scsv": extract_config("Fallback SCSV", clean_text)
    }

    # --- 4. Extract Vulnerabilities ---
    # Pattern: [Name] [Severity] \n Description: [Text] \n TCTR THREAT MAGNITUDE...
    vuln_pattern = re.compile(
        r'(?P<name>[^\n]+?)\s+(?P<sev>MEDIUM|HIGH|LOW|CRITICAL|INFO)\s+SEVERITY\s*'
        r'(?P<body>(?:(?!\n[^\n]+\s+(?:MEDIUM|HIGH|LOW|CRITICAL|INFO)\s+SEVERITY|\nSERVER CONFIGURATION|\Z).)+)',
        re.IGNORECASE | re.DOTALL
    )
    
    for v in vuln_pattern.finditer(clean_text):
        if "VULNERABILITY FINDINGS" in v.group('name'):
            continue
            
        body = v.group('body')
        
        desc_match = re.search(r'Description:\s*(.*?)(?=\s*TCTR THREAT MAGNITUDE|$)', body, re.IGNORECASE | re.DOTALL)
        desc = desc_match.group(1).strip() if desc_match else ''
        
        tctr_mag_match = re.search(r'TCTR THREAT MAGNITUDE\s*([\d\.]+)%', body, re.IGNORECASE)
        tctr = float(tctr_mag_match.group(1)) if tctr_mag_match else None
        
        intel_match = re.search(r'Intelligence Breakdown:\s*(.*?)(?:\[|\n|$)', body, re.IGNORECASE)
        intel = intel_match.group(1).strip() if intel_match else None

        report_data["vulnerabilities"].append({
            "name": v.group('name').strip(),
            "severity": v.group('sev').strip(),
            "description": desc,
            "tctr_magnitude_percent": tctr,
            "intelligence_breakdown": intel
        })

    # --- 5. Extract Protocols and Ciphers (State Machine Approach) ---
    lines = clean_text.split('\n')
    current_protocol = None
    
    # Regex to identify a Protocol Header line (e.g., "TLSv1.3 2 CIPHERS")
    proto_header_regex = re.compile(r'^(TLSv\d\.\d+(?:\s+\(Deprecated\))?)\s+\d+\s+CIPHERS', re.IGNORECASE)
    
    # Regex to identify a Cipher Data line (e.g., "AES256-SHA 256 bits ACCEPTED")
    cipher_line_regex = re.compile(r'^([A-Z0-9_-]+)\s+(\d+)\s+bits\s+(ACCEPTED|REJECTED)', re.IGNORECASE)

    for line in lines:
        line = line.strip()
        if not line: 
            continue

        p_match = proto_header_regex.match(line)
        if p_match:
            current_protocol = p_match.group(1)
            report_data["protocols"][current_protocol] = []
            continue

        c_match = cipher_line_regex.match(line)
        if c_match and current_protocol:
            report_data["protocols"][current_protocol].append({
                "cipher": c_match.group(1),
                "bits": int(c_match.group(2)),
                "status": c_match.group(3)
            })

    # --- 6. Extract Certificate Details [FIXED] ---
    # Expiry
    cert_expiry = re.search(r'Leaf Certificate Expires:\s*(\d{4}-\d{2}-\d{2})', clean_text)
    if cert_expiry:
        report_data["certificate_chain"]["leaf_expiry"] = cert_expiry.group(1)

    # Subject / Common Name
    subject_match = re.search(r'Subject / Common Name\s+(.*?)(?=Issuer)', clean_text, re.IGNORECASE)
    if subject_match:
        report_data["certificate_chain"]["subject"] = subject_match.group(1).strip()

    # Issuer [FIXED]
    # Changed \s+ to \s* to handle merged text "comIssuer"
    issuer_match = re.search(r'Issuer\s*(.*?)(?=\s*Signature Algorithm|\n)', clean_text, re.IGNORECASE)
    if issuer_match:
        val = issuer_match.group(1).strip()
        if val:
            report_data["certificate_chain"]["issuer"] = val
        
    # Signature Algorithm
    sig_match = re.search(r'Signature Algorithm\s+(.*?)(?=Key Type)', clean_text, re.IGNORECASE)
    if sig_match:
        report_data["certificate_chain"]["signature_algorithm"] = sig_match.group(1).strip()

    # Key Type [ADDED]
    key_match = re.search(r'Key Type\s*(.*?)(?=\s+NETSHIELDAI|\n|$)', clean_text, re.IGNORECASE)
    if key_match:
        report_data["certificate_chain"]["key_type"] = key_match.group(1).strip()

    return report_data


def process_sslscan_report_file(file_path: str) -> Dict[str, Any]:
    """
    Processes an SSLScan report PDF file and returns structured data.

    Args:
        pdf_path: Path to the SSLScan report PDF file.

    Returns:
        dict: Structured SSLScan report data.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"SSLScan report not found: {file_path}")

    logger.info(f"Processing SSLScan report: {file_path}")

    try:
        raw_text = extract_text_from_pdf(file_path)
        if not raw_text.strip():
            raise ValueError("Extracted text is empty or contains only whitespace.")

        # Parse the SSLScan report
        report_data = parse_sslscan_report(raw_text)

        # Add file metadata
        report_data["file_metadata"] = {
            "filename": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }

        return report_data

    except Exception as e:
        logger.error(f"Error processing SSLScan report {file_path}: {str(e)}")
        raise

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python ssl_parser.py <path_to_sslscan_report.pdf>")
        sys.exit(1)
        
    file_path = sys.argv[1]
    
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    try:
        print(f"Processing SSLScan report: {file_path}")
        parsed_data = process_sslscan_report_file(file_path)
        
        if parsed_data:
            print("\nParsed SSLScan Report Data:")
            print(json.dumps(parsed_data, indent=2))
            print("\nReport processed successfully!")
        else:
            print("Error: Failed to parse the SSLScan report.")
            
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
