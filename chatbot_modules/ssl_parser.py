import os
import re
import json
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Import the PDF extractor for text extraction
try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    from pdf_extractor import extract_text_from_pdf



def parse_sslscan_report(raw_sslscan_text: str) -> Dict[str, Any]:
    """
    Parses raw SSLScan report text into a structured dictionary.

    Args:
        raw_sslscan_text (str): The raw text content of an SSLScan report.

    Returns:
        dict: A structured dictionary containing SSLScan report information.
    """
    # Standardize newlines for easier regex matching
    raw_sslscan_text = re.sub(r'\r\n', '\n', raw_sslscan_text)
    raw_sslscan_text = re.sub(r'\r', '\n', raw_sslscan_text)

    report_data: Dict[str, Any] = {
        "scan_metadata": {
            "tool": "SSLScan Report" # Identify the tool
        },
        "protocols": [],
        "security_features": {},
        "supported_ciphers": [],
        "key_exchange_groups": [],
        "ssl_certificate": {}
    }

    # --- Parse Scan Metadata ---
    # Scan Initiated By
    match = re.search(r'"Scan Initiated By:\s*"\s*,\s*"([^"]+)"', raw_sslscan_text, re.IGNORECASE)
    if match:
        report_data["scan_metadata"]["initiated_by"] = match.group(1).strip()
    
    # Timestamp
    match = re.search(r'"Timestamp:\s*"\s*,\s*"([^"]+)"', raw_sslscan_text, re.IGNORECASE)
    if match:
        report_data["scan_metadata"]["timestamp"] = match.group(1).strip()
    
    # Target Host
    match = re.search(r'"Target Host:\s*"\s*,\s*"([^"]+)"', raw_sslscan_text, re.IGNORECASE)
    if match:
        report_data["scan_metadata"]["target_host"] = match.group(1).strip()
    
    # Version (sslscan tool version)
    match = re.search(r'Version:\s*([^\n]+)', raw_sslscan_text, re.IGNORECASE)
    if match:
        report_data["scan_metadata"]["tool_version"] = match.group(1).strip()

    # OpenSSL Version
    match = re.search(r'OpenSSL\s+([\d\.]+)', raw_sslscan_text, re.IGNORECASE)
    if match:
        report_data["scan_metadata"]["openssl_version"] = match.group(1).strip()
    
    # Connected to IP
    match = re.search(r'Connected to\s+([\d\.]{7,15})', raw_sslscan_text, re.IGNORECASE)
    if match:
        report_data["scan_metadata"]["connected_ip"] = match.group(1).strip()
    
    # Test server details (extract from "Testing SSL server..." line)
    match = re.search(r'Testing SSL server ([^\s]+)\s+on port (\d+)\s+using SNI name ([^\n]+)', raw_sslscan_text)
    if match:
        report_data["scan_metadata"]["tested_server"] = match.group(1).strip()
        report_data["scan_metadata"]["tested_port"] = int(match.group(2))
        report_data["scan_metadata"]["sni_name"] = match.group(3).strip()
    
    # --- Parse SSL/TLS Protocols ---
    protocols_section_match = re.search(r'SSL/TLS Protocols:\s*(.*?)(?=TLS Fallback SCSV:|Supported Server Cipher\(s\):|Server Key Exchange Group\(s\):|SSL Certificate:|$)', raw_sslscan_text, re.DOTALL)
    if protocols_section_match:
        protocols_text = protocols_section_match.group(1)
        for line in protocols_text.splitlines():
            line = line.strip()
            if line and ("enabled" in line.lower() or "disabled" in line.lower()):
                match = re.match(r'(SSLv\d\.\d|TLSv\d\.\d)\s+(enabled|disabled)', line, re.IGNORECASE)
                if match:
                    report_data["protocols"].append({
                        "name": match.group(1),
                        "status": match.group(2).lower()
                    })

    # --- Parse TLS Security Features ---
    # TLS Fallback SCSV
    match = re.search(r'TLS Fallback SCSV:\s*(.+)', raw_sslscan_text, re.IGNORECASE)
    if match:
        report_data["security_features"]["tls_fallback_scsv"] = match.group(1).strip()
    
    # TLS renegotiation
    match = re.search(r'TLS renegotiation:\s*(.+)', raw_sslscan_text, re.IGNORECASE)
    if match:
        report_data["security_features"]["tls_renegotiation"] = match.group(1).strip()
    
    # TLS Compression
    match = re.search(r'TLS Compression:\s*(.+)', raw_sslscan_text, re.IGNORECASE)
    if match:
        # Need to look for "Compression disabled" on the next relevant line
        compression_match = re.search(r'TLS Compression:\s*\n\s*(Compression disabled|Compression enabled)', raw_sslscan_text)
        if compression_match:
            report_data["security_features"]["tls_compression"] = compression_match.group(1).strip()
        else:
            report_data["security_features"]["tls_compression"] = match.group(1).strip() # Fallback to original match

    # Heartbleed
    heartbleed_match = re.search(r'Heartbleed:\s*(.+)', raw_sslscan_text, re.IGNORECASE)
    if heartbleed_match:
        # Heartbleed often has multiple lines like "TLSv1.2 not vulnerable to heartbleed"
        heartbleed_section_text = heartbleed_match.group(0)
        # Find all subsequent lines that look like heartbleed status
        hb_details = re.findall(r'(TLSv\d\.\d\s+not vulnerable to heartbleed|vulnerable to heartbleed)', heartbleed_section_text + raw_sslscan_text.split(heartbleed_match.group(0))[1], re.IGNORECASE)
        report_data["security_features"]["heartbleed"] = [d.strip() for d in hb_details if d.strip()] or [heartbleed_match.group(1).strip()]
        if not report_data["security_features"]["heartbleed"]: # Fallback if specific version not found
            report_data["security_features"]["heartbleed"] = heartbleed_match.group(1).strip()


    # --- Parse Supported Server Ciphers ---
    ciphers_section_match = re.search(r'Supported Server Cipher\(s\):\s*(.*?)(?=Server Key Exchange Group\(s\):|SSL Certificate:|$)', raw_sslscan_text, re.DOTALL)
    if ciphers_section_match:
        ciphers_text = ciphers_section_match.group(1)
        cipher_pattern = re.compile(
            r'(Preferred|Accepted)\s+(TLSv\d\.\d)?\s*(\d+\s+bits)\s+([^\n]+?)(?:Curve\s+([^\s]+)\s+DHE\s+(\d+))?',
            re.IGNORECASE
        )
        for match in cipher_pattern.finditer(ciphers_text):
            cipher_info = {
                "status": match.group(1).strip(),
                "tls_version": match.group(2).strip() if match.group(2) else None,
                "bits": int(match.group(3).split()[0]),
                "name": match.group(4).strip()
            }
            if match.group(5): # Curve
                cipher_info["curve"] = match.group(5).strip()
            if match.group(6): # DHE bits
                cipher_info["dhe_bits"] = int(match.group(6))
            report_data["supported_ciphers"].append(cipher_info)

    # --- Parse Server Key Exchange Group(s) ---
    key_exchange_section_match = re.search(r'Server Key Exchange Group\(s\):\s*(.*?)(?=SSL Certificate:|$)', raw_sslscan_text, re.DOTALL)
    if key_exchange_section_match:
        key_exchange_text = key_exchange_section_match.group(1)
        key_exchange_pattern = re.compile(r'(TLSv\d\.\d)?\s*(\d+\s+bits)?\s*([^\n]+)\s*\(([^)]+)\)', re.IGNORECASE)
        for match in key_exchange_pattern.finditer(key_exchange_text):
            group_info = {
                "tls_version": match.group(1).strip() if match.group(1) else None,
                "bits": int(match.group(2).split()[0]) if match.group(2) else None,
                "name": match.group(3).strip(),
                "details": match.group(4).strip()
            }
            report_data["key_exchange_groups"].append(group_info)

    # --- Parse SSL Certificate ---
    cert_section_match = re.search(r'SSL Certificate:\s*(.*?)(?=Sec\s+SERVICES PVT\.LTD\.|Securing the InSecure|$)', raw_sslscan_text, re.DOTALL)
    if cert_section_match:
        cert_text = cert_section_match.group(1)
        
        # Signature Algorithm
        match = re.search(r'Signature Algorithm:\s*([^\n]+)', cert_text, re.IGNORECASE)
        if match:
            report_data["ssl_certificate"]["signature_algorithm"] = match.group(1).strip()
        
        # RSA Key Strength
        match = re.search(r'RSA Key Strength:\s*(\d+)', cert_text, re.IGNORECASE)
        if match:
            report_data["ssl_certificate"]["rsa_key_strength"] = int(match.group(1))
        
        # Subject
        match = re.search(r'Subject:\s*([^\n]+)', cert_text, re.IGNORECASE)
        if match:
            report_data["ssl_certificate"]["subject"] = match.group(1).strip()
        
        # Altnames
        altnames_match = re.search(r'Altnames:\s*([^\n]+(?:,\s*[^\n]+)*)', cert_text, re.IGNORECASE)
        if altnames_match:
            # Split by comma and strip whitespace for each altname
            report_data["ssl_certificate"]["altnames"] = [
                a.strip() for a in altnames_match.group(1).split(',')
            ]
        
        # Issuer
        match = re.search(r'Issuer:\s*([^\n]+)', cert_text, re.IGNORECASE)
        if match:
            report_data["ssl_certificate"]["issuer"] = match.group(1).strip()
        
        # Not valid before
        match = re.search(r'Not valid before:\s*([^\n]+)', cert_text, re.IGNORECASE)
        if match:
            report_data["ssl_certificate"]["not_valid_before"] = match.group(1).strip()
        
        # Not valid after
        match = re.search(r'Not valid after:\s*([^\n]+)', cert_text, re.IGNORECASE)
        if match:
            report_data["ssl_certificate"]["not_valid_after"] = match.group(1).strip()

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

    print(f"Processing SSLScan report: {file_path}")

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
        print(f"Error processing SSLScan report {file_path}: {str(e)}")
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
