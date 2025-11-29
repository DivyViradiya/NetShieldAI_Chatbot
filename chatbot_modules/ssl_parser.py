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
    Parses raw SSLScan report text (specifically the NetShieldAI format) 
    into a structured dictionary using updated regular expressions.

    Args:
        raw_sslscan_text (str): The raw text content of an SSLScan report.

    Returns:
        dict: A structured dictionary containing SSLScan report information.
    """
    # 1. Standardize and clean up the input text
    # Replace multiple spaces/tabs with a single space to simplify matching
    raw_sslscan_text = re.sub(r'[ \t]+', ' ', raw_sslscan_text)
    # Standardize newlines
    raw_sslscan_text = re.sub(r'\r\n|\r', '\n', raw_sslscan_text)
    # Remove "Page X of Y" clutter
    raw_sslscan_text = re.sub(r'Page \d+ of \d+\n', '', raw_sslscan_text)
    
    report_data: Dict[str, Any] = {
        "scan_metadata": {
            "tool": "SSLScan Report (NetShieldAI Extracted)"
        },
        "vulnerabilities": [],
        "protocols": [],
        "server_configuration": {},
        "ssl_certificate": {},
        "supported_ciphers": [],
    }

    # --- 1. Parse Scan Metadata (Target, Port, Date) ---
    # TARGET
    match = re.search(r'TARGET:\s*([^\s]+)', raw_sslscan_text)
    if match:
        target_str = match.group(1).strip()
        # FIX: Clean up the target string for the PDF artifact's TARGET: google.comPORT: format
        target_str = re.sub(r'PORT:$', '', target_str)
        report_data["scan_metadata"]["target_host"] = target_str.strip()
    
    # PORT
    match = re.search(r'PORT:\s*(\d+)', raw_sslscan_text)
    if match:
        report_data["scan_metadata"]["port"] = int(match.group(1))
    
    # SCAN DATE
    match = re.search(r'SCAN DATE:\s*([^\n]+)', raw_sslscan_text)
    if match:
        report_data["scan_metadata"]["scan_date"] = match.group(1).strip()

    # --- 2. Parse Detected Vulnerabilities ---
    # Finds lines starting with Severity followed by a description, ignoring the header line
    vulnerabilities_text_block = re.search(
        r'Detected Vulnerabilities\s*Severity\s*Vulnerability Description\s*(.*?)(?=Supported Protocols)', 
        raw_sslscan_text, re.DOTALL)
    
    if vulnerabilities_text_block:
        # Regex to capture Severity and the rest of the line as Description
        # Note: We must handle the multi-line nature if it exists, but here it's simple line extraction.
        # Pattern: (Severity) (Description...)
        vuln_pattern = re.compile(r'(Medium|High|Low)\s+([^\n]+)', re.IGNORECASE)
        for line in vulnerabilities_text_block.group(1).splitlines():
            line = line.strip()
            if not line:
                continue
            match = vuln_pattern.match(line)
            if match:
                report_data["vulnerabilities"].append({
                    "severity": match.group(1).strip(),
                    "description": match.group(2).strip()
                })

    # --- 3. Parse Supported Protocols ---
    # Finds the protocols table block
    protocols_text_block = re.search(
        r'Supported Protocols\s*Protocol\s*Status\s*(.*?)(?=Server Configuration)', 
        raw_sslscan_text, re.DOTALL)
    
    if protocols_text_block:
        # Pattern: (Protocol Name/Version) (Status)
        protocol_pattern = re.compile(r'((?:TLSv)?\d\.\d|\d)\s+(Enabled|Disabled)', re.IGNORECASE)
        for line in protocols_text_block.group(1).splitlines():
            line = line.strip()
            if not line:
                continue
            match = protocol_pattern.match(line)
            if match:
                report_data["protocols"].append({
                    "name": match.group(1).strip(),
                    "status": match.group(2).strip().lower()
                })

    # --- 4. Parse Server Configuration (Security Features) ---
    # These are extracted as simple key: value pairs
    config_mappings = {
        "heartbleed": r'Heartbleed Vulnerability:\s*([^\n]+)',
        "tls_compression_crime": r'TLS Compression \(CRIME\):\s*([^\n]+)',
        "secure_renegotiation": r'Secure Renegotiation:\s*([^\n]+)',
        "fallback_scsv": r'Fallback SCSV:\s*([^\n]+)',
    }
    
    for key, pattern in config_mappings.items():
        match = re.search(pattern, raw_sslscan_text)
        if match:
            report_data["server_configuration"][key] = match.group(1).strip()
            
    # --- 5. Parse Certificate Chain (Leaf Certificate) ---
    cert_mappings = {
        "common_name": r'Common Name \(CN\):\s*([^\n]+)',
        "issuer": r'Issuer:\s*([^\n]+)',
        "signature_algorithm": r'Signature Algorithm:\s*([^\n]+)',
        "key_details": r'Key:\s*([^\n]+)',
        "validity": r'Validity:\s*([^\n]+)', # Will need further splitting for 'before' and 'after'
    }

    for key, pattern in cert_mappings.items():
        match = re.search(pattern, raw_sslscan_text)
        if match:
            # Special handling for validity to split into before/after
            if key == "validity":
                # Example: Oct 27 08:33:43 2025 GMT to Jan 19 08:33:42 2026 GMT
                validity_parts = match.group(1).split(' to ')
                if len(validity_parts) == 2:
                    report_data["ssl_certificate"]["not_valid_before"] = validity_parts[0].strip()
                    report_data["ssl_certificate"]["not_valid_after"] = validity_parts[1].strip()
                else:
                    report_data["ssl_certificate"][key] = match.group(1).strip()
            else:
                report_data["ssl_certificate"][key] = match.group(1).strip()
                
    # --- 6. Parse Supported Ciphers Table ---
    # Finds the ciphers table block starting after "Supported Ciphers" header
    ciphers_text_block = re.search(
        r'Supported Ciphers\s*Protocol\s*Cipher Name\s*Bits\s*Status\s*(.*?)Generated by NetShieldAI Reporting Engine', 
        raw_sslscan_text, re.DOTALL)
    
    if ciphers_text_block:
        # Pattern: (TLSvX.X) (Cipher Name - non-whitespace) (Bits - number) (Status - word)
        # Note: DES-CBC3-SHA has a space in the name, so we use a complex pattern to handle it robustly
        cipher_pattern = re.compile(
            r'(TLSv\d\.\d)\s+([^\s]+(?:-[A-Z0-9]+)?)\s+(\d+)\s+(accepted|disabled|weak)', 
            re.IGNORECASE)
        
        # A simpler pattern that relies heavily on whitespace (using \s+)
        simpler_cipher_pattern = re.compile(
            r'(TLSv\d\.\d)\s+([A-Z0-9_-]+)\s+(\d+)\s+(accepted|disabled|weak)', re.IGNORECASE)
        
        # Iterate over all non-empty lines in the block
        for line in ciphers_text_block.group(1).splitlines():
            line = line.strip()
            if not line:
                continue
            
            # The structure for DES-CBC3-SHA in the report is "TLSv1.2 DES-CBC3-SHA 112 accepted", 
            # where the Cipher Name contains spaces in the raw text, but is often seen compressed.
            # Let's clean the line first by replacing excessive spaces with a single space.
            clean_line = re.sub(r'\s+', ' ', line.strip())

            # Attempt a split-based approach for reliability since the columns are fixed
            parts = clean_line.split()
            
            # Expected format: [Protocol] [Cipher Name (1 or more words)] [Bits] [Status]
            if len(parts) >= 4:
                # The bits and status are always the last two items
                status = parts[-1]
                bits_str = parts[-2]
                
                # FIX: Use try-except to safely convert 'bits' to an integer,
                # skipping lines (like the header "Bits") that fail conversion.
                try:
                    bits = int(bits_str)
                except ValueError:
                    continue
                
                protocol = parts[0]
                # The cipher name is everything in between
                cipher_name = " ".join(parts[1:-2]) 
                
                report_data["supported_ciphers"].append({
                    "protocol": protocol.strip(),
                    "name": cipher_name.strip(),
                    "bits": bits,
                    "status": status.strip().lower()
                })
            

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
