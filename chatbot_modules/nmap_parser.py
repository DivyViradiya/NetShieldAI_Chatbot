import os
import re
import json
import uuid
import logging
from typing import Dict, Any, List
from datetime import datetime

# Initialize module logger
logger = logging.getLogger(__name__)

try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    try:
        from pdf_extractor import extract_text_from_pdf
    except ImportError:
        def extract_text_from_pdf(pdf_path: str) -> str:
            raise NotImplementedError("pdf_extractor.py not found.")

def parse_nmap_report(raw_nmap_text: str) -> Dict[str, Any]:
    """
    Parses 'NetShieldAI' formatted Nmap reports with robust footer handling.
    """
    # 1. Basic Cleanup
    raw_nmap_text = re.sub(r'\r\n|\r', '\n', raw_nmap_text)
    
    # 2. Aggressive Header/Footer Cleanup
    # Remove "Page X of Y"
    raw_nmap_text = re.sub(r'Page \d+ of \d+', '', raw_nmap_text)
    
    # Remove the specific engine footer signature, but PRESERVE what comes after it
    # We replace the footer with a newline to ensure the next Port starts on a fresh line.
    raw_nmap_text = re.sub(
        r'NETSHIELDAI REPORTING ENGINE // NETWORK ASSESSMENT // \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', 
        '\n', 
        raw_nmap_text
    )

    # 3. Force Newlines before "Port X (TCP)" to guarantee separation
    # This fixes cases where "Port 1900" is stuck to the end of a previous line.
    raw_nmap_text = re.sub(r'(Port\s+\d+\s+\(\w+\)\s+OPERATIONAL)', r'\n\1', raw_nmap_text)

    report: Dict[str, Any] = {
        "scan_metadata": {
            "tool": "NetShieldAI (Nmap)",
            "report_id": str(uuid.uuid4()),
            "target_ip": None,
            "scan_date": None,
            "host_status": None,
            "scan_arguments": None,
            "security_posture": None
        },
        "summary": {
            "ports_found": 0,
            "scan_duration_sec": 0.0,
            "threats_detected": 0
        },
        "open_ports": []
    }

    # --- METADATA SECTION ---
    
    # Target Node
    ip_match = re.search(r"(?:TARGET NODE|TARGET IP)\s*([\d\.]+)", raw_nmap_text)
    if ip_match:
        report["scan_metadata"]["target_ip"] = ip_match.group(1).strip()

    # Timestamp
    date_match = re.search(r"(?:TIMESTAMP|SCAN DATE)\s*(\d{4}-\d{2}-\d{2}[\s\n]+\d{2}:\d{2}:\d{2})", raw_nmap_text)
    if date_match:
        report["scan_metadata"]["scan_date"] = date_match.group(1).replace('\n', ' ')

    # Host Status
    status_match = re.search(r"HOST STATUS\s*(UP|DOWN)", raw_nmap_text, re.IGNORECASE)
    if status_match:
        report["scan_metadata"]["host_status"] = status_match.group(1).upper()

    # CLI Arguments
    args_match = re.search(r"CLI Arguments\s*(.*?)(?=\n[\d\.]+|Security Posture)", raw_nmap_text, re.DOTALL)
    if not args_match:
        # Fallback for new format
        args_match = re.search(r"as:\s*(nmap.*?)(?=\nHost:)", raw_nmap_text, re.DOTALL)
    if args_match:
        clean_args = re.sub(r'\s+', ' ', args_match.group(1)).strip()
        report["scan_metadata"]["scan_arguments"] = clean_args

    # Security Posture
    posture_match = re.search(r"(?:Security Posture|THREAT STATUS)\s*(.*?)\n", raw_nmap_text)
    if posture_match:
        report["scan_metadata"]["security_posture"] = posture_match.group(1).strip()

    # Numeric Metrics
    open_entry_match = re.search(r"(?:OPEN ENTRY POINTS|TOTAL SERVICES)\s*(\d+)", raw_nmap_text)
    if open_entry_match:
        report["summary"]["ports_found"] = int(open_entry_match.group(1))

    duration_match = re.search(r"(?:SCAN DURATION|ACTIVE SCANS)\s*([\d\.]+)", raw_nmap_text)
    if duration_match:
        report["summary"]["scan_duration_sec"] = float(duration_match.group(1))



    # --- PORT PARSING SECTION (Revised Strategy) ---
    
    # Strategy: Split the entire text by the "Port X..." header.
    # This creates a list where item [0] is pre-port text, and subsequent items are the ports.
    # We include the capturing group (the header itself) in the split so we don't lose the Port #.
    
    port_split_pattern = r"(Port\s+\d+\s+\([\w-]+\)[^\n]*?(?:OPERATIONAL|PRIORITY))"
    chunks = re.split(port_split_pattern, raw_nmap_text, flags=re.IGNORECASE)
    
    # chunks will look like: [IntroText, "Port 80...OPERATIONAL", "Body of Port 80", "Port 443...", "Body of Port 443", ...]
    # We iterate starting from index 1, taking 2 items at a time (Header + Body).
    
    ports_data = []
    
    if len(chunks) > 1:
        # Range starts at 1, goes to len, steps by 2
        for i in range(1, len(chunks), 2):
            header = chunks[i]
            body = chunks[i+1] if i+1 < len(chunks) else ""
            
            # 1. Parse Header for Port Number/Proto
            header_match = re.search(r"Port\s+(\d+)\s+\(([\w-]+)\)", header, re.IGNORECASE)
            port_num = int(header_match.group(1)) if header_match else 0
            
            # 2. Parse Body for details
            
            # Protocol: Try to find PROTOCOL block in body, else fallback to header
            proto_match = re.search(r"PROTOCOL\s*(.*?)\s*STATE", body, re.DOTALL | re.IGNORECASE)
            if proto_match:
                protocol = proto_match.group(1).strip().lower()
                service = header_match.group(2) if header_match else "Unknown"
            else:
                protocol = header_match.group(2).lower() if header_match else "tcp"
                svc_match = re.search(r"SERVICE\s*(.*?)\s*STATE", body, re.DOTALL | re.IGNORECASE)
                service = re.sub(r'\s+', '', svc_match.group(1)).strip() if svc_match else "Unknown"

            # State
            state = "Unknown"
            state_match = re.search(r"STATE\s*(.*?)\s*(?:PROCESS|SERVICE VERSION)", body, re.DOTALL | re.IGNORECASE)
            if state_match:
                state = state_match.group(1).strip()
            
            # Process
            process = "Unknown"
            proc_match = re.search(r"PROCESS\s*(.*?)\s*(?:CPE|VERSION IDENTITY|$)", body, re.DOTALL | re.IGNORECASE)
            if proc_match:
                process = re.sub(r'\s+', ' ', proc_match.group(1)).strip()

            # Version Identity
            version = None
            ver_match = re.search(r"(?:VERSION IDENTITY:|SERVICE VERSION)\s*(.*?)\s*(?:CPE|TCTR|$)", body, re.DOTALL | re.IGNORECASE)
            if ver_match:
                version = ver_match.group(1).strip()
            
            # Fallback: If version is empty, N/A, or missing, use service name
            final_version = version if version and version != "N/A" else service

            # TCTR Magnitude & Intelligence Breakdown
            tctr_mag_match = re.search(r"TCTR THREAT MAGNITUDE\s*([\d\.]+)%", body, re.IGNORECASE)
            tctr_magnitude = float(tctr_mag_match.group(1)) if tctr_mag_match else None
            
            intel_match = re.search(r"Intelligence Breakdown:\s*(.*?)(?:\[|\n|$)", body, re.IGNORECASE)
            intelligence_breakdown = intel_match.group(1).strip() if intel_match else None

            ports_data.append({
                "port": port_num,
                "protocol": protocol,
                "state": state,
                "service_name": service,
                "service_version": final_version,
                "local_process": process,
                "tctr_magnitude_percent": tctr_magnitude,
                "intelligence_breakdown": intelligence_breakdown
            })

    report["open_ports"] = ports_data
    return report

def process_nmap_report_file(file_path: str) -> Dict[str, Any]:
    # (Same as previous - boiler plate file handler)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Nmap report not found: {file_path}")
    
    logger.info(f"Processing Nmap report: {file_path}")
    try:
        raw_text = extract_text_from_pdf(file_path)
        if not raw_text.strip():
            raise ValueError("Extracted text from file is empty.")
            
        report_data = parse_nmap_report(raw_text)
        
        report_data["file_metadata"] = {
            "filename": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }
        return report_data
        
    except Exception as e:
        logger.error(f"Error processing Nmap report {file_path}: {e}")
        raise

# --- Testing Block ---
if __name__ == "__main__":
    # Test with the raw text provided in the prompt
    test_text = """
Network
Assessment
// AUTONOMOUS DEFENSE GRID
OPERATIONAL OVERVIEW
OPEN ENTRY POINTS
5SCAN DURATION
597.44
secondsTHREATS DETECTED
0 OS FINGERPRINT
Unknown / Not
Detected 
SERVICE ENUMERATION
TARGET NODE
192.168.29.1TIMESTAMP
2026-01-07
15:56:57HOST STATUS
UP
CONFIGURATION
METRICPARAMETERS / RESULTS
CLI Argumentsnmap -T4 -sC -sV --script vuln -Pn -oG D:\\NetShieldAI\\Services\
\\results\\DivyaViradiya_1\\network_scanner\\scan_result_vuln.txt
192.168.29.1
Security Posture VERIFIED SECURE
Port 80 (TCP) OPERATIONAL 
SERVICE
HTTPSTATE
OpenPROCESS
No listening PID
foundCPE TRACE
None
VERSION IDENTITY:  lighttpd 
Port 443 (TCP) OPERATIONAL 
SERVICE
SSL|HTTPSTATE
OpenPROCESS
No listening PID
foundCPE TRACE
None
VERSION IDENTITY:  lighttpd 
Page 1 of 2
NETSHIELDAI REPORTING ENGINE // NETWORK ASSESSMENT // 2026-01-07 15:56:57 Port 1900 (TCP) OPERATIONAL 
SERVICE
UPNPSTATE
OpenPROCESS
No listening PID
foundCPE TRACE
None
Port 7443 (TCP) OPERATIONAL 
SERVICE
SSL|ORACLEAS-
HTTPS?STATE
OpenPROCESS
No listening PID
foundCPE TRACE
None
Port 8080 (TCP) OPERATIONAL 
SERVICE
HTTP-PROXY?STATE
OpenPROCESS
No listening PID
foundCPE TRACE
None
Page 2 of 2
"""
    result = parse_nmap_report(test_text)
    print(json.dumps(result, indent=2))