import os
import sys
import re
import json
import uuid
from typing import Union, Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

# Add the current directory to Python path to ensure local imports work
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Now import pdf_extractor
try:
    from pdf_extractor import extract_text_from_pdf
except ImportError as e:
    print(f"Error importing pdf_extractor: {e}")
    print(f"Current Python path: {sys.path}")
    print(f"Current directory: {os.getcwd()}")
    print("Files in current directory:", os.listdir('.'))
    
    # Define a fallback function if import fails
    def extract_text_from_pdf(pdf_path: str) -> Optional[str]:
        print(f"ERROR: Could not import pdf_extractor. Cannot extract text from {pdf_path}")
        return None


def _parse_aggressive_scan(report_text: str, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    (FINAL REVISION) Parses the raw text from an Aggressive (-A) Nmap/iSec scan.
    This version includes final fixes for complex multi-line scripts and OS guess parsing.
    """
    # --- Initialize Data Structures ---
    parsed_data['scan_metadata'] = {}
    parsed_data['hosts'] = []
    host_info = {
        "ip_address": None, "hostnames": [], "other_addresses": [], "status": None,
        "rdns_record": None, "ports": [], "os_detection": {}, "traceroute": [],
        "network_distance": None
    }

    # --- Clean up report text ---
    clean_text = "\n".join(
        line for line in report_text.splitlines()
        if "© iSec Services Pvt Ltd" not in line and line.strip()
    )

    # --- Parse Scan Metadata (Unchanged) ---
    if initiator := re.search(r"Scan Initiated By:\s*(.+)", clean_text):
        parsed_data["scan_metadata"]["initiated_by"] = initiator.group(1).strip()
    if timestamp := re.search(r"Timestamp:\s*(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})", clean_text):
        parsed_data["scan_metadata"]["timestamp"] = timestamp.group(1).strip()
    if summary := re.search(r"iSec Engine 1.0 done:\s*(.*)", clean_text):
        parsed_data["scan_metadata"]["summary"] = summary.group(1).strip()
    parsed_data["scan_metadata"]["scan_type"] = "Aggressive Scan"

    # --- Parse Host Information (Unchanged) ---
    if host_match := re.search(r"scan report for\s+(.+?)\s+\(([\d.X]+)\)", clean_text):
        host_info["hostnames"].append(host_match.group(1).strip())
        host_info["ip_address"] = host_match.group(2).strip()
    if status_match := re.search(r"Host is up\s*(\(.*?\))", clean_text):
        host_info["status"] = f"Host is up {status_match.group(1)}".strip()
    if rdns_match := re.search(r"rDNS record for .*?:\s*(.*)", clean_text):
        host_info["rdns_record"] = rdns_match.group(1).strip()

    # --- (FINAL FIX) Parse Ports and their Scripts ---
    port_section_match = re.search(r"PORT\s+STATE\s+SERVICE\s+VERSION\n(.*?)(?:\n\n|\n[A-Z])", clean_text, re.DOTALL)
    if port_section_match:
        port_text = port_section_match.group(1)
        # Split the text block by the port number pattern to correctly group multi-line scripts
        port_chunks = re.split(r'\n(?=\d+/(?:tcp|udp))', port_text)
        for chunk in port_chunks:
            lines = chunk.strip().split('\n')
            first_line = lines[0]
            parts = re.split(r'\s+', first_line, maxsplit=3)
            port_data = {
                "port_id": parts[0], "state": parts[1], "service": parts[2],
                "version": parts[3] if len(parts) > 3 else "", "script_outputs": []
            }
            # Reconstruct multi-line script outputs
            script_output = ""
            for line in lines[1:]:
                clean_line = line.strip()
                if clean_line.startswith(('|', '_')):
                    if script_output: port_data["script_outputs"].append(script_output)
                    script_output = clean_line.replace("|_", "").replace("|", "").strip()
                else:
                    script_output += " " + clean_line
            if script_output: port_data["script_outputs"].append(script_output)
            host_info["ports"].append(port_data)

    # --- (FINAL FIX) Parse OS Detection ---
    if os_warning := re.search(r"(Warning: OSScan results may be unreliable.*)", clean_text):
        host_info["os_detection"]["warning"] = os_warning.group(1).strip()
    if os_guesses_match := re.search(r"Aggressive OS guesses:\s*(.*)", clean_text, re.DOTALL):
        guesses_str = os_guesses_match.group(1).replace('\n', ' ')
        # Use findall to capture each complete guess, which handles commas within a guess
        guesses = re.findall(r'(.+? \(\d+%\))', guesses_str)
        host_info["os_detection"]["guesses"] = [g.strip(" ,") for g in guesses]
    if os_match_status := re.search(r"(No exact OS matches for host.*)", clean_text):
        host_info["os_detection"]["match_status"] = os_match_status.group(1).strip()

    # --- Parse Traceroute (Unchanged) ---
    if distance := re.search(r"Network Distance: (\d+)\s+hops", clean_text):
        host_info["network_distance"] = int(distance.group(1))
    trace_match = re.search(r"TRACEROUTE.*?HOP\s+RTT\s+ADDRESS\n(.*?)(?=\n\n|\n[A-Z]|\nOS and Service detection)", clean_text, re.DOTALL)
    if trace_match:
        trace_lines = trace_match.group(1).strip().split('\n')
        for line in trace_lines:
            hop_match = re.match(r'^(\d+)\s+([\d.]+\s+ms)\s+(.*)', line.strip())
            if hop_match:
                hop = { "hop": int(hop_match.group(1)), "rtt": hop_match.group(2), "address": hop_match.group(3).strip() }
                host_info["traceroute"].append(hop)

    parsed_data["hosts"].append(host_info)
    return parsed_data

def _parse_port_scan(report_text: str, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses the raw text from a simple Port Scan.

    This function extracts metadata, host details, other IP addresses,
    and a simple list of open ports.
    """
    # --- Initialize Data Structures ---
    parsed_data['scan_metadata'] = {}
    parsed_data['hosts'] = []
    host_info = {
        "ip_address": None,
        "hostnames": [],
        "other_addresses": [],
        "status": None,
        "rdns_record": None,
        "ports": [],
    }

    # --- Clean up report text ---
    clean_text = "\n".join(
        line for line in report_text.splitlines()
        if "© iSec Services Pvt Ltd" not in line and line.strip()
    )

    # --- Parse Scan Metadata ---
    if initiator := re.search(r"Scan Initiated By:\s*(.+)", clean_text):
        parsed_data["scan_metadata"]["initiated_by"] = initiator.group(1).strip()
    if timestamp := re.search(r"Timestamp:\s*(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})", clean_text):
        parsed_data["scan_metadata"]["timestamp"] = timestamp.group(1).strip()
    if summary := re.search(r"iSec Engine 1.0 done:\s*(.*)", clean_text):
        parsed_data["scan_metadata"]["summary"] = summary.group(1).strip()
    # Set the specific scan type
    parsed_data["scan_metadata"]["scan_type"] = "Port Scan"

    # --- Parse Host Information ---
    if host_match := re.search(r"scan report for\s+(.+?)\s+\(([\d.X]+)\)", clean_text):
        host_info["hostnames"].append(host_match.group(1).strip())
        host_info["ip_address"] = host_match.group(2).strip()

    if status_match := re.search(r"Host is up\s*(\(.*?\))", clean_text):
        host_info["status"] = f"Host is up {status_match.group(1)}".strip()

    if rdns_match := re.search(r"rDNS record for .*?:\s*(.*)", clean_text):
        host_info["rdns_record"] = rdns_match.group(1).strip()
        
    other_addr_match = re.search(r'Other addresses for .*?\(not scanned\):(.*?)\nrDNS record', clean_text, re.DOTALL)
    if other_addr_match:
        addr_block = other_addr_match.group(1)
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{10,}', addr_block)
        host_info["other_addresses"] = [ip.strip() for ip in ips]

    # --- Parse Ports ---
    port_summary_match = re.search(r"(Not shown: \d+.*?ports.*)", clean_text)
    if port_summary_match:
        host_info["port_summary"] = port_summary_match.group(1).strip()

    port_section_match = re.search(r"PORT\s+STATE\s+SERVICE\n(.*?)(?=\n\n|\niSec Engine 1.0 done)", clean_text, re.DOTALL)
    if port_section_match:
        port_lines = port_section_match.group(1).strip().split('\n')
        for line in port_lines:
            parts = re.split(r'\s+', line.strip(), maxsplit=2)
            if len(parts) == 3:
                port_data = {
                    "port_id": parts[0],
                    "state": parts[1],
                    "service": parts[2],
                }
                host_info["ports"].append(port_data)

    parsed_data["hosts"].append(host_info)
    return parsed_data

def _parse_tcp_syn_scan(report_text: str, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses the raw text from a TCP SYN Scan.

    This function extracts metadata, host details, other IP addresses,
    and a simple list of open ports.
    """
    # --- Initialize Data Structures ---
    parsed_data['scan_metadata'] = {}
    parsed_data['hosts'] = []
    host_info = {
        "ip_address": None,
        "hostnames": [],
        "other_addresses": [],
        "status": None,
        "rdns_record": None,
        "ports": [],
    }

    # --- Clean up report text ---
    clean_text = "\n".join(
        line for line in report_text.splitlines()
        if "© iSec Services Pvt Ltd" not in line and line.strip()
    )

    # --- Parse Scan Metadata ---
    if initiator := re.search(r"Scan Initiated By:\s*(.+)", clean_text):
        parsed_data["scan_metadata"]["initiated_by"] = initiator.group(1).strip()
    if timestamp := re.search(r"Timestamp:\s*(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})", clean_text):
        parsed_data["scan_metadata"]["timestamp"] = timestamp.group(1).strip()
    if summary := re.search(r"iSec Engine 1.0 done:\s*(.*)", clean_text):
        parsed_data["scan_metadata"]["summary"] = summary.group(1).strip()
    # Set the specific scan type
    parsed_data["scan_metadata"]["scan_type"] = "TCP SYN Scan"

    # --- Parse Host Information ---
    if host_match := re.search(r"scan report for\s+(.+?)\s+\(([\d.X]+)\)", clean_text):
        host_info["hostnames"].append(host_match.group(1).strip())
        host_info["ip_address"] = host_match.group(2).strip()

    if status_match := re.search(r"Host is up\s*(\(.*?\))", clean_text):
        host_info["status"] = f"Host is up {status_match.group(1)}".strip()

    if rdns_match := re.search(r"rDNS record for .*?:\s*(.*)", clean_text):
        host_info["rdns_record"] = rdns_match.group(1).strip()
        
    other_addr_match = re.search(r'Other addresses for .*?\(not scanned\):(.*?)\nrDNS record', clean_text, re.DOTALL)
    if other_addr_match:
        addr_block = other_addr_match.group(1)
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{10,}', addr_block)
        host_info["other_addresses"] = [ip.strip() for ip in ips]

    # --- Parse Ports ---
    port_summary_match = re.search(r"(Not shown: \d+.*?ports.*)", clean_text)
    if port_summary_match:
        host_info["port_summary"] = port_summary_match.group(1).strip()

    port_section_match = re.search(r"PORT\s+STATE\s+SERVICE\n(.*?)(?=\n\n|\niSec Engine 1.0 done)", clean_text, re.DOTALL)
    if port_section_match:
        port_lines = port_section_match.group(1).strip().split('\n')
        for line in port_lines:
            parts = re.split(r'\s+', line.strip(), maxsplit=2)
            if len(parts) == 3:
                port_data = {
                    "port_id": parts[0],
                    "state": parts[1],
                    "service": parts[2],
                }
                host_info["ports"].append(port_data)

    parsed_data["hosts"].append(host_info)
    return parsed_data

def _parse_os_detection_scan(report_text: str, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses the raw text from an OS Detection Scan.

    This function extracts metadata, host details, a simple port list,
    and detailed OS detection results.
    """
    # --- Initialize Data Structures ---
    parsed_data['scan_metadata'] = {}
    parsed_data['hosts'] = []
    host_info = {
        "ip_address": None,
        "hostnames": [],
        "other_addresses": [],
        "status": None,
        "rdns_record": None,
        "ports": [],
        "os_detection": {},
        "network_distance": None
    }

    # --- Clean up report text ---
    clean_text = "\n".join(
        line for line in report_text.splitlines()
        if "© iSec Services Pvt Ltd" not in line and line.strip()
    )

    # --- Parse Scan Metadata ---
    if initiator := re.search(r"Scan Initiated By:\s*(.+)", clean_text):
        parsed_data["scan_metadata"]["initiated_by"] = initiator.group(1).strip()
    if timestamp := re.search(r"Timestamp:\s*(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})", clean_text):
        parsed_data["scan_metadata"]["timestamp"] = timestamp.group(1).strip()
    if summary := re.search(r"iSec Engine 1.0 done:\s*(.*)", clean_text):
        parsed_data["scan_metadata"]["summary"] = summary.group(1).strip()
    parsed_data["scan_metadata"]["scan_type"] = "OS Detection Scan"

    # --- Parse Host Information ---
    if host_match := re.search(r"scan report for\s+(.+?)\s+\(([\d.X]+)\)", clean_text):
        host_info["hostnames"].append(host_match.group(1).strip())
        host_info["ip_address"] = host_match.group(2).strip()

    if status_match := re.search(r"Host is up\s*(\(.*?\))", clean_text):
        host_info["status"] = f"Host is up {status_match.group(1)}".strip()

    if rdns_match := re.search(r"rDNS record for .*?:\s*(.*)", clean_text):
        host_info["rdns_record"] = rdns_match.group(1).strip()
        
    other_addr_match = re.search(r'Other addresses for .*?\(not scanned\):(.*?)\nrDNS record', clean_text, re.DOTALL)
    if other_addr_match:
        addr_block = other_addr_match.group(1)
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{10,}', addr_block)
        host_info["other_addresses"] = [ip.strip() for ip in ips]

    # --- Parse Simple Port List ---
    port_section_match = re.search(r"PORT\s+STATE\s+SERVICE\n(.*?)(?=\n\n|\nWarning: OSScan)", clean_text, re.DOTALL)
    if port_section_match:
        port_lines = port_section_match.group(1).strip().split('\n')
        for line in port_lines:
            parts = re.split(r'\s+', line.strip(), maxsplit=2)
            if len(parts) == 3:
                port_data = {"port_id": parts[0], "state": parts[1], "service": parts[2]}
                host_info["ports"].append(port_data)
    
    # --- Parse OS Detection ---
    if os_warning := re.search(r"(Warning: OSScan results may be unreliable.*)", clean_text):
        host_info["os_detection"]["warning"] = os_warning.group(1).strip()
    if os_guesses_match := re.search(r"Aggressive OS guesses:\s*(.*)", clean_text, re.DOTALL):
        guesses_str = os_guesses_match.group(1).replace('\n', ' ')
        guesses = re.findall(r'(.+? \(\d+%\))', guesses_str)
        host_info["os_detection"]["guesses"] = [g.strip(" ,") for g in guesses]
    if os_match_status := re.search(r"(No exact OS matches for host.*)", clean_text):
        host_info["os_detection"]["match_status"] = os_match_status.group(1).strip()
    
    # --- Parse Network Distance ---
    if distance := re.search(r"Network Distance: (\d+)\s+hops", clean_text):
        host_info["network_distance"] = int(distance.group(1))

    parsed_data["hosts"].append(host_info)
    return parsed_data

def _parse_fragmented_scan(report_text: str, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    (REVISED) Parses the raw text from a Fragmented Packet Scan.
    This version includes the fix for parsing the "Other addresses" field.
    """
    # --- Initialize Data Structures ---
    parsed_data['scan_metadata'] = {}
    parsed_data['hosts'] = []
    host_info = {
        "ip_address": None,
        "hostnames": [],
        "other_addresses": [],
        "status": None,
        "rdns_record": None,
        "ports": [],
    }

    # --- Clean up report text ---
    clean_text = "\n".join(
        line for line in report_text.splitlines()
        if "© iSec Services Pvt Ltd" not in line and line.strip()
    )

    # --- Parse Scan Metadata ---
    if initiator := re.search(r"Scan Initiated By:\s*(.+)", clean_text):
        parsed_data["scan_metadata"]["initiated_by"] = initiator.group(1).strip()
    if timestamp := re.search(r"Timestamp:\s*(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})", clean_text):
        parsed_data["scan_metadata"]["timestamp"] = timestamp.group(1).strip()
    if summary := re.search(r"iSec Engine 1.0 done:\s*(.*)", clean_text):
        parsed_data["scan_metadata"]["summary"] = summary.group(1).strip()
    parsed_data["scan_metadata"]["scan_type"] = "Fragmented Packet Scan"

    # --- Parse Host Information ---
    if host_match := re.search(r"scan report for\s+(.+?)\s+\(([\d.X]+)\)", clean_text):
        host_info["hostnames"].append(host_match.group(1).strip())
        host_info["ip_address"] = host_match.group(2).strip()

    if status_match := re.search(r"Host is up\s*(\(.*?\))", clean_text):
        host_info["status"] = f"Host is up {status_match.group(1)}".strip()

    if rdns_match := re.search(r"rDNS record for .*?:\s*(.*)", clean_text):
        host_info["rdns_record"] = rdns_match.group(1).strip()
        
    # --- (REVISED) Parse Other Addresses ---
    # The regex below is now corrected to properly find the address block.
    other_addr_match = re.search(r'Other addresses for .*?\(not scanned\):(.*?)\nrDNS record', clean_text, re.DOTALL)
    if other_addr_match:
        addr_block = other_addr_match.group(1)
        # Find all valid IPv4 (non-masked) and IPv6 addresses in the block
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{10,}', addr_block)
        host_info["other_addresses"] = [ip.strip() for ip in ips]

    # --- Parse Ports ---
    port_summary_match = re.search(r"(Not shown: \d+.*?ports.*)", clean_text)
    if port_summary_match:
        host_info["port_summary"] = port_summary_match.group(1).strip()

    port_section_match = re.search(r"PORT\s+STATE\s+SERVICE\n(.*?)(?=\n\n|\niSec Engine 1.0 done)", clean_text, re.DOTALL)
    if port_section_match:
        port_lines = port_section_match.group(1).strip().split('\n')
        for line in port_lines:
            parts = re.split(r'\s+', line.strip(), maxsplit=2)
            if len(parts) == 3:
                port_data = {
                    "port_id": parts[0],
                    "state": parts[1],
                    "service": parts[2],
                }
                host_info["ports"].append(port_data)

    parsed_data["hosts"].append(host_info)
    return parsed_data

def _parse_ip_range_scan(report_text: str, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses the raw text from an iSec IP Range Scan report.

    This function processes a report containing multiple host entries from a range scan,
    extracting scan metadata, individual host details, open ports, and MAC addresses.

    Args:
        report_text: The full string content of the iSec IP Range Scan report.
        parsed_data: The dictionary to populate with the parsed data.

    Returns:
        The dictionary populated with structured scan data.
    """
    # --- Initialize Data Structures ---
    parsed_data['scan_metadata'] = {}
    parsed_data['hosts'] = []

    # --- Clean up report text ---
    clean_text = "\n".join(
        line.strip() for line in report_text.splitlines()
        if "© iSec Services Pvt Ltd" not in line and "Page " not in line and line.strip()
    )

    # --- 1. Parse Scan-Wide Metadata ---
    metadata_patterns = [
        ("initiated_by", r"Scan Initiated By:\s*(.+)"),
        ("timestamp", r"Timestamp:\s*(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})"),
        ("summary", r"iSec Engine 1.0 done:\s*(.+)"),
    ]
    for key, pattern in metadata_patterns:
        if match := re.search(pattern, clean_text):
            parsed_data["scan_metadata"][key] = match.group(1).strip()
    
    # Set the scan type
    parsed_data["scan_metadata"]["scan_type"] = "IP Range Scan"

    # --- 2. Split the report into individual host blocks ---
    host_blocks = re.split(r'(?=iSec Engine 1.0 scan report for)', clean_text)

    # --- 3. Process Each Host Block ---
    for block in host_blocks:
        if not block.strip() or 'scan report for' not in block:
            continue

        host_info: Dict[str, Any] = {
            "ip_address": None, "status": None, "latency": None, "ports": [],
            "mac_address": None, "mac_vendor": None, "unshown_ports_summary": None,
            "scan_notes": []
        }

        # Extract IP, Status, Latency, and MAC
        if ip_match := re.search(r"scan report for\s+([\d.X]+)", block):
            host_info["ip_address"] = ip_match.group(1).strip()
        
        if status_match := re.search(r"Host is up(?:\s*\(([\d.]+s) latency\))?", block):
            host_info["status"] = "up"
            host_info["latency"] = status_match.group(1) if status_match.group(1) else "N/A"
        
        if mac_match := re.search(r"MAC Address:\s*([0-9A-F:X]+)\s+\((.*?)\)", block):
            host_info["mac_address"] = mac_match.group(1).strip()
            host_info["mac_vendor"] = mac_match.group(2).strip()

        # Extract Contextual Notes
        if unshown_match := re.search(r"Not shown:\s*(.*)", block):
            host_info["unshown_ports_summary"] = unshown_match.group(1).strip()
        if note_match := re.search(r"(All \d+ scanned ports.*?are in ignored states\.)", block):
            host_info["scan_notes"].append(note_match.group(1).strip())

        # --- CORRECTED SECTION ---
        # Extract Open Ports. The lookahead now includes the "iSec Engine done" line
        # to correctly terminate parsing for the final host.
        port_section_match = re.search(
            r"PORT\s+STATE\s+SERVICE\n(.*?)(?=\nMAC Address:|\niSec Engine 1.0 done:|\n$)",
            block,
            re.DOTALL
        )
        if port_section_match:
            port_text = port_section_match.group(1).strip()
            for line in port_text.split('\n'):
                parts = re.split(r'\s+', line.strip(), maxsplit=2)
                if len(parts) == 3:
                    host_info["ports"].append({"port_id": parts[0], "state": parts[1], "service": parts[2]})

        # Add the processed host data if it's valid
        if host_info.get("ip_address"):
            parsed_data["hosts"].append(host_info)

    return parsed_data

def _parse_generic_scan(report_text: str, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    The main parsing logic, capable of handling a wide variety of Nmap outputs.
    This serves as the foundation and fallback parser.
    """
    # --- Process Host Blocks ---
    # This is the core logic from your original function.
    host_blocks = re.split(r"Nmap scan report for", report_text)[1:]

    for block in host_blocks:
        lines_in_block = [line.strip() for line in block.split('\n') if line.strip()]
        if not lines_in_block:
            continue

        host_info_line = lines_in_block[0]
        ip_match = re.search(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", host_info_line)
        hostname_match = re.search(r"^([^\s\(]+)", host_info_line)
        
        ip_address = ip_match.group(1) if ip_match else "N/A"
        hostname = hostname_match.group(1) if hostname_match else ip_address
        
        current_host = {
            "ip_address": ip_address,
            "hostname": hostname,
            "status": "unknown",
            "latency": "N/A",
            "rdns": "N/A",
            "other_addresses": [],
            "mac_address": "N/A",
            "network_distance": None,
            "os_detection": {},
            "ports": [],
            "traceroute": [],
        }
        
        i = 0
        while i < len(lines_in_block):
            line = lines_in_block[i].strip()
            
            # Host status and latency
            if "Host is up" in line:
                current_host["status"] = "up"
                latency_match = re.search(r"\((\d+\.\d+s) latency\)", line)
                if latency_match:
                    current_host["latency"] = latency_match.group(1)
            
            # rDNS record
            elif "rDNS record for" in line:
                rdns_match = re.search(r"rDNS record for .*?: (.*)", line)
                if rdns_match:
                    current_host["rdns"] = rdns_match.group(1).strip()

            # MAC Address
            elif "MAC Address:" in line:
                mac_match = re.search(r"MAC Address: ([\dA-F:]{17}) \((.*?)\)", line)
                if mac_match:
                    current_host["mac_address"] = f"{mac_match.group(1)} ({mac_match.group(2)})"

            # Port Information
            elif re.match(r"^\d+/(tcp|udp)", line):
                port_match = re.match(r"(\d+)/(tcp|udp)\s+([\w|\-]+)\s+([\w\-]+)\s*(.*)", line)
                if port_match:
                    current_port = {
                        "port_id": int(port_match.group(1)),
                        "protocol": port_match.group(2),
                        "state": port_match.group(3),
                        "service": port_match.group(4),
                        "version": port_match.group(5).strip() or "N/A",
                        "script_outputs": {}
                    }
                    current_host["ports"].append(current_port)
            
            # OS Detection
            elif "Aggressive OS guesses:" in line:
                os_guesses = line.split(":", 1)[1].strip()
                current_host["os_detection"]["aggressive_os_guesses"] = [g.strip() for g in os_guesses.split(',')]

            # TRACEROUTE
            elif "TRACEROUTE" in line:
                # Placeholder for traceroute logic
                pass # Add full traceroute parsing here if needed

            i += 1
            
        parsed_data["hosts"].append(current_host)
        
    return parsed_data


# --- Main Controller Function ---

def parse_nmap_report(raw_nmap_text: str) -> Dict[str, Any]:
    """
    Transforms raw Nmap text into a structured dictionary by delegating to a specific parser.

    Args:
        raw_nmap_text: The raw text output from an Nmap scan.

    Returns:
        A structured dictionary containing the parsed Nmap scan information.
    """
    parsed_data: Dict[str, Any] = {
        "scan_metadata": {
            "scan_type": "Generic Nmap Scan",
            "target": None,
            "nmap_version": None,
            "scan_start_time": None,
            "scan_duration": None,
        },
        "hosts": []
    }
    
    # Clean up raw text
    cleaned_text = "\n".join([line.strip() for line in raw_nmap_text.split('\n') if line.strip()])

    # --- Extract Common Metadata ---
    # This information is consistent across most scan types.
    target_match = re.search(r"Nmap scan report for (.*?)\n", cleaned_text)
    if target_match:
        parsed_data["scan_metadata"]["target"] = target_match.group(1).strip()
        
    version_match = re.search(r"Starting Nmap ([\d.]+)", cleaned_text)
    if version_match:
        parsed_data["scan_metadata"]["nmap_version"] = version_match.group(1)
        
    start_time_match = re.search(r"at (.*?)$", cleaned_text, re.MULTILINE)
    if start_time_match:
        parsed_data["scan_metadata"]["scan_start_time"] = start_time_match.group(1).strip()

    duration_match = re.search(r"Nmap done:.*?in ([\d.]+ seconds)", cleaned_text)
    if duration_match:
        parsed_data["scan_metadata"]["scan_duration"] = duration_match.group(1)
        
    # --- Determine Scan Type and Delegate to the Correct Parser ---
    scan_type = "iSec Scan Engine - Generic Scan" # Default
    if "iSec Scan Engine - Aggressive Scan Report" in cleaned_text or "-A" in cleaned_text:
        scan_type = "Aggressive Scan"
    elif "iSec Scan Engine - Port Scan Report" in cleaned_text:
        scan_type = "Port Scan"
    elif "iSec Scan Engine - Tcp Syn Scan Report" in cleaned_text or "-sS" in cleaned_text:
        scan_type = "TCP SYN Scan"
    elif "iSec Scan Engine - Os Detection Report" in cleaned_text or "-O" in cleaned_text:
        scan_type = "OS Detection Scan"
    elif "iSec Scan Engine - Fragmented Packet Scan Report" in cleaned_text or "-f" in cleaned_text:
        scan_type = "Fragmented Packet Scan"
    elif "iSec Scan Engine - Ip Range Scan Report" in cleaned_text or "-R" in cleaned_text:
        scan_type = "IP Range Scan"
    
    parsed_data["scan_metadata"]["scan_type"] = scan_type
    
    # The if-elif-else block for delegation
    if scan_type == "Aggressive Scan":
        print("--- Using Aggressive Scan Parser ---")
        return _parse_aggressive_scan(cleaned_text, parsed_data)
    elif scan_type == "Port Scan":
        print("--- Using Port Scan Parser ---")
        return _parse_port_scan(cleaned_text, parsed_data)
    elif scan_type == "TCP SYN Scan":
        print("--- Using TCP SYN Scan Parser ---")
        return _parse_tcp_syn_scan(cleaned_text, parsed_data)
    elif scan_type == "OS Detection Scan":
        print("--- Using OS Detection Scan Parser ---")
        return _parse_os_detection_scan(cleaned_text, parsed_data)
    elif scan_type == "Fragmented Packet Scan":
        print("--- Using Fragmented Packet Scan Parser ---")
        return _parse_fragmented_scan(cleaned_text, parsed_data)
    elif scan_type == "IP Range Scan":
        print("--- Using IP Range Scan Parser ---")
        return _parse_ip_range_scan(cleaned_text, parsed_data)

    else:
        # Fallback to the generic parser for any other scan type
        print("--- No specific parser found, using Generic Parser ---")
        return _parse_generic_scan(cleaned_text, parsed_data)

# --- Main Nmap Report Processing Function for Files ---

def process_nmap_report_file(pdf_file_path: str) -> Optional[Dict[str, Any]]:
    """
    Reads an Nmap PDF report, extracts text, identifies its type (if possible),
    and calls the general parser function.
    Returns a dictionary with overall report metadata and a list of structured host data.
    """
    print(f"\nProcessing Nmap PDF: {pdf_file_path}")
    raw_text = extract_text_from_pdf(pdf_file_path)

    if not raw_text:
        print(f"  Failed to extract text from {pdf_file_path}. Skipping.")
        return None

    # The parse_nmap_report function now handles internal type detection and general parsing
    structured_data = parse_nmap_report(raw_text)

    # Add source file name to metadata
    structured_data["scan_metadata"]["source_file_name"] = os.path.basename(pdf_file_path)

    # It's good to also add the report ID here, which would ideally be passed through
    # For now, let's generate one if not already set by an overarching process
    if "report_id" not in structured_data["scan_metadata"]:
        structured_data["scan_metadata"]["report_id"] = str(uuid.uuid4())

    print(f"  Processed {len(structured_data['hosts'])} host(s) from {os.path.basename(pdf_file_path)}.")
    
    return structured_data

# --- Main Execution Flow for Testing ---
if __name__ == "__main__":
    # Ensure this script can find pdf_extractor.py
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root_dir = os.path.dirname(current_script_dir)  # Go up one level to VulnScanAI
    
    # Add project root to path for module imports
    if project_root_dir not in sys.path:
        sys.path.insert(0, project_root_dir)
    
    # Use the nmap_reports_data directory in the project root
    pdf_reports_directory = os.path.join(project_root_dir,"documents", "Nmap_test")
    
    print(f"Looking for Nmap PDF files in: {pdf_reports_directory}\n")

    if not os.path.exists(pdf_reports_directory):
        print(f"Error: Directory '{pdf_reports_directory}' not found.")
        sys.exit(1)
    
    # Get all PDF files in the directory
    pdf_files = [f for f in os.listdir(pdf_reports_directory) 
                if f.lower().endswith('.pdf') and os.path.isfile(os.path.join(pdf_reports_directory, f))]
    
    if not pdf_files:
        print(f"No PDF files found in {pdf_reports_directory}")
        sys.exit(1)
    
    print(f"Found {len(pdf_files)} PDF file(s) to process:\n")
    
    for filename in pdf_files:
        pdf_path = os.path.join(pdf_reports_directory, filename)
        print(f"--- Processing {filename} ---")
        
        try:
            # Extract text from PDF
            raw_text = extract_text_from_pdf(pdf_path)
            if not raw_text:
                print(f"  Failed to extract text from {filename}")
                continue
                
            # Parse the Nmap report
            parsed_data = parse_nmap_report(raw_text)
            
            # Add source file info
            parsed_data["scan_metadata"]["source_file"] = filename
            
            # Print the parsed data
            print(json.dumps(parsed_data, indent=2))
            print("\n" + "="*80 + "\n")  # Separator for clarity
            
        except Exception as e:
            print(f"Error processing {filename}: {e}")
            import traceback
            traceback.print_exc()  # Print full traceback for debugging
            print("\n" + "="*80 + "\n")