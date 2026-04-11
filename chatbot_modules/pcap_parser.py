import os
import re
import json
import uuid
import logging
from typing import Dict, Any, List
from datetime import datetime

# Initialize module logger
logger = logging.getLogger(__name__)

# --- PDF Dependency Integration ---
try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    try:
        from pdf_extractor import extract_text_from_pdf
    except ImportError:
        def extract_text_from_pdf(pdf_path: str) -> str:
            raise NotImplementedError("pdf_extractor.py not found.")

def parse_pcap_report(raw_text: str) -> Dict[str, Any]:
    # 1. Normalize Line Endings
    raw_text = re.sub(r'\r\n|\r', '\n', raw_text)
    raw_text = re.sub(r'Page \d+ of \d+', '', raw_text) 

    report = {
        "scan_metadata": {
            "tool": "NetShieldAI (TShark)",
            "report_id": str(uuid.uuid4()),
            "report_type": "Network Traffic Analysis",
            "target_node": None,
            "capture_timestamp": None,
            "engine_version": None,
            "anomalies_detected": "Unknown"
        },
        "traffic_metrics": {
            "total_packets": 0,
            "data_volume": None,
            "duration_sec": 0.0,
            "throughput": None
        },
        "protocol_hierarchy": [],
        "active_conversations": [],
        "packet_sample": [],
        "security_insights": "No anomalies detected."
    }

    # --- METADATA ---
    target_match = re.search(r"(?:TARGET NODE|TARGET NODE\n|TARGET IP\n)\s*([\d\.]+)", raw_text)
    if target_match: report["scan_metadata"]["target_node"] = target_match.group(1)

    ts_match = re.search(r"(?:CAPTURE TIMESTAMP|CAPTURE DATE)\s*([\d-]{10}T[\d:\.\+\-\s]+?)(?:ENGINE|DATA|\nTOTAL|\n\n|$)", raw_text, re.DOTALL)
    if ts_match: report["scan_metadata"]["capture_timestamp"] = ts_match.group(1).replace('\n', '')

    ver_match = re.search(r"ENGINE VERSION\s*(.*)", raw_text)
    if ver_match: report["scan_metadata"]["engine_version"] = ver_match.group(1).strip()

    anomal_match = re.search(r"ANOMALIES DETECTED\s*(.*?)\s*\n", raw_text)
    if anomal_match: report["scan_metadata"]["anomalies_detected"] = anomal_match.group(1).strip()

    # --- TRAFFIC METRICS (FIXED) ---
    pkts_match = re.search(r"TOTAL\s+PACKETS\s*(\d+)", raw_text)
    if pkts_match: report["traffic_metrics"]["total_packets"] = int(pkts_match.group(1))

    # FIX: Regex now explicitly looks for specific units (B, KB, MB, GB) to avoid grabbing "DURATION"
    vol_match = re.search(r"DATA\s+VOLUME\s*([\d\.]+)\s*(B|KB|MB|GB|TB)", raw_text, re.IGNORECASE)
    if vol_match:
        report["traffic_metrics"]["data_volume"] = f"{vol_match.group(1)} {vol_match.group(2).upper()}"

    dur_match = re.search(r"DURATION\s*([\d\.]+)s", raw_text)
    if dur_match: report["traffic_metrics"]["duration_sec"] = float(dur_match.group(1))

    thru_match = re.search(r"(?:THROUGHPUT|AVG THROUGHPUT)\s*([\d\.]+\s*(?:bps|kbps|mbps|gbps|Bps|KBps|MBps))", raw_text, re.IGNORECASE)
    if thru_match: report["traffic_metrics"]["throughput"] = thru_match.group(1)

    # --- PROTOCOL HIERARCHY ---
    proto_start = raw_text.find("PROTOCOL LAYER FRAME COUNT BYTES")
    if proto_start == -1:
        proto_start = raw_text.find("PROTOCOL DISTRIBUTION")

    proto_end = raw_text.find("ACTIVE CONVERSATIONS")
    if proto_end == -1:
        proto_end = raw_text.find("NETSHIELDAI REPORTING ENGINE")
    
    if proto_start != -1:
        proto_section = raw_text[proto_start:proto_end] if proto_end != -1 else raw_text[proto_start:]
        # Regex looks for lines starting with word, space, digits, space, digits
        proto_pattern = re.compile(r"([a-z0-9]+)\s+(\d+)\s+(\d+)", re.IGNORECASE)
        
        for match in proto_pattern.finditer(proto_section):
            # Skip the header line itself ("frame", "164"...) if it gets caught
            if match.group(1).lower() == "layer": continue
            
            report["protocol_hierarchy"].append({
                "protocol": match.group(1),
                "frames": int(match.group(2)),
                "bytes": int(match.group(3))
            })

    # --- ACTIVE CONVERSATIONS ---
    # Pattern: IP:Port ↔ IP:Port
    # We added `re.MULTILINE` and relaxed spaces to catch all lines
    conv_pattern = re.compile(r"([\d\.]+):(\d+)\s*↔\s*([\d\.]+):(\d+)")
    
    for match in conv_pattern.finditer(raw_text):
        report["active_conversations"].append({
            "src_ip": match.group(1),
            "src_port": int(match.group(2)),
            "dst_ip": match.group(3),
            "dst_port": int(match.group(4))
        })

    # --- PACKET INSPECTION SAMPLE ---
    packet_start = raw_text.find("TIME SOURCE DESTINATION PROTOCOL LEN")
    if packet_start == -1:
        packet_start = raw_text.find("TRAFFIC INTELLIGENCE (PACKET INSPECTION)")

    if packet_start != -1:
        packet_section = raw_text[packet_start:]
        # Regex: Time Space IP Space IP Space Proto Space Len (Optional Length) + trailing body
        pkt_pattern = re.compile(
            r"(?:\[([\d\.]+)s\]|([\d\.]+)s)\s+([\w\.:]+)\s*(?:→|->|<->|↔)?\s*([\w\.:]+)\s+([A-Za-z0-9_]+)(?:\s+(\d+))?"
            r"((?:\n|.)*?)"
            r"(?=(?:\[[\d\.]+s\]|[\d\.]+s)\s+[\w\.:]+|\nPROTOCOL|\nNetShield|\Z)"
        )
        
        for match in pkt_pattern.finditer(packet_section):
            time_str = match.group(1) or match.group(2)
            body = match.group(7)
            
            tctr_mag_match = re.search(r"TCTR MAGNITUDE.*?\n([\d\.]+)%", body, re.IGNORECASE)
            tctr_magnitude = float(tctr_mag_match.group(1)) if tctr_mag_match else None
            
            intel_match = re.search(r"%\s*\n(.*?)(?=\n\[ TCTR|\Z)", body, re.IGNORECASE | re.DOTALL)
            intelligence = intel_match.group(1).replace('\n', ' ').strip() if intel_match else None

            report["packet_sample"].append({
                "time_offset": float(time_str) if time_str else 0.0,
                "source": match.group(3),
                "destination": match.group(4),
                "protocol": match.group(5),
                "length": int(match.group(6)) if match.group(6) else 0,
                "tctr_magnitude_percent": tctr_magnitude,
                "intelligence_breakdown": intelligence
            })

    # --- SECURITY INSIGHTS ---
    insight_match = re.search(r"(?:Analysis Summary:|Anomaly Analysis Summary\b[^\n]*\n)\s*(.*?)(?=\nPage|\nNetShield|\[ TCTR|\Z)", raw_text, re.DOTALL)
    if insight_match:
        report["security_insights"] = insight_match.group(1).strip()

    return report

def process_pcap_report_file(file_path: str) -> Dict[str, Any]:
    """
    Handles file I/O for Traffic Analysis reports.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Report not found: {file_path}")
    
    logger.info(f"Processing Traffic Analysis report: {file_path}")
    try:
        raw_text = extract_text_from_pdf(file_path)
        if not raw_text.strip():
            raise ValueError("Extracted text is empty.")
            
        report_data = parse_pcap_report(raw_text)
        
        # Add File Metadata
        report_data["file_metadata"] = {
            "filename": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "processed_at": datetime.now().isoformat()
        }
        return report_data
        
    except Exception as e:
        logger.error(f"Error processing report {file_path}: {e}")
        raise

# --- Test Block ---
if __name__ == "__main__":
    # Extracted text from your prompt
    test_text = """
Network Traffic
Analysis
AUTOMATED INSPECTION REPORT
TRAFFIC OVERVIEW
TOTAL PACKETS
164DATA VOLUME
58.29 KBDURATION
15.33sTHROUGHPUT
3894.52 bps
PROTOCOL HIERARCHY
TARGET NODE
192.168.29.48CAPTURE TIMESTAMP
2026-01-07T10:51:58.716902+
00:00ENGINE VERSION
TShark 4.0.x
PROTOCOL LAYER FRAME COUNT BYTES
frame 164 59686
eth 164 59686
ip 143 52607
tcp 111 42146
tls 52 36162
tls 2 1690
data 1 55
udp 28 10245
dns 8 1103
Page 1 of 3
ACTIVE CONVERSATIONS
PACKET INSPECTION (SAMPLE)SOURCE ENDPOINT DESTINATION ENDPOINT
192.168.29.48:1906 ↔ 140.82.113.22:443
192.168.29.48:17659 ↔ 20.189.173.7:443
TIME SOURCE DESTINATION PROTOCOL LEN
0.000000000s 192.168.29.48 192.168.29.196 TLS 164
0.005750000s 192.168.29.196 192.168.29.48 TLS 164
Page 2 of 3
SECURITY INSIGHTS
NETSHIELDAI REPORTING ENGINE // GENERATED 2026-01-07 16:21:58 Analysis Summary:
No anomalies detected.
Page 3 of 3
"""
    result = parse_pcap_report(test_text)
    print(json.dumps(result, indent=2))