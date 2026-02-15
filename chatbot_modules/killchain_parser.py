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

def parse_killchain_report(raw_text: str) -> Dict[str, Any]:
    """
    Parses the "Kill Chain Analysis" PDF report.
    Handles Phase analysis, Risk summaries, and hybrid finding formats (Standard vs ZAP).
    """
    # --- 1. Clean Text ---
    # Remove "Page X of Y" artifacts
    clean_text = re.sub(r'Page \d+ of \d+', '', raw_text)
    # Normalize line endings
    clean_text = re.sub(r'\r\n|\r', '\n', clean_text).strip()

    report_data = {
        "metadata": {},
        "risk_summary": {},
        "phase_analysis": {
            "recon": {},
            "weaponization": {}
        },
        "vulnerabilities": []
    }

    # --- 2. Extract Header & Metadata ---
    
    # Target & Profile
    target_match = re.search(r'TARGET\s*\n?([^\n]+)', clean_text)
    if target_match:
        report_data["metadata"]["target"] = target_match.group(1).replace("PROFILE", "").strip()

    profile_match = re.search(r'PROFILE\s*\n?([^\n]+)', clean_text)
    if profile_match:
        report_data["metadata"]["profile"] = profile_match.group(1).replace("REPORT ID", "").strip()

    # Report ID & Date
    rid_match = re.search(r'REPORT ID\s*\n?([^\n]+)', clean_text)
    if rid_match:
        report_data["metadata"]["report_id"] = rid_match.group(1).replace("DATE", "").strip()

    date_match = re.search(r'DATE\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', clean_text)
    if date_match:
        report_data["metadata"]["scan_date"] = date_match.group(1)

    # --- 3. Extract Risk Summary ---
    # Looks for "TOTAL FINDINGS\n45CRITICAL\n2HIGH..." pattern
    # We use regex to find numbers adjacent to the labels
    
    total_match = re.search(r'TOTAL FINDINGS\s*(\d+)', clean_text)
    if total_match: report_data["risk_summary"]["total"] = int(total_match.group(1))

    crit_match = re.search(r'CRITICAL\s*(\d+)', clean_text)
    if crit_match: report_data["risk_summary"]["critical"] = int(crit_match.group(1))

    high_match = re.search(r'HIGH\s*(\d+)', clean_text)
    if high_match: report_data["risk_summary"]["high"] = int(high_match.group(1))

    med_match = re.search(r'MEDIUM\s*(\d+)', clean_text)
    if med_match: report_data["risk_summary"]["medium"] = int(med_match.group(1))

    low_match = re.search(r'LOW / INFO\s*(\d+)', clean_text)
    if low_match: report_data["risk_summary"]["low_info"] = int(low_match.group(1))

    # --- 4. Extract Phase Analysis ---

    # Phase 1: Reconnaissance
    recon_section = re.search(r'PHASE 1: RECONNAISSANCE(.*?)(?=PHASE 2)', clean_text, re.DOTALL)
    if recon_section:
        r_text = recon_section.group(1)
        ip_match = re.search(r'Target IP:\s*([^\n]+)', r_text)
        if ip_match: report_data["phase_analysis"]["recon"]["target_ip"] = ip_match.group(1).strip()
        
        status_match = re.search(r'Status:\s*([^\n]+)', r_text)
        if status_match: report_data["phase_analysis"]["recon"]["status"] = status_match.group(1).strip()
        
        sub_match = re.search(r'Subdomains Found:\s*(\d+)', r_text)
        if sub_match: report_data["phase_analysis"]["recon"]["subdomains_count"] = int(sub_match.group(1))
        
        url_match = re.search(r'URLs Discovered:\s*(\d+)', r_text)
        if url_match: report_data["phase_analysis"]["recon"]["urls_count"] = int(url_match.group(1))
        
        ports_match = re.search(r'OPEN PORTS:\s*\n?(.*)', r_text, re.DOTALL)
        if ports_match:
            ports = [p.strip() for p in ports_match.group(1).split('\n') if p.strip()]
            report_data["phase_analysis"]["recon"]["open_ports"] = ports

    # Phase 2: Weaponization
    weap_section = re.search(r'PHASE 2: WEAPONIZATION \(TECH\)(.*?)(?=NETSHIELD AGGREGATED)', clean_text, re.DOTALL)
    if weap_section:
        w_text = weap_section.group(1)
        server_match = re.search(r'Server:\s*([^\n]+)', w_text)
        if server_match: report_data["phase_analysis"]["weaponization"]["server"] = server_match.group(1).strip()
        
        lang_match = re.search(r'Language:\s*([^\n]+)', w_text)
        if lang_match: report_data["phase_analysis"]["weaponization"]["language"] = lang_match.group(1).strip()

    # --- 5. Extract Vulnerabilities ---
    
    # We split the text to start looking after the header findings
    # Use "NETSHIELD AGGREGATED FINDINGS" as the start marker
    parts = clean_text.split("NETSHIELD AGGREGATED FINDINGS")
    body_text = parts[1] if len(parts) > 1 else clean_text

    # Regex to find vulnerability headers
    # Handles: "SSRF CRITICAL" or "Cross Site Scripting (Reflected) HIGH" or "SQL Injection HIGH CWE-CWE-89"
    # Logic: Look for a line ending with a Severity, optionally followed by CWE
    
    vuln_pattern = re.compile(
        r'(?P<title>.*?)\s+'  # Title (greedy match until severity)
        r'(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*' # Severity
        r'(?:CWE-(?P<cwe>[A-Za-z0-9\-]+))?\s*$' # Optional CWE (e.g. CWE-CWE-79)
        , re.MULTILINE
    )

    # Find all matches to calculate chunks
    matches = list(vuln_pattern.finditer(body_text))
    
    for i, match in enumerate(matches):
        start_idx = match.end()
        end_idx = matches[i+1].start() if i + 1 < len(matches) else len(body_text)
        
        # Extracted content block for this vulnerability
        content_block = body_text[start_idx:end_idx]
        
        # Clean up title
        raw_title = match.group("title").strip()
        # Remove "ZAP:" prefix if present for cleaner display
        clean_title = raw_title.replace("ZAP:", "").strip()
        
        item = {
            "title": clean_title,
            "severity": match.group("severity"),
            "cwe": match.group("cwe") if match.group("cwe") else "N/A",
            "description": "",
            "remediation": "",
            "evidence": "",
            "payload": ""
        }

        # --- Sub-field Extraction ---
        # 1. Parameter / Timestamp
        param_match = re.search(r'PARAMETER:\s*(.*?)(?=\s+TIMESTAMP|$)', content_block)
        if param_match: item["parameter"] = param_match.group(1).strip()

        # 2. Payload
        payload_match = re.search(r'PAYLOAD\s*\n(.*?)(?=\n[A-Z]|$)', content_block, re.DOTALL)
        if payload_match: item["payload"] = payload_match.group(1).strip()

        # 3. Evidence / URL (Handles both "EVIDENCE / URL" and "VULNERABLE URL")
        evidence_match = re.search(r'(?:EVIDENCE / URL|VULNERABLE URL)\s*\n(.*?)(?=\n[A-Z]|$)', content_block, re.DOTALL)
        if evidence_match: item["evidence"] = evidence_match.group(1).strip()

        # 4. Description
        desc_match = re.search(r'DESCRIPTION\s*\n(.*?)(?=\n[A-Z]|$)', content_block, re.DOTALL)
        if desc_match: 
            # Clean up newlines in description
            desc = desc_match.group(1).replace('\n', ' ').strip()
            item["description"] = desc

        # 5. Remediation (Usually in Detailed Insights section)
        rem_match = re.search(r'SUGGESTED REMEDIATION\s*\n(.*?)(?=\n[A-Z]|$)', content_block, re.DOTALL)
        if rem_match: 
            rem = rem_match.group(1).replace('\n', ' ').strip()
            item["remediation"] = rem

        report_data["vulnerabilities"].append(item)

    return report_data


def process_killchain_report_file(file_path: str) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Report not found: {file_path}")

    logger.info(f"Processing KillChain report: {file_path}")

    try:
        raw_text = extract_text_from_pdf(file_path)
        if not raw_text.strip():
            raise ValueError("Extracted text is empty.")

        report_data = parse_killchain_report(raw_text)

        report_data["file_metadata"] = {
            "filename": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }

        return report_data

    except Exception as e:
        logger.error(f"Error processing report {file_path}: {str(e)}")
        raise

if __name__ == "__main__":
    import sys
    # Testing block
    if len(sys.argv) > 1:
        fpath = sys.argv[1]
        try:
            if fpath.endswith(".txt"):
                with open(fpath, "r", encoding="utf-8") as f:
                    txt = f.read()
                print(json.dumps(parse_killchain_report(txt), indent=2))
            else:
                print(json.dumps(process_killchain_report_file(fpath), indent=2))
        except Exception as e:
            print(f"Failed: {e}")