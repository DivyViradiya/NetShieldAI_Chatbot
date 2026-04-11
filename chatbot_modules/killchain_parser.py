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
    target_match = re.search(r'TARGET ASSET\s*\n?([^\n]+)', clean_text)
    if target_match:
        report_data["metadata"]["target"] = target_match.group(1).split("AUDIT PROFILE")[0].strip()

    profile_match = re.search(r'AUDIT PROFILE\s*\n?([^\n]+)', clean_text)
    if profile_match:
        report_data["metadata"]["profile"] = profile_match.group(1).split("AGGRESSION")[0].strip()

    agg_match = re.search(r'AGGRESSION\s*\n?([^\n]+)', clean_text)
    if agg_match:
        report_data["metadata"]["aggression"] = agg_match.group(1).split("AUDIT DATE")[0].strip()

    # Scan Date
    date_match = re.search(r'AUDIT DATE\s*\n?(\d{4}-\d{2}-\d{2})\s*\n?(\d{2}:\d{2}:\d{2})', clean_text)
    if date_match:
        report_data["metadata"]["scan_date"] = f"{date_match.group(1)} {date_match.group(2)}"

    # --- 3. Extract Risk Summary ---
    def extract_count(label):
        match = re.search(rf'(\d+)\s*{label}', clean_text, re.IGNORECASE)
        return int(match.group(1)) if match else 0

    report_data["risk_summary"] = {
        "total": extract_count("CRITICAL") + extract_count("HIGH RISK") + extract_count("MEDIUM RISK") + extract_count("LOW / INFO"),
        "critical": extract_count("CRITICAL"),
        "high": extract_count("HIGH RISK"),
        "medium": extract_count("MEDIUM RISK"),
        "low_info": extract_count("LOW / INFO")
    }
    
    # Overwrite total if explicitly found
    total_found = re.search(r'TOTAL FINDINGS\s*(\d+)', clean_text)
    if total_found:
         report_data["risk_summary"]["total"] = int(total_found.group(1))

    # --- 4. Extract Phase Analysis ---

    # Phase 1: RECON & DISCOVERY
    recon_section = re.search(r'PHASE 1: RECON & DISCOVERY(.*?)(?=PHASE 2)', clean_text, re.DOTALL)
    if recon_section:
        r_text = recon_section.group(1)
        ip_match = re.search(r'Target IP:\s*([^\n]+)', r_text)
        if ip_match: report_data["phase_analysis"]["recon"]["target_ip"] = ip_match.group(1).strip()
        
        sub_match = re.search(r'Subdomains Found:\s*(\d+)', r_text)
        if sub_match: report_data["phase_analysis"]["recon"]["subdomains_count"] = int(sub_match.group(1))
        
        # Technology Stack
        tech_match = re.search(r'TECHNOLOGY STACK\s*\n?Server:\s*([^\n]+)', r_text, re.DOTALL)
        if tech_match: report_data["phase_analysis"]["recon"]["server"] = tech_match.group(1).strip()

    # Phase 2: NETWORK AUDIT
    net_section = re.search(r'PHASE 2: NETWORK AUDIT(.*?)(?=PHASE 3)', clean_text, re.DOTALL)
    if net_section:
        n_text = net_section.group(1)
        status_match = re.search(r'Status:\s*([^\n]+)', n_text)
        if status_match: report_data["phase_analysis"]["network_audit"] = {"status": status_match.group(1).strip()}
        
        os_match = re.search(r'OS Fingerprint:\s*([^\n]+)', n_text)
        if os_match: report_data["phase_analysis"]["network_audit"]["os"] = os_match.group(1).strip()
        
        ports_match = re.search(r'OPEN PORTS \((\d+)\)\s*\n?(.*?)▸', n_text, re.DOTALL)
        if ports_match:
            port_text = ports_match.group(2).replace('\n', ' ')
            report_data["phase_analysis"]["network_audit"]["open_ports"] = re.findall(r'\d+/\w+ \([^\)]+\)', port_text)

    # Phase 3: WEB APPLICATION AUDIT
    web_section = re.search(r'PHASE 3: WEB APPLICATION AUDIT(.*?)(?=PHASE 4)', clean_text, re.DOTALL)
    if web_section:
        w_text = web_section.group(1)
        waf_match = re.search(r'WAF Detected:\s*([^\n]+)', w_text)
        if waf_match: report_data["phase_analysis"]["web_audit"] = {"waf": waf_match.group(1).strip()}
        
        surface_match = re.search(r'Surface Area:\s*(.*?)(?=API|$)', w_text, re.DOTALL)
        if surface_match: report_data["phase_analysis"]["web_audit"]["surface"] = surface_match.group(1).strip()

    # Phase 4: TRAFFIC ANALYSIS
    traffic_section = re.search(r'PHASE 4: TRAFFIC ANALYSIS(.*?)(?=AGGREGATED SECURITY FINDINGS)', clean_text, re.DOTALL)
    if traffic_section:
        t_text = traffic_section.group(1)
        packets_match = re.search(r'Captured Packets:\s*(\d+)', t_text)
        if packets_match: report_data["phase_analysis"]["traffic_audit"] = {"packets": int(packets_match.group(1))}

    # --- 5. Extract Vulnerabilities ---
    
    # Split after "AGGREGATED SECURITY FINDINGS"
    parts = clean_text.split("AGGREGATED SECURITY FINDINGS")
    body_text = parts[1] if len(parts) > 1 else clean_text

    # Regex to find vulnerability headers
    # Format: [Title] [Risk] [CWE] [Module]
    vuln_pattern = re.compile(
        r'(?P<title>.*?)\s+'  # Title (greedy match until severity)
        r'(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+' # Severity
        r'(?P<cwe>CWE-[^\s]+)\s+' # CWE
        r'(?P<module>NETSHIELD AI|ZAP|NMAP|.*?)' # Tool/Module
        r'(?=\s*\n|$)', 
        re.MULTILINE
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
        # Remove artifacts like "LOW 1 FINDING(S)"
        clean_title = re.sub(r'^[A-Z]+\s+\d+\s+FINDING\(S\)', '', raw_title).strip()
        # Remove "ZAP:" prefix if present
        clean_title = clean_title.replace("ZAP:", "").strip()
        
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
        # 4. Description
        desc_match = re.search(r'Description:\s*\n?(.*?)(?=Remediation:|ML Risk Assessment:|$)', content_block, re.DOTALL)
        if desc_match: 
            item["description"] = desc_match.group(1).replace('\n', ' ').strip()

        # 5. Remediation
        rem_match = re.search(r'Remediation:\s*\n?(.*?)(?=ML Risk Assessment:|$|NetShieldAI Security Report)', content_block, re.DOTALL)
        if rem_match: 
            item["remediation"] = rem_match.group(1).replace('\n', ' ').strip()

        # 6. ML Risk Assessment
        ml_match = re.search(r'ML Risk Assessment\s*\n?([\d\.]+)\s*/\s*10\.0', content_block)
        if ml_match:
            item["ml_threat_score"] = float(ml_match.group(1))
            
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