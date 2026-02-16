import json
from typing import Dict, Any, List, Callable
import os
import sys
import dotenv
import uuid
import re
import logging

# Initialize module logger
logger = logging.getLogger(__name__)

# Load environment variables from a .env file (if present)
dotenv.load_dotenv()

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from chatbot_modules import config 

def _format_nmap_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for an LLM to analyze parsed NetShieldAI (Nmap) data,
    generating a professional report with markdown tables and remediation steps.
    """
    
    # --- 1. Extract Data from New JSON Structure ---
    metadata = parsed_data.get("scan_metadata", {})
    summary = parsed_data.get("summary", {})
    ports = parsed_data.get("open_ports", [])
    
    target_ip = metadata.get('target_ip', 'N/A')
    scan_args = metadata.get('scan_arguments', '')
    scan_date = metadata.get('scan_date', 'N/A')
    security_posture = metadata.get('security_posture', 'Unknown')
    
    ports_found_count = summary.get("ports_found", 0)
    threats_detected = summary.get("threats_detected", 0)

    # --- 2. Determine Scan Type Logic ---
    args_lower = scan_args.lower()
    if "-a" in args_lower:
        scan_type = "Aggressive Scan (-A) - OS/Version/Scripting"
    elif "-sv" in args_lower:
        scan_type = "Service Version Detection (-sV)"
    elif "--script vuln" in args_lower:
        scan_type = "Vulnerability Scan (--script vuln)"
    elif "-ss" in args_lower:
        scan_type = "TCP SYN Scan (Stealth) (-sS)"
    else:
        scan_type = "Standard TCP/Port Scan"

    # --- 3. Construct the LLM System Instructions ---
    prompt = (
        "You are **NetShieldAI's Senior Network Security Consultant**.\n"
        "Your task is to analyze the following Nmap scan data and generate a professional 'Network Assessment Briefing' for the user.\n\n"
        
        "### Guidelines:\n"
        "1. **Persona**: Be authoritative but accessible. Translate technical findings into real-world risk.\n"
        "2. **Format**: Use clean Markdown. Do not output raw JSON.\n"
        "3. **Data Source**: Use *only* the data provided in the '--- SCAN DATA ---' block below.\n\n"
        
        "### Required Report Structure:\n\n"
        
        "#### 1. Executive Summary\n"
        "   - Give a 2-3 sentence 'Bottom Line Up Front' verdict.\n"
        "   - Explicitly state if the network is **Secure**, **At Risk**, or **Critical**.\n"
        "   - Mention the total open ports and the specific Security Posture verdict from the tool.\n\n"
        
        "#### 2. Network Fingerprint (Table)\n"
        "   - Create a **Markdown Table** with the following columns:\n"
        "     - **Port / Protocol** (e.g., 80/TCP)\n"
        "     - **Service Name** (e.g., HTTP / lighttpd)\n"
        "     - **Function** (A brief, plain-English explanation of what this service does)\n"
        "     - **Risk Assessment** (e.g., 'Low - Standard Web Port', 'Medium - Unencrypted', 'High - Known Vulnerability')\n\n"
        
        "#### 3. Deep Dive Analysis\n"
        "   - Select the top 2-3 most notable findings (e.g., UPnP, Non-standard ports like 7443).\n"
        "   - Explain *why* these might be open (e.g., 'Port 1900 is often used for media streaming discovery...').\n"
        "   - If 'Threats Detected' > 0, prioritize those vulnerabilities.\n\n"
        
        "#### 4. Remediation & Hardening\n"
        "   - Provide 3 bullet points of actionable advice.\n"
        "   - Focus on reducing the attack surface (e.g., 'Disable UPnP if not needed', 'Ensure the router firmware is updated').\n\n"
        
        "--- SCAN DATA ---\n"
    )

    # --- 4. Inject Formatted Data Block ---
    prompt += f"Target Node: {target_ip}\n"
    prompt += f"Scan Date: {scan_date}\n"
    prompt += f"Scan Type: {scan_type}\n"
    prompt += f"Security Posture Verdict: {security_posture}\n"
    prompt += f"Threats Detected: {threats_detected}\n"
    prompt += f"Total Open Ports: {ports_found_count}\n\n"

    if ports:
        prompt += "### Open Ports Details:\n"
        for p in ports:
            # Handle cases where version might be same as name to avoid redundancy in text
            version_info = p.get('service_version', 'N/A')
            if version_info == p.get('service_name'):
                display_version = "Same as Service Name" 
            else:
                display_version = version_info

            prompt += (
                f"- Port {p.get('port')}/{p.get('protocol')} ({p.get('state')}): "
                f"Service='{p.get('service_name')}', "
                f"Version='{display_version}', "
                f"Process='{p.get('local_process')}'\n"
            )
    else:
        prompt += "No open ports were detected.\n"

    prompt += "\n--- END OF SCAN DATA ---\n"
    
    return prompt

def _format_traffic_analysis_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a prompt for an LLM to analyze TShark network traffic data,
    focusing on bandwidth usage, protocol distribution, and external connections.
    """
    
    # --- 1. Extract Core Data ---
    metadata = parsed_data.get("scan_metadata", {})
    metrics = parsed_data.get("traffic_metrics", {})
    protocols = parsed_data.get("protocol_hierarchy", [])
    conversations = parsed_data.get("active_conversations", [])
    security_insights = parsed_data.get("security_insights", "N/A")

    target_node = metadata.get('target_node', 'N/A')
    duration = metrics.get('duration_sec', 0)
    volume = metrics.get('data_volume', 'N/A')

    # --- 2. Construct LLM Instructions ---
    prompt = (
        "You are **NetShieldAI's Senior Network Traffic Analyst**.\n"
        "Your task is to analyze the following packet capture summary and generate a 'Traffic Inspection Briefing'.\n\n"
        
        "### Guidelines:\n"
        "1. **Objective**: Identify what the target device was doing during the capture window (e.g., browsing, streaming, idle).\n"
        "2. **Focus**: Highlight encrypted vs. unencrypted traffic and external vs. internal connections.\n"
        "3. **Format**: Use clean Markdown with tables.\n\n"
        
        "### Required Report Structure:\n\n"
        
        "#### 1. Traffic Snapshot\n"
        "   - Summarize the capture duration, data volume, and general throughput.\n"
        "   - Give a verdict on whether this looks like 'High Load' or 'Background Activity' based on the throughput.\n\n"
        
        "#### 2. Protocol Composition (Table)\n"
        "   - Create a **Markdown Table** with columns: **Protocol**, **Frame Count**, **Bytes**, **% of Traffic** (Estimate based on bytes).\n"
        "   - Briefly explain what the dominant protocol indicates (e.g., 'High TLS indicates secure web browsing').\n\n"
        
        "#### 3. Connection Analysis\n"
        "   - Analyze the 'Active Conversations'.\n"
        "   - Identify any **External IPs** (Public Internet) vs **Internal IPs** (Local Network).\n"
        "   - Flag any suspicious destination ports (standard are 80/443; others might be interesting).\n\n"
        
        "#### 4. Automated Security Insights\n"
        "   - State the automated tool's verdict found in the report.\n"
        "   - Add your own observation: Is the presence of unencrypted traffic (HTTP/DNS) a concern?\n\n"
        
        "--- PACKET CAPTURE DATA ---\n"
    )

    # --- 3. Inject Data ---
    prompt += f"Target Node: {target_node}\n"
    prompt += f"Capture Duration: {duration} seconds\n"
    prompt += f"Total Data Volume: {volume}\n"
    prompt += f"Throughput: {metrics.get('throughput', 'N/A')}\n"
    prompt += f"Automated Verdict: {security_insights}\n\n"

    # Protocol Block
    prompt += "### Protocol Hierarchy (Top Layers):\n"
    if protocols:
        # Filter out 'frame', 'eth', 'ip' usually to save tokens, or keep them if deep analysis needed.
        # Here we include them all but you might want to filter in production.
        for p in protocols:
            prompt += f"- {p['protocol'].upper()}: {p['frames']} frames, {p['bytes']} bytes\n"
    else:
        prompt += "No protocol data available.\n"

    # Conversation Block
    prompt += "\n### Active Conversations (Sample):\n"
    if conversations:
        for c in conversations:
            prompt += f"- {c['src_ip']}:{c['src_port']} <--> {c['dst_ip']}:{c['dst_port']}\n"
    else:
        prompt += "No conversation data available.\n"

    prompt += "\n--- END OF CAPTURE DATA ---\n"
    
    return prompt


def _format_zap_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Constructs a detailed prompt for an LLM to analyze ZAP scan data.
    
    Design Goals:
    1. Educational Tone: Explains *why* vulnerabilities matter in plain English.
    2. Table-Centric: Forces the output into structured tables for readability.
    3. Action-Oriented: Focuses on specific remediation steps.
    4. No Images: Strictly text and tables only.
    """
    
    # --- 1. LLM Persona and Constraints ---
    prompt = (
        "You are **NetShieldAI's Senior Web Application Security Consultant**.\n"
        "Your goal is to explain the provided OWASP ZAP scan results clearly, comprehensively, and professionally.\n\n"
        
        "### STRICT OUTPUT GUIDELINES:\n"
        "1. **NO IMAGES**: Do not include any images, diagrams, or placeholders for images.\n"
        "2. **USE TABLES**: You must use Markdown tables to organize the Executive Summary and the Remediation Checklist.\n"
        "3. **EDUCATIONAL TONE**: For every high/medium risk, explain the concept simply (as if to a junior developer) before providing the technical fix.\n"
        "4. **STRUCTURE**: Your response must follow the exact structure defined below.\n\n"
        
        "### REQUIRED RESPONSE STRUCTURE:\n"
        "**1. Executive Summary Table**\n"
        "   - Create a table with columns: [Scan Target, Scan Date, High Risks, Medium Risks, Low/Info Risks, Overall Status].\n\n"
        
        "**2. Critical Vulnerability Analysis (High & Medium Only)**\n"
        "   - For each finding, provide:\n"
        "     - **Vulnerability Name & Risk Level**\n"
        "     - **The 'Plain English' Explanation**: What is this vulnerability? (Explain concepts like SQLi or XSS simply).\n"
        "     - **Business Impact**: Why should the business care? (e.g., data theft, reputation loss).\n"
        "     - **Technical Details**: The specific URL/Parameter affected.\n"
        "     - **Technical Solution**: Specific code-level advice.\n\n"
        
        "**3. Prioritized Remediation Checklist (Table)**\n"
        "   - Create a table with columns: [Priority, Action Item, Affected Component, Difficulty].\n"
        "   - Rank the actions from most critical to least critical.\n\n"
        
        "**4. Low Risk & Best Practices**\n"
        "   - A bulleted summary of low-risk issues (e.g., headers, banners) that should be fixed for defense-in-depth.\n\n"
        
        "--- START OF ZAP RAW DATA ---\n"
    )

    # --- 2. Inject Metadata ---
    metadata = parsed_data.get("scan_metadata", {})
    prompt += f"## META INFORMATION\n"
    # Provide defaults to prevent errors if keys are missing
    prompt += f"Target URL: {metadata.get('target_url', 'N/A (See URLs in findings)')}\n"
    prompt += f"Generated At: {metadata.get('generated_at', 'N/A')}\n"
    prompt += f"Tool: {metadata.get('tool', 'ZAP Scanner')}\n\n"

    # --- 3. Inject Risk Summary ---
    # FIXED: JSON uses 'alert_summary'
    risk_counts = parsed_data.get("alert_summary", {})
    
    prompt += "## RISK COUNT SUMMARY\n"
    for risk_level, count in risk_counts.items():
        if risk_level != "Total":  # Optional: skip 'Total' if you only want specific risks
            prompt += f"- {risk_level}: {count}\n"
    prompt += "\n"

    # --- 4. Inject Detailed Vulnerabilities ---
    # FIXED: JSON uses 'findings', not 'vulnerabilities'
    vulnerabilities = parsed_data.get("findings", [])
    
    # FIXED: JSON uses 'risk_level' (Upper Case). Code logic updated to handle this safely.
    high_medium_vulns = [
        v for v in vulnerabilities 
        if v.get("risk_level", "").upper() in ["HIGH", "MEDIUM"]
    ]
    
    # FIXED: Added 'INFO' to list since your JSON has 'Info' count
    low_info_vulns = [
        v for v in vulnerabilities 
        if v.get("risk_level", "").upper() in ["LOW", "INFO", "INFORMATIONAL"]
    ]

    # A. High & Medium Detail Block
    if high_medium_vulns:
        prompt += "## HIGH & MEDIUM RISK FINDINGS (Detailed)\n"
        for i, vuln in enumerate(high_medium_vulns, 1):
            prompt += f"--- FINDING #{i} ---\n"
            prompt += f"Name: {vuln.get('name', 'N/A')}\n"
            prompt += f"Risk Level: {vuln.get('risk_level', 'N/A')}\n"
            # Removed CWE ID check as it is not in your JSON snippet
            prompt += f"Affected URL: {vuln.get('url', 'N/A')}\n"
            prompt += f"Description: {vuln.get('description', 'N/A')}\n"
            prompt += f"Suggested Solution: {vuln.get('solution', 'N/A')}\n\n"
    else:
        prompt += "## HIGH & MEDIUM RISK FINDINGS\nNo critical vulnerabilities found.\n\n"

    # B. Low & Info List Block
    if low_info_vulns:
        prompt += "## LOW & INFORMATIONAL FINDINGS (List)\n"
        unique_lows = set()
        for v in low_info_vulns:
            name = v.get('name', 'N/A')
            risk = v.get('risk_level', 'N/A')
            
            # Avoid duplicates in the summary list
            if name not in unique_lows:
                prompt += f"- {name} ({risk})\n"
                unique_lows.add(name)
        prompt += "\n"

    prompt += "--- END OF ZAP RAW DATA ---\n"
    
    return prompt

def _format_sslscan_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed, targeted prompt for the LLM based on SSLScan parsed data.
    
    Adapts to the "Assessment" JSON structure (nested protocols/ciphers).
    """
    
    # 1. Extract Helper Variables
    meta = parsed_data.get("metadata", {})
    cert = parsed_data.get("certificate_chain", {})
    config = parsed_data.get("server_configuration", {})
    vulns = parsed_data.get("vulnerabilities", [])
    protocols_dict = parsed_data.get("protocols", {})

    # 2. Identify Weak Ciphers (Logic: <128 bits or "DES/RC4" in name)
    weak_ciphers = []
    active_protocols = []
    
    for proto, ciphers in protocols_dict.items():
        active_protocols.append(proto)
        for c in ciphers:
            name = c.get("cipher", "")
            bits = c.get("bits", 0)
            if bits < 128 or "DES" in name or "RC4" in name or "MD5" in name:
                weak_ciphers.append(f"{proto}: {name} ({bits} bits)")

    # 3. Construct the Prompt
    prompt = (
        "As a Netshield's Senior Cybersecurity Analyst, analyze the following SSL/TLS "
        "Assessment Report data and provide a professional security audit.\n\n"
        
        "### ANALYSIS REQUIREMENTS\n"
        "You must organize your response into the following sections. "
        "**Use Markdown Tables** for clear data presentation where requested.\n\n"
        
        "1. **Executive Summary:**\n"
        "   - Provide a high-level status of the target (Secure, At Risk, or Critical).\n"
        "   - Mention the Overall Grade if available.\n\n"
        
        "2. **Critical Vulnerabilities (Table Required):**\n"
        "   - Create a table with columns: [Severity, Vulnerability Name, Impact].\n"
        "   - List all Medium/High severity findings found in the data.\n\n"
        
        "3. **Protocol & Cipher Analysis (Table Required):**\n"
        "   - Create a table with columns: [Protocol Version, Status, Remediation].\n"
        "   - specifically flag deprecated protocols (TLS 1.0, 1.1) as 'Risky'.\n"
        "   - Highlight any weak ciphers (e.g., DES, RC4) detected.\n\n"
        
        "4. **Configuration & Certificate Health:**\n"
        "   - Review server flags (Compression, Renegotiation).\n"
        "   - Review Certificate validity and Signature Algorithm.\n\n"
        
        "5. **Remediation Plan:**\n"
        "   - Provide a numbered list of technical steps to fix the issues.\n"
        "   - specific config commands or strategy (e.g., 'Disable TLS 1.0').\n\n"
        
        "--- START REPORT DATA ---\n"
    )

    # --- Inject Data ---

    # Metadata
    prompt += f"Target: {meta.get('target', 'Unknown')}\n"
    prompt += f"Scan Date: {meta.get('scan_date', 'Unknown')}\n"
    prompt += f"Overall Grade: {meta.get('grade', 'N/A')}\n\n"

    # Vulnerabilities
    if vulns:
        prompt += "DETECTED VULNERABILITIES:\n"
        for v in vulns:
            prompt += f"- [{v.get('severity')}] {v.get('name')}: {v.get('description')}\n"
    else:
        prompt += "DETECTED VULNERABILITIES: None explicitly listed.\n"

    # Weak Ciphers (Pre-calculated)
    if weak_ciphers:
        prompt += "\nWEAK CIPHERS DETECTED:\n"
        for wc in weak_ciphers:
            prompt += f"- {wc}\n"
    else:
        prompt += "\nWEAK CIPHERS DETECTED: None (<128 bits).\n"

    # Active Protocols List
    prompt += f"\nACTIVE PROTOCOLS:\n- {', '.join(active_protocols)}\n"

    # Server Configuration
    if config:
        prompt += "\nSERVER CONFIGURATION:\n"
        for k, v in config.items():
            prompt += f"- {k}: {v}\n"

    # Certificate Chain
    prompt += "\nCERTIFICATE DETAILS:\n"
    prompt += f"- Subject: {cert.get('subject', 'N/A')}\n"
    prompt += f"- Issuer: {cert.get('issuer', 'N/A')}\n"
    prompt += f"- Expiry: {cert.get('leaf_expiry', 'N/A')}\n"
    prompt += f"- Sig Algo: {cert.get('signature_algorithm', 'N/A')}\n"
    prompt += f"- Key: {cert.get('key_type', 'N/A')}\n"

    prompt += "--- END REPORT DATA ---\n\n"
    prompt += "Please generate the assessment now, ensuring tables are used for the vulnerability and protocol sections."

    return prompt

def _format_sql_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed, targeted prompt for the LLM based on SQL Injection parsed data.
    
    Adapts to the "NetShieldAI SQL Audit" JSON structure.
    """
    
    # 1. Extract Helper Variables
    meta = parsed_data.get("metadata", {})
    counts = parsed_data.get("summary_counts", {})
    fingerprint = parsed_data.get("database_fingerprint", {})
    vulns = parsed_data.get("vulnerabilities", [])

    # 2. Pre-process specific security flags
    # Check if the user is running as root/admin (common high-risk indicator)
    current_user = fingerprint.get("current_user", "")
    is_privileged = "root" in current_user or "admin" in current_user or "dba" in current_user
    
    db_status = meta.get("database_status", "Unknown")

    # 3. Construct the Prompt
    prompt = (
        "As a NetShieldAI's Senior Cybersecurity Analyst, analyze the following SQL Injection "
        "Audit Report data and provide a professional security assessment.\n\n"
        
        "### ANALYSIS REQUIREMENTS\n"
        "You must organize your response into the following sections. "
        "**Use Markdown Tables** for clear data presentation where requested.\n\n"
        
        "1. **Executive Summary:**\n"
        "   - Assess the immediate risk level (e.g., CRITICAL if database is exposed).\n"
        "   - Summarize the scope of compromise (how many injection types found).\n"
        "   - Explicitly state if the database is currently 'Exposed' or if Data Extraction is possible.\n\n"
        
        "2. **Target Fingerprint Analysis:**\n"
        "   - Analyze the detected DBMS and Version.\n"
        "   - \n"
        "   - Assess the impact of the 'Current User' privileges (highlight if root/admin).\n\n"
        
        "3. **Vulnerability Findings (Table Required):**\n"
        "   - Create a table with columns: [Risk Level, Injection Type, Payload Snippet, Recommended Fix].\n"
        "   - Summarize the specific techniques used (e.g., Boolean-based, Time-based).\n\n"
        
        "4. **Technical Remediation Plan:**\n"
        "   - Provide specific code-level fixes (e.g., Prepared Statements).\n"
        "   - Suggest infrastructure controls (e.g., WAF, Input Validation).\n\n"
        
        "--- START REPORT DATA ---\n"
    )

    # --- Inject Data ---

    # Metadata & Counts
    prompt += f"Target URL: {meta.get('target_url', 'Unknown')}\n"
    prompt += f"Scan Date: {meta.get('scan_date', 'Unknown')}\n"
    prompt += f"Database Status: {db_status}\n"
    prompt += f"Total Vulnerabilities: {counts.get('vulnerabilities_found', 0)}\n"
    prompt += f"Unique Injection Types: {counts.get('injection_types_count', 0)}\n\n"

    # Database Fingerprint
    prompt += "DATABASE FINGERPRINT:\n"
    prompt += f"- Technology: {fingerprint.get('detected_dbms', 'Unknown')}\n"
    prompt += f"- Version: {fingerprint.get('version', 'Unknown')}\n"
    prompt += f"- Current User: {current_user} {'(PRIVILEGED ACCOUNT)' if is_privileged else ''}\n"
    prompt += f"- Current DB: {fingerprint.get('current_database', 'Unknown')}\n\n"

    # Vulnerabilities List
    if vulns:
        prompt += "DETECTED INJECTION VECTORS:\n"
        for i, v in enumerate(vulns, 1):
            # Truncate very long payloads for the prompt to save tokens, if necessary
            payload = v.get('payload', 'N/A')
            if len(payload) > 150:
                payload = payload[:147] + "..."
                
            prompt += f"{i}. [{v.get('risk_level')}] Type: {v.get('injection_type')}\n"
            prompt += f"   - Title: {v.get('title')}\n"
            prompt += f"   - Payload: {payload}\n"
            prompt += f"   - Remediation Hint: {v.get('remediation')}\n"
    else:
        prompt += "DETECTED INJECTION VECTORS: None found.\n"

    prompt += "--- END REPORT DATA ---\n\n"
    prompt += "Please generate the assessment now, focusing on the critical nature of the exposed database."

    return prompt


def _format_killchain_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a strategic, full-spectrum security audit prompt based on the 
    Kill Chain Analysis report.
    """
    
    # --- 1. Extract Helper Variables ---
    meta = parsed_data.get("metadata", {})
    risks = parsed_data.get("risk_summary", {})
    phases = parsed_data.get("phase_analysis", {})
    recon = phases.get("recon", {})
    tech = phases.get("weaponization", {})
    vulns = parsed_data.get("vulnerabilities", [])

    # --- 2. Filter Critical/High Findings ---
    # We prioritize the most dangerous issues for the prompt context
    critical_issues = [v for v in vulns if v.get("severity", "").upper() in ["CRITICAL", "HIGH"]]
    
    # If no criticals, grab mediums to ensure we have something to discuss
    if not critical_issues:
        critical_issues = [v for v in vulns if v.get("severity", "").upper() == "MEDIUM"][:5]

    # --- 3. Construct the Prompt ---
    prompt = (
        "As a Netshield's Lead Penetration Tester, analyze the following Full-Spectrum Kill Chain "
        "Security Assessment data and provide a strategic executive report.\n\n"
        
        "### ANALYSIS REQUIREMENTS\n"
        "You must organize your response into the following sections using **Markdown**:\n\n"
        
        "1. **Executive Kill Chain Summary:**\n"
        "   - Provide a verdict on the target's posture (Critical, Poor, Moderate, or Secure).\n"
        "   - Summarize the attack surface identified in the Reconnaissance phase.\n"
        "   - Highlight the most dangerous exploit path discovered.\n\n"
        
        "2. **Phase 1: Reconnaissance & Exposure:**\n"
        "   - Analyze the open ports and discovered subdomains/URLs.\n"
        "   - Assessing if the exposed surface area is excessive.\n\n"
        
        "3. **Phase 2: Weaponization (Tech Stack Risks):**\n"
        "   - Analyze the detected technologies (Server, Language).\n"
        "   - Mention if the versions detected (e.g., Nginx, PHP) are outdated or widely targeted.\n\n"
        
        "4. **Phase 3: Exploitation (Critical Findings Table):**\n"
        "   - Create a Markdown table with columns: [Severity, Vulnerability, Impact].\n"
        "   - Focus on the 'Critical' and 'High' findings provided in the data.\n\n"
        
        "5. **Strategic Remediation Plan:**\n"
        "   - Provide a numbered list of prioritized fixes.\n"
        "   - Address the root causes (e.g., 'Sanitize Input' for SQLi, 'Update Server' for Version Leaks).\n\n"
        
        "--- START KILL CHAIN DATA ---\n"
    )

    # --- Inject Data ---

    # Global Metadata
    prompt += f"Target: {meta.get('target', 'Unknown')}\n"
    prompt += f"Scan Date: {meta.get('scan_date', 'Unknown')}\n"
    prompt += f"Profile: {meta.get('profile', 'Full Audit')}\n\n"

    # Risk Dashboard
    prompt += "RISK DASHBOARD:\n"
    prompt += f"- Critical: {risks.get('critical', 0)}\n"
    prompt += f"- High: {risks.get('high', 0)}\n"
    prompt += f"- Medium: {risks.get('medium', 0)}\n"
    prompt += f"- Total Findings: {risks.get('total', 0)}\n\n"

    # Phase 1: Recon
    prompt += "PHASE 1: RECONNAISSANCE DATA:\n"
    prompt += f"- IP Address: {recon.get('target_ip', 'Unknown')}\n"
    prompt += f"- Status: {recon.get('status', 'Unknown')}\n"
    prompt += f"- Open Ports: {', '.join(recon.get('open_ports', []))}\n"
    prompt += f"- Subdomains Found: {recon.get('subdomains_count', 0)}\n"
    prompt += f"- URLs Discovered: {recon.get('urls_count', 0)}\n\n"

    # Phase 2: Tech
    prompt += "PHASE 2: TECHNOLOGY STACK:\n"
    if tech:
        for k, v in tech.items():
            prompt += f"- {k.title()}: {v}\n"
    else:
        prompt += "- No technology fingerprinting data available.\n"
    prompt += "\n"

    # Phase 3: Vulnerabilities
    prompt += "PHASE 3: CONFIRMED VULNERABILITIES (Top Priorities):\n"
    if critical_issues:
        for v in critical_issues[:10]: # Limit to top 10 to avoid token overflow
            prompt += f"- [{v.get('severity')}] {v.get('title')}\n"
            if v.get('cwe') and v.get('cwe') != "N/A":
                prompt += f"  CWE: {v.get('cwe')}\n"
            if v.get('evidence'):
                prompt += f"  Evidence: {v.get('evidence')}\n"
            if v.get('description'):
                # Truncate description to keep it concise
                desc = v.get('description')[:200] + "..." if len(v.get('description')) > 200 else v.get('description')
                prompt += f"  Context: {desc}\n"
            prompt += "\n"
    else:
        prompt += "No Critical or High vulnerabilities detected. Review Medium/Low findings in full report.\n"

    prompt += "--- END KILL CHAIN DATA ---\n\n"
    prompt += "Please generate the strategic assessment now."

    return prompt


async def summarize_report_with_llm( # Added 'async' keyword here
    llm_instance: Any, 
    generate_response_func: Callable[[Any, str, int], str], 
    parsed_data: Dict[str, Any], 
    report_type: str
) -> str:
    """
    Generates a natural language summary and remediation steps for a parsed security report
    using the provided LLM instance and its generation function.

    Args:
        llm_instance (Any): The loaded LLM model instance (e.g., Llama, GenerativeModel).
        generate_response_func (Callable): The function responsible for generating a response
                                           from the given LLM instance, prompt, and max_tokens.
        parsed_data (Dict[str, Any]): The structured dictionary parsed from the report.
        report_type (str): The type of the report.

    Returns:
        str: The generated explanation and remediation steps from the LLM.
    """
    prompt = ""
    if report_type.lower() == "nmap":
        prompt = _format_nmap_summary_prompt(parsed_data)
    elif report_type.lower() == "zap":
        prompt = _format_zap_summary_prompt(parsed_data)
    elif report_type.lower() == "sslscan":
        prompt = _format_sslscan_summary_prompt(parsed_data)
    elif report_type.lower() == "pcap":
        prompt = _format_traffic_analysis_prompt(parsed_data)
    elif report_type.lower() == "sql":
        prompt = _format_sql_summary_prompt(parsed_data)
    elif report_type.lower() == "killchain":
        prompt = _format_killchain_summary_prompt(parsed_data)
    else:
        logger.warning(f"Unsupported report type: {report_type}")


    logger.info(f"Generating summary for {report_type} report...")

    try:
        # Call the passed generate_response_func
        llm_response = await generate_response_func(llm_instance, prompt, max_tokens=config.DEFAULT_SUMMARIZE_MAX_TOKENS)
        
        # If the response is a dict (Gemini), extract 'text'
        if isinstance(llm_response, dict):
            return llm_response.get("text", "")
            
        return llm_response
    except Exception as e:
        logger.error(f"Error generating LLM response for {report_type} summary: {e}")
        return f"Error generating summary for {report_type} report. Please try again."



async def summarize_chat_history_segment( # Added 'async' keyword here
    llm_instance: Any, 
    generate_response_func: Callable[[Any, str, int], str], # New argument: the specific generate_response function
    history_segment: List[Dict[str, str]], 
    max_tokens: int = config.DEFAULT_SUMMARIZE_MAX_TOKENS
) -> str:
    """
    Uses the LLM to summarize a segment of the chat history.

    Args:
        llm_instance (Any): The loaded LLM model instance (e.g., Llama, GenerativeModel).
        generate_response_func (Callable): The function responsible for generating a response
                                           from the given LLM instance, prompt, and max_tokens.
        history_segment (List[Dict[str, str]]): A list of message dictionaries
                                                    (e.g., [{'role': 'user', 'content': '...'}, ...]).
        max_tokens (int): Maximum tokens for the summary.

    Returns:
        str: A concise summary of the conversation segment.
    """
    if not history_segment:
        return ""

    # Construct the prompt for summarization
    summarization_prompt = (
        "Please summarize the following conversation history concisely. "
        "Focus on the main topics discussed and any key questions or conclusions.\n\n"
        "--- Conversation History to Summarize ---\n"
    )
    
    # Concatenate the history segment into a string for the LLM
    for msg in history_segment:
        summarization_prompt += f"{msg['role'].capitalize()}: {msg['content']}\n"
    
    summarization_prompt += "--- End Conversation History ---\n\nSummary:"

    logger.info(f"Summarizing chat history segment ({len(history_segment)} turns)...")

    try:
        # Call generate_response_func (now awaited as it's an async function)
        summary_response = await generate_response_func(llm_instance, summarization_prompt, max_tokens=max_tokens)
        
        # If the response is a dict (Gemini), extract 'text'
        if isinstance(summary_response, dict):
            return summary_response.get("text", "").strip()

        return summary_response.strip()
    except Exception as e:
        logger.error(f"Error generating history summary: {e}")
        return "(Error summarizing previous conversation.)"
