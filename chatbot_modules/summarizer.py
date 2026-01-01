import json
from typing import Dict, Any, List, Callable
import os
import sys
import dotenv
import uuid
import re

# Load environment variables from a .env file (if present)
dotenv.load_dotenv()

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from chatbot_modules import config 

# --- Main Router Function ---
def _format_nmap_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for an LLM to analyze parsed Nmap data,
    ensuring a structured, professional, and actionable final summary.
    """
    
    # --- LLM Instructions ---
    prompt = (
        "You are a **senior network security consultant** drafting an executive briefing for a Network Operations Team. "
        "Your goal is to provide a clear analysis and actionable steps based on the Nmap scan results below.\n"
        "Based *only* on the data provided within the '--- Nmap Report Data ---' block, you must complete the following four sections:\n"
        "1.  **Executive Summary**: Write a concise, non-technical summary of the scan. State the target, the host status, the total number of open ports found, and the key network services exposed (e.g., SMB/CIFS, RPC).\n"
        "2.  **Scan Analysis**: Detail the **type of scan** performed (e.g., Aggressive, SYN Scan) and explain the implications of the Host Status (e.g., 'Up' means the host is active and responsive).\n"
        "3.  **High-Risk Service Review**: List every **Open** port. For services like **135, 139, 445 (RPC, NetBIOS, SMB/CIFS)**, explain the **vulnerability exposure** (e.g., potential for lateral movement, credential harvesting, or exploitation of protocol vulnerabilities).\n"
        "4.  **Remediation Steps**: Provide practical, actionable remediation steps for securing the network services exposed. **Group recommendations by action (e.g., Firewalling, Patching, Configuration)**.\n\n"
        
        "Format your response using clear headings: 'Executive Summary', 'Scan Analysis', 'High-Risk Service Review', and 'Remediation Steps'.\n\n"
        "--- Nmap Report Data ---\n\n"
    )

    # --- Metadata Section ---
    metadata = parsed_data.get("scan_metadata", {})
    target_ip = metadata.get('target_ip', 'N/A')
    host_status = metadata.get('host_status', 'N/A')
    scan_args = metadata.get('scan_arguments', '')
    
    # Determine the Scan Type (Logic moved inline)
    args_lower = scan_args.lower()
    if "-a" in args_lower:
        scan_type = "Aggressive Scan (-A) - Includes OS/Version/Scripting/Traceroute"
    elif "-sv" in args_lower:
        scan_type = "Service Version Detection (-sV)"
    elif "-ss" in args_lower:
        scan_type = "TCP SYN Scan (Stealth) (-sS)"
    elif "-st" in args_lower:
        scan_type = "TCP Connect Scan (-sT)"
    elif "-sn" in args_lower or "-sp" in args_lower:
        scan_type = "Ping Scan (Host Discovery)"
    elif "-sN" in args_lower or "-sF" in args_lower or "-sX" in args_lower:
        scan_type = "Stealth/FIN/Xmas Scans"
    else:
        scan_type = "Standard TCP/Port Scan"


    prompt += "## Scan Metadata\n"
    prompt += f"- **Target IP**: {target_ip}\n"
    prompt += f"- **Host Status**: {host_status}\n"
    prompt += f"- **Scan Date**: {metadata.get('scan_date', 'N/A')}\n"
    
    # Include the determined Scan Type
    prompt += f"- **Scan Type**: {scan_type}\n"
    prompt += f"- **Full Arguments**: {scan_args}\n\n"

    # --- Summary and Port Counts ---
    summary = parsed_data.get("summary", {})
    open_ports_count = summary.get("open_ports_count", 0)
    
    prompt += "## Open Port Summary\n"
    prompt += f"- **Total Open Ports Detected**: {open_ports_count}\n\n"
    
    # --- Detailed Port Findings ---
    ports = parsed_data.get("open_ports", [])

    if ports:
        prompt += "## Detailed Open Port Findings\n"
        for i, port_data in enumerate(ports, 1):
            prompt += f"### {i}. Port {port_data.get('port', 'N/A')} / {port_data.get('protocol', 'N/A')}\n"
            prompt += f"- **Service**: {port_data.get('service_name', 'N/A')}\n"
            prompt += f"- **Version**: {port_data.get('service_version', 'N/A')}\n"
            prompt += f"- **State**: {port_data.get('state', 'N/A')}\n"
            prompt += f"- **Local Process**: {port_data.get('local_process', 'N/A')}\n\n"
    else:
        prompt += "## Detailed Open Port Findings\n\nNo open ports were detected on the target.\n\n"


    prompt += "--- End of Report Data ---\n"
    
    return prompt


def _format_zap_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a highly optimized and detailed prompt for an LLM to analyze parsed ZAP data,
    ensuring a structured, professional, and actionable final summary.
    """
    
    # --- LLM Instructions ---
    prompt = (
        "You are a **senior cybersecurity consultant** drafting an executive briefing for a development team. "
        "Your goal is to provide a clear analysis and actionable steps based on the ZAP scan results below.\n"
        "Based *only* on the data provided within the '--- ZAP Report Data ---' block, you must complete the following four sections:\n"
        "1.  **Executive Summary**: Write a concise, non-technical summary of the scan results. State the target, the **overall risk posture** (e.g., Moderate Risk), and the most critical security category exposed (e.g., Missing Security Headers).\n"
        "2.  **Key Findings**: Detail all **High and Medium risk** vulnerabilities. For each, clearly state the **CWE ID** (if available) and explain the **potential business impact** (e.g., session hijacking, data leakage) on the application.\n"
        "3.  **Remediation Steps**: Provide practical, actionable remediation steps for each High and Medium risk finding. **Structure these steps using bullet points, grouped by Phase (Architecture, Implementation, etc.)** as provided in the Solution section.\n"
        "4.  **Low-Priority Context**: Briefly summarize the general themes (e.g., 'Information Leakage', 'Missing Security Controls') found in the Low and Informational alerts.\n\n"
        
        "Format your response using clear headings: 'Executive Summary', 'Key Findings', and 'Remediation Steps'.\n\n"
        "--- ZAP Report Data ---\n\n"
    )

    # --- Metadata Section ---
    metadata = parsed_data.get("scan_metadata", {})
    target_url = metadata.get('target_url', 'N/A')
    tool_info = metadata.get('tool', 'ZAP Scanner')

    prompt += "## Scan Metadata\n"
    prompt += f"- **Target Site**: {target_url}\n"
    prompt += f"- **Generated At**: {metadata.get('generated_at', 'N/A')}\n"
    prompt += f"- **Scan Tool/Version**: {tool_info}\n\n"

    # --- Summary Risk Counts & Inconsistency Note ---
    summary = parsed_data.get("summary", {})
    risk_counts = summary.get("risk_counts", {})
    
    prompt += "## Risk Distribution Summary\n"
    for risk_level, count in risk_counts.items():
        prompt += f"- **{risk_level}**: {count} alerts\n"
    prompt += f"- **Total Alerts (Report Summary)**: {summary.get('total_alerts', 0)}\n"
    
    # Add note about common summary table inconsistency
    prompt += "> **Note**: The detailed vulnerability list contains {len(parsed_data.get('vulnerabilities', []))} unique findings, including Informational alerts, which may exceed the 'Total Alerts' count.\n\n"

    # --- Alerts by Type and Prevalence ---
    alerts_by_name = summary.get("alerts_by_name", [])
    if alerts_by_name:
        prompt += "## Alerts by Type and Prevalence\n"
        for alert in alerts_by_name:
            prompt += f"- **{alert.get('name', 'N/A')}** (**{alert.get('risk_level', 'N/A')}**): {alert.get('instances_count', 0)} Instances\n"
        prompt += "\n"

    # --- Detailed High and Medium Risk Vulnerabilities ---
    vulnerabilities = parsed_data.get("vulnerabilities", [])
    high_medium_vulnerabilities = [v for v in vulnerabilities if v.get("risk") in ["High", "Medium"]]
    low_info_vulnerabilities = [v for v in vulnerabilities if v.get("risk") in ["Low", "Informational"]]

    if high_medium_vulnerabilities:
        prompt += "## Detailed High and Medium Risk Vulnerabilities\n\n"
        for i, vuln in enumerate(high_medium_vulnerabilities, 1):
            prompt += f"### {i}. {vuln.get('name', 'N/A')}\n"
            prompt += f"- **Risk Level**: {vuln.get('risk', 'N/A')}\n"
            
            # Include CWE ID for deeper context
            cwe_id = vuln.get('cwe_id')
            prompt += f"- **CWE ID**: {cwe_id if cwe_id else 'N/A'}\n"
            
            prompt += f"- **Affected URL**: {vuln.get('url', 'N/A')}\n"
            prompt += f"- **Description**: {vuln.get('description', 'N/A')}\n"
            
            # --- Formatted Solution for LLM Remediation ---
            # Pre-format the solution into a clean, parseable list for the LLM
            solution_text = vuln.get('solution', 'N/A')
            
            # Use regex to find and group solutions by Phase header if present (e.g., 'Phase: Architecture')
            solution_groups = re.findall(r"(Phase: [^\n]+)(.*?)(?=Phase: |Reference:|\Z)", solution_text, re.DOTALL)
            
            if solution_groups:
                prompt += "- **Remediation Details (by Phase)**:\n"
                for phase, details in solution_groups:
                    phase = phase.strip()
                    details = details.strip()
                    # Clean the details and present as bullet points
                    clean_details = [line.strip() for line in details.split('\n') if line.strip()]
                    
                    # Ensure the Phase header is bolded for the LLM to structure by
                    prompt += f"  - **{phase}**:\n"
                    for detail in clean_details:
                        # Convert asterisks/dashes to clean bullet points
                        detail = re.sub(r'^\s*[\*\-]', '', detail).strip()
                        prompt += f"    - {detail}\n"
            else:
                # Fallback to presenting the solution as a single block if phases aren't found
                prompt += f"- **Raw Solution**: {solution_text}\n"

            prompt += "\n"
    else:
        prompt += "## Detailed High and Medium Risk Vulnerabilities\n\nNo High or Medium risk vulnerabilities were identified.\n\n"

    # --- Low Risk & Informational Findings ---
    if low_info_vulnerabilities:
        prompt += "## Low Risk & Informational Findings\n"
        prompt += "The following low-risk and informational issues were noted:\n"
        unique_low_info_names = sorted(list(set(v.get('name', 'N/A') for v in low_info_vulnerabilities)))
        for name in unique_low_info_names:
            # Include risk level for context
            risk = next(v.get('risk') for v in low_info_vulnerabilities if v.get('name') == name)
            prompt += f"- **{name}** ({risk})\n"
        prompt += "\n"

    prompt += "--- End of Report Data ---\n"
    
    return prompt

def _format_sslscan_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed, targeted prompt for the LLM based on SSLScan parsed data
    (NetShieldAI format). Focuses on mandatory analysis points: vulnerabilities, 
    protocols, ciphers, and certificate health.

    Args:
        parsed_data (Dict[str, Any]): The structured dictionary from the parser.

    Returns:
        str: A detailed prompt ready for the LLM.
    """
    prompt = (
        "As a senior cybersecurity analyst, analyze the following SSL/TLS "
        "Vulnerability Scan Report and provide a comprehensive, actionable assessment.\n"
        "The analysis must strictly adhere to the data provided below and be organized "
        "under the specified headings. Pay special attention to Medium or High severity findings.\n\n"
        "--- SSLScan Report Analysis Requirements ---\n"
        "1. **Concise Summary:** An overview of the target, scan date, and overall security posture.\n"
        "2. **Key Findings (Categorized):** List all vulnerabilities (Medium/High priority) and deviations from best practices (e.g., weak protocols, ciphers).\n"
        "3. **Implications:** Explain the direct security risk of each key finding (e.g., data interception, downgrade attacks).\n"
        "4. **Remediation Steps:** Provide clear, prioritized, and technical remediation actions.\n"
        "--- End Requirements ---\n\n"
        "--- SSLScan Report Data ---\n"
    )

    # 1. Scan Metadata (Streamlined)
    metadata = parsed_data.get("scan_metadata", {})
    prompt += f"Target Host: {metadata.get('target_host', 'N/A')}\n"
    prompt += f"Port: {metadata.get('port', 'N/A')}\n"
    prompt += f"Scan Date: {metadata.get('scan_date', 'N/A')}\n\n"

    # 2. Detected Vulnerabilities (CRITICAL SECTION ADDED)
    vulnerabilities = parsed_data.get("vulnerabilities", [])
    if vulnerabilities:
        prompt += "Vulnerabilities Found:\n"
        for vuln in vulnerabilities:
            prompt += f" - [{vuln.get('severity', 'N/A')}] {vuln.get('description', 'N/A')}\n"
    else:
        prompt += "Vulnerabilities Found: None explicitly listed (beyond cipher acceptance list).\n"

    # 3. Protocols
    protocols = parsed_data.get("protocols", [])
    if protocols:
        prompt += "\nEnabled/Disabled Protocols:\n"
        for proto in protocols:
            prompt += f" - {proto.get('name', 'N/A')}: {proto.get('status', 'N/A')}\n"
    
    # 4. Server Configuration (Security Features)
    # Using the populated 'server_configuration' field from the parser
    server_config = parsed_data.get("server_configuration", {})
    if server_config:
        prompt += "\nServer Configuration & Security Features:\n"
        for feature, status in server_config.items():
            prompt += f" - {feature.replace('_', ' ').title()}: {status}\n"

    # 5. Supported Ciphers (Focusing on Weakness)
    ciphers = parsed_data.get("supported_ciphers", [])
    if ciphers:
        prompt += "\nSupported Server Ciphers:\n"
        weak_ciphers = [
            f"{c.get('name')} ({c.get('bits')} bits) on {c.get('protocol')}" 
            for c in ciphers if c.get('bits', 0) < 128 or 'des' in c.get('name', '').lower()
        ]
        
        if weak_ciphers:
             prompt += f"Weak/Legacy Ciphers Accepted (Priority Review):\n"
             for cipher_detail in weak_ciphers:
                 prompt += f"   - {cipher_detail}\n"
        else:
             prompt += "Weak/Legacy Ciphers Accepted: None found below 128 bits.\n"


    # 6. SSL Certificate
    certificate = parsed_data.get("ssl_certificate", {})
    if certificate:
        prompt += "\nSSL Certificate Details:\n"
        # Only include fields relevant to security or expiration review
        prompt += f" - Common Name: {certificate.get('common_name', 'N/A')}\n"
        prompt += f" - Issuer: {certificate.get('issuer', 'N/A')}\n"
        prompt += f" - Signature Algorithm: {certificate.get('signature_algorithm', 'N/A')}\n"
        prompt += f" - Key Details: {certificate.get('key_details', 'N/A')}\n"
        prompt += f" - Valid Until: {certificate.get('not_valid_after', 'N/A')}\n"
        # Note: 'key_exchange_groups' is excluded as it was empty in the report data.

    prompt += "\n--- End SSLScan Report Data ---\n"
    prompt += "Please ensure the response is concise, highly technical, and strictly follows the four required section headings."
    
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
    else:
        print(f"Warning: Unsupported report type")


    print(f"\n--- Sending formatted prompt to LLM for {report_type} report summary ---")

    try:
        # Call the passed generate_response_func
        llm_response = await generate_response_func(llm_instance, prompt, max_tokens=config.DEFAULT_SUMMARIZE_MAX_TOKENS)
        return llm_response
    except Exception as e:
        print(f"Error generating LLM response for {report_type} summary: {e}")
        return f"Error generating summary for {report_type} report. Please try again. Details: {e}"



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

    print(f"\n--- Sending chat history segment to LLM for summarization (length: {len(summarization_prompt)} chars) ---")

    try:
        # Call generate_response_func (now awaited as it's an async function)
        summary_response = await generate_response_func(llm_instance, summarization_prompt, max_tokens=max_tokens)
        return summary_response.strip()
    except Exception as e:
        print(f"Error generating history summary: {e}")
        return "(Error summarizing previous conversation. Some context may be lost.)"
