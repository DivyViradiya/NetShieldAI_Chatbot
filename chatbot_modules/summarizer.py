import json
from typing import Dict, Any, List, Callable
import os
import sys
import dotenv
import uuid

# Load environment variables from a .env file (if present)
dotenv.load_dotenv()

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from chatbot_modules import config 



from typing import Dict, Any

def _create_aggressive_scan_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Creates a comprehensive analysis prompt for a parsed Aggressive Scan report.
    This function includes every piece of extracted data for a thorough assessment.
    """
    # Extract metadata for easy access
    metadata = parsed_data.get("scan_metadata", {})
    
    # All reports in your example have a single host, so we'll focus on the first one.
    if not parsed_data.get("hosts"):
        return "Error: Parsed data contains no host information to generate a prompt."
    host = parsed_data["hosts"][0]

    # Start building the detailed prompt
    prompt = (
        "As a senior cybersecurity analyst, provide a comprehensive security assessment for the following Nmap Aggressive Scan report.\n\n"
        "**Your analysis must be detailed and cover these specific sections:**\n"
        "1.  **Executive Summary:** A high-level overview of the target's security posture, key risks, and the most critical findings.\n"
        "2.  **Detailed Findings & Vulnerability Analysis:**\n"
        "    - For each **Open Port**, identify the service and its version. Analyze this combination for known vulnerabilities (e.g., outdated software, default configurations, dangerous enabled methods).\n"
        "    - Analyze the **OS Guesses**. Is the likely OS modern and supported? Correlate this with the running services.\n"
        "    - Evaluate the **Script Outputs** (e.g., ssl-cert details, http-title) for misconfigurations or information leakage.\n"
        "3.  **Network Infrastructure Assessment:**\n"
        "    - Analyze the **Traceroute** path. Are there any unexpected or suspicious hops? Comment on the network distance.\n"
        "    - Discuss the significance of the **rDNS record** and the list of **Other Associated Addresses**. Does this suggest a load-balanced or CDN-hosted environment?\n"
        "4.  **Actionable Remediation Plan:** Provide a prioritized list of concrete steps to mitigate all identified risks. Recommendations should be specific (e.g., 'Upgrade service X from version 1.2 to 1.5,' not just 'patch services').\n\n"
        "--- Full Aggressive Scan Report Data ---\n\n"
        f"## Scan Metadata\n"
        f"- **Source File:** {metadata.get('source_file', 'N/A')}\n"
        f"- **Scan Type:** {metadata.get('scan_type', 'N/A')}\n"
        f"- **Timestamp:** {metadata.get('timestamp', 'N/A')}\n"
        f"- **Initiated By:** {metadata.get('initiated_by', 'N/A')}\n"
        f"- **Scan Summary:** {metadata.get('summary', 'N/A')}\n\n"
        
        f"## Target Information\n"
        f"- **Primary IP Address:** {host.get('ip_address', 'N/A')}\n"
        f"- **Status:** {host.get('status', 'N/A')}\n"
        f"- **rDNS Record:** {host.get('rdns_record', 'N/A')}\n"
        f"- **Other Associated Addresses:** {', '.join(host.get('other_addresses', [])) or 'None Found'}\n\n"
        
        f"## Open Ports & Services\n"
    )
    
    if not host.get("ports"):
        prompt += "- No open ports found.\n\n"
    else:
        for port in host.get("ports", []):
            prompt += (
                f"- **Port:** {port.get('port_id', 'N/A')}\n"
                f"  - **State:** {port.get('state', 'N/A')}\n"
                f"  - **Service:** {port.get('service', 'N/A')}\n"
                f"  - **Version:** {port.get('version', 'N/A')}\n"
            )
            if port.get("script_outputs"):
                prompt += "  - **Script Outputs:**\n"
                for output in port.get("script_outputs", []):
                    prompt += f"    - {output}\n"
            prompt += "\n"
            
    prompt += "## OS & Network Details\n"
    os_info = host.get("os_detection", {})
    if not os_info:
        prompt += "- No OS detection data available.\n\n"
    else:
        prompt += f"- **OS Detection Warning:** {os_info.get('warning', 'None')}\n"
        prompt += f"- **Match Status:** {os_info.get('match_status', 'N/A')}\n"
        prompt += "- **Aggressive OS Guesses:**\n"
        for guess in os_info.get("guesses", []):
            prompt += f"  - {guess}\n"
        prompt += "\n"

    prompt += "## Traceroute Information\n"
    trace_info = host.get("traceroute", [])
    if not trace_info:
        prompt += "- No traceroute data available.\n"
    else:
        prompt += f"- **Network Distance:** {host.get('network_distance', 'N/A')} hops\n"
        for hop in trace_info:
            prompt += f"  - **Hop {hop.get('hop')}:** {hop.get('address', 'N/A')} (RTT: {hop.get('rtt', 'N/A')})\n"
            
    prompt += "\n--- End of Report Data ---\n"
    
    return prompt

# --- Prompt Builder for OS Detection Scan (-O) ---
def _create_os_detection_scan_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Creates a comprehensive analysis prompt for a parsed OS Detection Scan report.
    This function includes every piece of extracted data for a thorough assessment.
    """
    # Extract metadata for easy access
    metadata = parsed_data.get("scan_metadata", {})

    # Assume a single host per report as per the examples
    if not parsed_data.get("hosts"):
        return "Error: Parsed data contains no host information to generate a prompt."
    host = parsed_data["hosts"][0]
    os_info = host.get("os_detection", {})

    # Start building the detailed prompt
    prompt = (
        "As a cybersecurity analyst, provide a detailed security analysis of the following Nmap OS Detection Scan report.\n\n"
        "**Your analysis must cover these specific sections:**\n"
        "1.  **Executive Summary:** Briefly summarize the most likely operating systems identified and the primary risks associated with the open ports.\n"
        "2.  **Detailed OS Analysis:**\n"
        "    - Evaluate the list of **OS Guesses**. Discuss the likelihood and security posture of the top candidates (e.g., modern and patched vs. legacy and vulnerable).\n"
        "    - Address the **OS Detection Warning** and **Match Status**. Explain why the results might be unreliable and what 'non-ideal' conditions imply.\n"
        "    - Correlate the open ports with the OS guesses. Are the services (HTTP, HTTPS) typical for the likely OS?\n"
        "3.  **Network Context:**\n"
        "    - Analyze the **rDNS record** and the list of **Other Associated Addresses**. What does this indicate about the host's environment (e.g., CDN, cloud provider)?\n"
        "    - Note the **Network Distance** and its relevance to the host's location on the network.\n"
        "4.  **Actionable Remediation Plan:** Provide specific, prioritized steps. This must include recommendations for OS hardening, patching based on likely versions, and steps to independently verify the host's true OS.\n\n"
        "--- Full OS Detection Scan Report Data ---\n\n"
        f"## Scan Metadata\n"
        f"- **Source File:** {metadata.get('source_file', 'N/A')}\n"
        f"- **Scan Type:** {metadata.get('scan_type', 'N/A')}\n"
        f"- **Timestamp:** {metadata.get('timestamp', 'N/A')}\n"
        f"- **Scan Summary:** {metadata.get('summary', 'N/A')}\n\n"

        f"## Target Information\n"
        f"- **Primary IP Address:** {host.get('ip_address', 'N/A')}\n"
        f"- **Status:** {host.get('status', 'N/A')}\n"
        f"- **rDNS Record:** {host.get('rdns_record', 'N/A')}\n"
        f"- **Other Associated Addresses:** {', '.join(host.get('other_addresses', [])) or 'None Found'}\n\n"

        f"## OS Detection Results\n"
        f"- **OS Detection Warning:** {os_info.get('warning', 'None')}\n"
        f"- **Match Status:** {os_info.get('match_status', 'N/A')}\n"
        f"- **Network Distance:** {host.get('network_distance', 'N/A')} hops\n"
        f"- **Aggressive OS Guesses:**\n"
    )

    if not os_info.get("guesses"):
        prompt += "  - No OS guesses provided.\n\n"
    else:
        for guess in os_info.get("guesses", []):
            prompt += f"  - {guess}\n"
        prompt += "\n"

    prompt += "## Discovered Open Ports\n"
    if not host.get("ports"):
        prompt += "- No open ports found.\n"
    else:
        for port in host.get("ports", []):
            prompt += (
                f"  - **Port:** {port.get('port_id', 'N/A')}\n"
                f"    - **State:** {port.get('state', 'N/A')}\n"
                f"    - **Service:** {port.get('service', 'N/A')}\n"
            )
        prompt += "\n"

    prompt += "\n--- End of Report Data ---\n"

    return prompt

def _create_port_scan_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Creates a comprehensive analysis prompt for a parsed Port Scan report.
    This function includes every piece of extracted data for a thorough assessment.
    """
    # Extract metadata for easy access
    metadata = parsed_data.get("scan_metadata", {})
    scan_type = metadata.get('scan_type', 'Scan')

    # All your examples have a single host, so we'll focus on the first one.
    if not parsed_data.get("hosts"):
        return "Error: Parsed data contains no host information to generate a prompt."
    host = parsed_data["hosts"][0]

    # Start building the detailed prompt
    prompt = (
        f"As a cybersecurity analyst, provide a security assessment for the following Nmap {scan_type} report.\n\n"
        "**Your analysis must address these specific points:**\n"
        "1.  **Executive Summary:** Briefly summarize the findings, noting the open ports and the overall accessibility of the target.\n"
        "2.  **Detailed Findings & Implications:**\n"
        "    - For each **Open Port**, discuss the inherent risks of the exposed service (e.g., potential for web application attacks on open HTTP/HTTPS ports).\n"
        "    - Analyze the list of **Other Associated Addresses** and the **rDNS record**. What does this large number of IPs suggest about the target's network architecture (e.g., load balancing, use of a CDN like Akamai)?\n"
        "    - Discuss the significance of the **Port Summary**, which indicates a large number of ports are filtered, likely by a network firewall.\n"
        "3.  **Actionable Remediation Plan:** Provide clear, prioritized steps for mitigation. This should include recommendations for standard web server hardening, such as ensuring services are patched, securely configured, and monitored, and the potential use of a Web Application Firewall (WAF).\n\n"
        f"--- Full {scan_type} Report Data ---\n\n"
        f"## Scan Metadata\n"
        f"- **Source File:** {metadata.get('source_file', 'N/A')}\n"
        f"- **Scan Type:** {scan_type}\n"
        f"- **Timestamp:** {metadata.get('timestamp', 'N/A')}\n"
        f"- **Scan Summary:** {metadata.get('summary', 'N/A')}\n\n"

        f"## Target Information\n"
        f"- **Primary IP Address:** {host.get('ip_address', 'N/A')}\n"
        f"- **Status:** {host.get('status', 'N/A')}\n"
        f"- **rDNS Record:** {host.get('rdns_record', 'N/A')}\n"
        f"- **Other Associated Addresses:** {', '.join(host.get('other_addresses', [])) or 'None Found'}\n\n"

        f"## Port Scan Results\n"
        f"- **Port Status Summary:** {host.get('port_summary', 'N/A')}\n"
    )

    if not host.get("ports"):
        prompt += "- **Open Ports:** No open ports found.\n"
    else:
        prompt += "- **Open Ports:**\n"
        for port in host.get("ports", []):
            prompt += (
                f"  - **Port:** {port.get('port_id', 'N/A')}\n"
                f"    - **State:** {port.get('state', 'N/A')}\n"
                f"    - **Service:** {port.get('service', 'N/A')}\n"
            )
        prompt += "\n"

    prompt += "\n--- End of Report Data ---\n"

    return prompt

def _create_fragmented_scan_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Creates a comprehensive analysis prompt for a parsed Fragmented Packet Scan report.
    This function includes every piece of extracted data for a thorough assessment.
    """
    # Extract metadata for easy access
    metadata = parsed_data.get("scan_metadata", {})

    # All your examples have a single host, so we'll focus on the first one.
    if not parsed_data.get("hosts"):
        return "Error: Parsed data contains no host information to generate a prompt."
    host = parsed_data["hosts"][0]

    # Start building the detailed prompt
    prompt = (
        "As a cybersecurity analyst, provide a security assessment for the following Nmap Fragmented Packet Scan report.\n\n"
        "**Your analysis must address these specific points:**\n"
        "1.  **Executive Summary:** Briefly summarize the findings, noting the open ports and the fact that a **fragmented scan** was used, which could indicate an attempt to evade network defenses.\n"
        "2.  **Detailed Findings & Implications:**\n"
        "    - For each **Open Port**, discuss the inherent risks of the exposed service (e.g., web application vulnerabilities on HTTP/HTTPS).\n"
        "    - Analyze the list of **Other Associated Addresses**. What does the presence of numerous IPs and a CDN-related **rDNS record** imply about the target's architecture (e.g., load balancing, content delivery network)?\n"
        "    - Discuss the significance of the **Port Summary**, which indicates many ports are filtered, likely by a firewall.\n"
        "3.  **Actionable Remediation Plan:** Provide clear, prioritized steps for mitigation. This should include standard hardening for web servers (patching, secure configurations, WAF) and a recommendation to verify that the network architecture is configured as expected.\n\n"
        "--- Full Fragmented Packet Scan Report Data ---\n\n"
        f"## Scan Metadata\n"
        f"- **Source File:** {metadata.get('source_file', 'N/A')}\n"
        f"- **Scan Type:** {metadata.get('scan_type', 'N/A')}\n"
        f"- **Timestamp:** {metadata.get('timestamp', 'N/A')}\n"
        f"- **Scan Summary:** {metadata.get('summary', 'N/A')}\n\n"

        f"## Target Information\n"
        f"- **Primary IP Address:** {host.get('ip_address', 'N/A')}\n"
        f"- **Status:** {host.get('status', 'N/A')}\n"
        f"- **rDNS Record:** {host.get('rdns_record', 'N/A')}\n"
        f"- **Other Associated Addresses:** {', '.join(host.get('other_addresses', [])) or 'None Found'}\n\n"

        f"## Port Scan Results\n"
        f"- **Port Status Summary:** {host.get('port_summary', 'N/A')}\n"
    )

    if not host.get("ports"):
        prompt += "- **Open Ports:** No open ports found.\n"
    else:
        prompt += "- **Open Ports:**\n"
        for port in host.get("ports", []):
            prompt += (
                f"  - **Port:** {port.get('port_id', 'N/A')}\n"
                f"    - **State:** {port.get('state', 'N/A')}\n"
                f"    - **Service:** {port.get('service', 'N/A')}\n"
            )
        prompt += "\n"

    prompt += "\n--- End of Report Data ---\n"

    return prompt

def _create_tcp_syn_scan_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Creates a comprehensive analysis prompt for a parsed TCP SYN Scan report.
    This function includes every piece of extracted data for a thorough assessment.
    """
    # Extract metadata for easy access
    metadata = parsed_data.get("scan_metadata", {})
    scan_type = metadata.get('scan_type', 'Scan')

    # Assume a single host per report as per the examples
    if not parsed_data.get("hosts"):
        return "Error: Parsed data contains no host information to generate a prompt."
    host = parsed_data["hosts"][0]

    # Start building the detailed prompt
    prompt = (
        f"As a cybersecurity analyst, provide a security assessment for the following Nmap {scan_type} report.\n\n"
        "**Your analysis must address these specific points:**\n"
        "1.  **Executive Summary:** Briefly summarize the findings, highlighting the open ports and noting that a **TCP SYN scan** was performed, which is a common type of 'stealth' scan designed to be less detectable.\n"
        "2.  **Detailed Findings & Implications:**\n"
        "    - For each **Open Port**, discuss the inherent risks of the exposed service (e.g., vulnerabilities in web servers on ports 80/443).\n"
        "    - Analyze the network architecture suggested by the **rDNS record** and the extensive list of **Other Associated Addresses**, which points towards a CDN or load-balanced environment.\n"
        "    - Comment on the **Port Summary**, which shows that most ports are filtered, indicating the presence of a firewall.\n"
        "3.  **Actionable Remediation Plan:** Provide clear, prioritized steps for mitigation. This should include standard hardening for the exposed services, ensuring they are patched, securely configured, and adequately monitored.\n\n"
        f"--- Full {scan_type} Report Data ---\n\n"
        f"## Scan Metadata\n"
        f"- **Source File:** {metadata.get('source_file', 'N/A')}\n"
        f"- **Scan Type:** {scan_type}\n"
        f"- **Timestamp:** {metadata.get('timestamp', 'N/A')}\n"
        f"- **Scan Summary:** {metadata.get('summary', 'N/A')}\n\n"

        f"## Target Information\n"
        f"- **Primary IP Address:** {host.get('ip_address', 'N/A')}\n"
        f"- **Status:** {host.get('status', 'N/A')}\n"
        f"- **rDNS Record:** {host.get('rdns_record', 'N/A')}\n"
        f"- **Other Associated Addresses:** {', '.join(host.get('other_addresses', [])) or 'None Found'}\n\n"

        f"## Port Scan Results\n"
        f"- **Port Status Summary:** {host.get('port_summary', 'N/A')}\n"
    )

    if not host.get("ports"):
        prompt += "- **Open Ports:** No open ports found.\n"
    else:
        prompt += "- **Open Ports:**\n"
        for port in host.get("ports", []):
            prompt += (
                f"  - **Port:** {port.get('port_id', 'N/A')}\n"
                f"    - **State:** {port.get('state', 'N/A')}\n"
                f"    - **Service:** {port.get('service', 'N/A')}\n"
            )
        prompt += "\n"

    prompt += "\n--- End of Report Data ---\n"

    return prompt

def _create_ip_range_scan_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Creates a comprehensive analysis prompt for a parsed IP Range Scan report.
    This function formats all hosts and their details for a full network assessment.
    """
    # Extract metadata for easy access
    metadata = parsed_data.get("scan_metadata", {})
    scan_type = metadata.get('scan_type', 'IP Range Scan')
    hosts = parsed_data.get("hosts", [])

    if not hosts:
        return "Error: Parsed data contains no host information to generate a prompt."

    # --- 1. Define the Analysis Instructions ---
    # These instructions are tailored to the findings of a multi-host internal scan.
    prompt = (
        f"As a cybersecurity analyst, provide a security assessment for the following **{scan_type}** report.\n\n"
        "**Your analysis must address these specific points:**\n"
        "1.  **Executive Summary:** Briefly summarize the findings for the entire IP range. Mention the total number of live hosts discovered and give a high-level overview of the types of services and devices found (e.g., web servers, Windows file shares, network infrastructure).\n"
        "2.  **Detailed Findings & Host-by-Host Analysis:**\n"
        "    - For each host, analyze its open ports and their implications. Pay special attention to high-risk services like SSH (22), MSRPC/NetBIOS (135/139/445), and any unusual or unknown services.\n"
        "    - Comment on the device types suggested by the **MAC Vendor** information (e.g., TP-Link, Giga-byte, Intel), which can help map the network assets.\n"
        "    - Note any hosts with special conditions, such as those that are firewalled (`filtered ports`) or have no open ports but are responsive.\n"
        "3.  **Overall Network Posture & Remediation:**\n"
        "    - Provide a consolidated, prioritized list of recommendations for the entire network. Group similar issues together (e.g., all hosts with open NetBIOS ports).\n"
        "    - Recommend network segmentation and firewall rule reviews as general best practices based on the scan results.\n\n"
        f"--- Full {scan_type} Report Data ---\n\n"
    )

    # --- 2. Add Overall Scan Metadata ---
    prompt += (
        "## Scan Metadata\n"
        f"- **Source File:** {metadata.get('source_file', 'N/A')}\n"
        f"- **Scan Type:** {scan_type}\n"
        f"- **Initiated By:** {metadata.get('initiated_by', 'N/A')}\n"
        f"- **Timestamp:** {metadata.get('timestamp', 'N/A')}\n"
        f"- **Scan Summary:** {metadata.get('summary', 'N/A')}\n\n"
        "## Discovered Host Details\n"
    )

    # --- 3. Iterate Through Each Host and Add Its Details ---
    for i, host in enumerate(hosts, 1):
        prompt += f"\n--- Host {i} of {len(hosts)} ---\n"
        prompt += (
            f"- **IP Address:** {host.get('ip_address', 'N/A')}\n"
            f"- **Status:** {host.get('status', 'N/A')} (Latency: {host.get('latency', 'N/A')})\n"
            f"- **MAC Address:** {host.get('mac_address', 'N/A')}\n"
            f"- **MAC Vendor:** {host.get('mac_vendor', 'N/A')}\n"
            f"- **Port Summary:** {host.get('unshown_ports_summary', 'N/A')}\n"
        )

        # List all found ports (open, filtered, etc.)
        if host.get("ports"):
            prompt += "- **Discovered Ports:**\n"
            for port in host.get("ports", []):
                prompt += (
                    f"  - **Port:** {port.get('port_id', 'N/A')} "
                    f"({port.get('state', 'N/A')}) - "
                    f"**Service:** {port.get('service', 'N/A')}\n"
                )
        else:
            prompt += "- **Discovered Ports:** None found.\n"

        # List any special notes for the host
        if host.get("scan_notes"):
            prompt += "- **Notes:**\n"
            for note in host.get("scan_notes", []):
                prompt += f"  - {note}\n"

    prompt += "\n--- End of Report Data ---\n"

    return prompt


# --- Main Router Function ---
def _format_nmap_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Selects the correct tailored prompt based on the Nmap scan type.
    """
    scan_type = parsed_data.get("scan_metadata", {}).get("scan_type", "Generic Nmap Scan")

    if scan_type == "Aggressive Scan":
        return _create_aggressive_scan_prompt(parsed_data)
    elif scan_type == "OS Detection Scan":
        return _create_os_detection_scan_prompt(parsed_data)
    elif scan_type == "Port Scan":
        return _create_port_scan_prompt(parsed_data)
    elif scan_type == "TCP SYN Scan":
        return _create_tcp_syn_scan_prompt(parsed_data)
    elif scan_type == "Fragmented Packet Scan":
        return _create_fragmented_scan_prompt(parsed_data)
    elif scan_type == "IP Range Scan":
        return _create_ip_range_scan_prompt(parsed_data)
    else:
        # Fallback to a generic prompt if the type is unknown
        return _create_port_scan_prompt(parsed_data)

from typing import Dict, Any

def _format_zap_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed and well-structured prompt for an LLM to analyze parsed ZAP data.
    
    This version includes:
    - The 'solution' for each high/medium vulnerability.
    - A summary of low-risk findings for comprehensive context.
    - Improved formatting for better LLM parsing.
    """
    
    # Instructions for the LLM are clearer and more direct.
    prompt = (
        "You are a senior cybersecurity analyst. Your task is to analyze the following ZAP scan report data and generate a professional summary.\n"
        "Based *only* on the data provided within the '--- ZAP Report Data ---' block, you must:\n"
        "1.  **Summary**: Write a concise, executive-level summary of the scan results, including the target site and the overall risk posture.\n"
        "2.  **Key Findings**: Detail the High and Medium risk vulnerabilities. For each, explain its potential impact on the application.\n"
        "3.  **Remediation Steps**: Provide practical, actionable remediation steps for each High and Medium risk finding. Base your recommendations directly on the 'Solution' provided in the data.\n"
        "4.  **Prevalent Alert Types**: Briefly interpret the 'Alerts by Type' section, noting which types of security issues are most common in this scan.\n\n"
        "Format your response using clear headings: 'Executive Summary', 'Key Findings', and 'Remediation Steps'.\n\n"
        "--- ZAP Report Data ---\n\n"
    )

    # Add scan metadata with improved formatting
    metadata = parsed_data.get("scan_metadata", {})
    prompt += "## Scan Metadata\n"
    prompt += f"- **Site Scanned**: {metadata.get('site', 'N/A')}\n"
    prompt += f"- **Generated At**: {metadata.get('generated_at', 'N/A')}\n"
    prompt += f"- **ZAP Version**: {metadata.get('zap_version', 'N/A')}\n\n"

    # Add summary risk counts
    summary = parsed_data.get("summary", {})
    risk_counts = summary.get("risk_counts", {})
    prompt += "## Risk Distribution Summary\n"
    for risk_level, count in risk_counts.items():
        prompt += f"- **{risk_level}**: {count} alerts\n"
    prompt += f"- **Total Alerts**: {summary.get('total_alerts', 0)}\n\n"

    # Add alerts by name for interpretation
    alerts_by_name = summary.get("alerts_by_name", [])
    if alerts_by_name:
        prompt += "## Alerts by Type and Prevalence\n"
        for alert in alerts_by_name:
            prompt += f"- **Name**: {alert.get('name', 'N/A')}, **Risk**: {alert.get('risk_level', 'N/A')}, **Instances**: {alert.get('instances_count', 0)}\n"
        prompt += "\n"

    # Focus on High and Medium vulnerabilities, now including the crucial 'solution' field.
    vulnerabilities = parsed_data.get("vulnerabilities", [])
    high_medium_vulnerabilities = [v for v in vulnerabilities if v.get("risk") in ["High", "Medium"]]
    low_info_vulnerabilities = [v for v in vulnerabilities if v.get("risk") in ["Low", "Informational"]]

    if high_medium_vulnerabilities:
        prompt += "## Detailed High and Medium Risk Vulnerabilities\n\n"
        for i, vuln in enumerate(high_medium_vulnerabilities, 1):
            prompt += f"### {i}. {vuln.get('name', 'N/A')}\n"
            prompt += f"- **Risk Level**: {vuln.get('risk', 'N/A')}\n"
            prompt += f"- **Description**: {vuln.get('description', 'N/A')}\n"
            # CRITICAL ADDITION: Including the solution gives the LLM what it needs for remediation.
            prompt += f"- **Solution**: {vuln.get('solution', 'N/A')}\n"
            prompt += f"- **Instances Count**: {vuln.get('instances_count', 0)}\n"
            
            if vuln.get('urls'):
                prompt += "- **Affected Instances (up to 2 shown)**:\n"
                for j, instance in enumerate(vuln['urls'][:2], 1):
                    prompt += f"  - **Instance {j} URL**: {instance.get('url', 'N/A')}\n"
                    prompt += f"    - **Method**: {instance.get('method', 'N/A')}\n"
                    if instance.get('parameter'):
                        prompt += f"    - **Parameter**: {instance.get('parameter')}\n"
                    if instance.get('evidence'):
                        prompt += f"    - **Evidence**: {instance.get('evidence', 'N/A')[:200]}...\n" # Limit evidence length
            prompt += "\n"
    else:
        prompt += "## Detailed High and Medium Risk Vulnerabilities\n\nNo High or Medium risk vulnerabilities were identified.\n\n"

    # NEW SECTION: Add context for low-risk findings without cluttering the prompt.
    if low_info_vulnerabilities:
        prompt += "## Low Risk & Informational Findings\n"
        prompt += "The following low-risk and informational issues were also noted:\n"
        unique_low_info_names = sorted(list(set(v.get('name', 'N/A') for v in low_info_vulnerabilities)))
        for name in unique_low_info_names:
            prompt += f"- {name}\n"
        prompt += "\n"

    prompt += "--- End of Report Data ---\n"
    
    return prompt


def _format_sslscan_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for the LLM based on SSLScan parsed data.
    Focuses on protocols, ciphers, key exchange, certificate details, and security features.
    """
    prompt = (
        "As a cybersecurity analyst, analyze the following SSL/TLS Vulnerability Scan Report "
        "and provide:\n"
        "1. A concise summary of the scan results, including the target host and overall security posture.\n"
        "2. Key findings regarding enabled/disabled protocols, supported ciphers, and certificate details.\n"
        "3. Potential security implications for any identified weaknesses (e.g., outdated protocols, weak ciphers, certificate issues).\n"
        "4. Actionable remediation steps to improve the SSL/TLS configuration.\n"
        "The report data is in JSON format. Do not invent information not present in the report.\n\n"
        "--- SSLScan Report Data ---\n"
    )

    # Add scan metadata
    metadata = parsed_data.get("scan_metadata", {})
    prompt += f"Tool: {metadata.get('tool', 'N/A')}\n"
    prompt += f"Target Host: {metadata.get('target_host', 'N/A')}\n"
    prompt += f"Connected IP: {metadata.get('connected_ip', 'N/A')}\n"
    prompt += f"Timestamp: {metadata.get('timestamp', 'N/A')}\n"
    prompt += f"Tool Version: {metadata.get('tool_version', 'N/A')}\n"
    prompt += f"OpenSSL Version: {metadata.get('openssl_version', 'N/A')}\n"
    prompt += f"Tested Server: {metadata.get('tested_server', 'N/A')}:{metadata.get('tested_port', 'N/A')} (SNI: {metadata.get('sni_name', 'N/A')})\n\n"

    # Protocols
    protocols = parsed_data.get("protocols", [])
    if protocols:
        prompt += "SSL/TLS Protocols:\n"
        for proto in protocols:
            prompt += f"  - {proto.get('name', 'N/A')}: {proto.get('status', 'N/A')}\n"
    
    # Security Features
    security_features = parsed_data.get("security_features", {})
    if security_features:
        prompt += "\nTLS Security Features:\n"
        for feature, status in security_features.items():
            if isinstance(status, list): # For Heartbleed which can be a list
                prompt += f"  - {feature.replace('_', ' ').title()}: {', '.join(status)}\n"
            else:
                prompt += f"  - {feature.replace('_', ' ').title()}: {status}\n"

    # Supported Ciphers
    ciphers = parsed_data.get("supported_ciphers", [])
    if ciphers:
        prompt += "\nSupported Server Ciphers (Preferred/Accepted):\n"
        for cipher in ciphers:
            cipher_info = f"  - {cipher.get('status', 'N/A')} {cipher.get('name', 'N/A')} ({cipher.get('bits', 'N/A')} bits)"
            if cipher.get('tls_version'):
                cipher_info += f" on {cipher['tls_version']}"
            if cipher.get('curve'):
                cipher_info += f" Curve: {cipher['curve']}"
            if cipher.get('dhe_bits'):
                cipher_info += f" DHE: {cipher['dhe_bits']} bits"
            prompt += f"{cipher_info}\n"

    # Key Exchange Groups
    key_exchange_groups = parsed_data.get("key_exchange_groups", [])
    if key_exchange_groups:
        prompt += "\nServer Key Exchange Groups:\n"
        for group in key_exchange_groups:
            group_info = f"  - {group.get('name', 'N/A')} ({group.get('details', 'N/A')})"
            if group.get('tls_version'):
                group_info += f" on {group['tls_version']}"
            if group.get('bits'):
                group_info += f" ({group['bits']} bits)"
            prompt += f"{group_info}\n"

    # SSL Certificate
    certificate = parsed_data.get("ssl_certificate", {})
    if certificate:
        prompt += "\nSSL Certificate Details:\n"
        prompt += f"  - Subject: {certificate.get('subject', 'N/A')}\n"
        prompt += f"  - Issuer: {certificate.get('issuer', 'N/A')}\n"
        prompt += f"  - Signature Algorithm: {certificate.get('signature_algorithm', 'N/A')}\n"
        prompt += f"  - RSA Key Strength: {certificate.get('rsa_key_strength', 'N/A')} bits\n"
        prompt += f"  - Altnames: {', '.join(certificate.get('altnames', ['N/A']))}\n"
        prompt += f"  - Valid From: {certificate.get('not_valid_before', 'N/A')}\n"
        prompt += f"  - Valid Until: {certificate.get('not_valid_after', 'N/A')}\n"

    prompt += "\n--- End SSLScan Report Data ---\n"
    prompt += "Please provide the summary, key findings, implications, and remediation steps based on the above. "
    prompt += "Format your response with clear headings: 'Summary', 'Key Findings', 'Implications', 'Remediation Steps'."
    
    return prompt

def _format_mobsf_android_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for the LLM based on MobSF parsed data.
    Focuses on app information, security score, findings, and permissions.
    """
    prompt = (
        "As a cybersecurity analyst, analyze the following Mobile Security Framework (MobSF) report "
        "and provide:\n"
        "1. A concise summary of the application analysis, including app name, package, version, and overall security score.\n"
        "2. Key findings, focusing on high and medium severity issues, and abused permissions.\n"
        "3. Potential security implications for any identified weaknesses.\n"
        "4. Actionable remediation steps for the identified issues.\n"
        "The report data is in JSON format. Prioritize critical and high-risk information. "
        "Do not invent information not present in the report.\n\n"
        "--- MobSF Report Data ---\n"
    )

    # Add scan metadata
    metadata = parsed_data.get("scan_metadata", {})
    prompt += f"Tool: {metadata.get('tool', 'N/A')}\n"
    prompt += f"Report ID: {metadata.get('report_id', 'N/A')}\n"
    prompt += f"Scan Date: {metadata.get('scan_date', 'N/A')}\n"
    prompt += f"MobSF Version: {metadata.get('mobsf_version', 'N/A')}\n"
    prompt += f"App Security Score: {metadata.get('app_security_score', 'N/A')}\n"
    prompt += f"Grade: {metadata.get('grade', 'N/A')}\n\n"

    # App Information
    app_info = parsed_data.get("app_information", {})
    file_info = parsed_data.get("file_information", {})
    prompt += "App Information:\n"
    prompt += f"  App Name: {app_info.get('App Name', 'N/A')}\n"
    prompt += f"  Package Name: {app_info.get('Package Name', 'N/A')}\n"
    prompt += f"  Android Version Name: {app_info.get('Android Version Name', 'N/A')}\n"
    prompt += f"  MD5: {file_info.get('MD5', 'N/A')}\n"
    prompt += f"  SHA1: {file_info.get('SHA1', 'N/A')}\n"
    prompt += f"  SHA256: {file_info.get('SHA256', 'N/A')}\n\n"

    # Summary of Findings
    summary = parsed_data.get("summary", {})
    findings_severity = summary.get("findings_severity", {})
    prompt += "Summary of Findings:\n"
    prompt += f"  Total Issues: {summary.get('total_issues', 0)}\n"
    prompt += f"  High Severity: {findings_severity.get('High', 0)}\n"
    prompt += f"  Medium Severity: {findings_severity.get('Medium', 0)}\n"
    prompt += f"  Info Severity: {findings_severity.get('Info', 0)}\n"
    prompt += f"  Secure Findings: {findings_severity.get('Secure', 0)}\n"
    prompt += f"  Hotspot Findings: {findings_severity.get('Hotspot', 0)}\n\n"

    # Detailed Findings (High & Medium)
    all_findings = []
    all_findings.extend(parsed_data.get("certificate_analysis_findings", []))
    all_findings.extend(parsed_data.get("manifest_analysis_findings", []))
    all_findings.extend(parsed_data.get("code_analysis_findings", []))

    high_medium_findings = [f for f in all_findings if f.get('severity') in ['high', 'warning']] # Using 'high' and 'warning' based on provided JSON
    
    if high_medium_findings:
        prompt += "Detailed High and Medium Severity Findings:\n"
        for i, finding in enumerate(high_medium_findings):
            prompt += f"  Finding {i+1}:\n"
            prompt += f"    Title/Issue: {finding.get('title', finding.get('issue', 'N/A'))}\n"
            prompt += f"    Description: {finding.get('description', 'N/A')}\n"
            prompt += f"    Severity: {finding.get('severity', 'N/A')}\n"
            if 'standards' in finding: # Specifically for code_analysis_findings
                prompt += f"    Standards/CWE: {finding.get('standards', 'N/A')}\n"
            if 'files' in finding: # Specifically for code_analysis_findings
                prompt += f"    Files: {finding.get('files', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No High or Medium severity findings reported.\n\n"

    # Abused Permissions
    abused_permissions = parsed_data.get("abused_permissions_summary", {})
    malware_permissions_section = abused_permissions.get("Malware Permissions", {})
    
    # Check if 'matches' is a string like "2/25" and extract the first number
    matches_str = malware_permissions_section.get('matches', '0/0')
    total_abused_permissions_count = 0
    if isinstance(matches_str, str) and '/' in matches_str:
        try:
            total_abused_permissions_count = int(matches_str.split('/')[0])
        except ValueError:
            total_abused_permissions_count = 0

    if total_abused_permissions_count > 0:
        prompt += "Abused Permissions:\n"
        prompt += f"  Matches: {matches_str}\n"
        prompt += f"  Permissions: {', '.join(malware_permissions_section.get('permissions', []))}\n"
        prompt += f"  Description: {malware_permissions_section.get('description', 'N/A')}\n\n"
    else:
        prompt += "No abused permissions detected as malware.\n\n"


    prompt += "\n--- End MobSF Report Data ---\n"
    prompt += "Please provide the summary, key findings, implications, and remediation steps based on the above. "
    prompt += "Format your response with clear headings: 'Summary', 'Key Findings', 'Implications', 'Remediation Steps'."
    
    return prompt

def _format_mobsf_ios_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for the LLM based on MobSF iOS parsed data.
    Focuses on app information, security score, and various security findings.
    """
    prompt = (
        "As a cybersecurity analyst, analyze the following Mobile Security Framework (MobSF) iOS report "
        "and provide:\n"
        "1. A concise summary of the application analysis, including app name, identifier, version, and overall security score.\n"
        "2. Key findings, focusing on high and medium (warning) severity issues from binary code analysis and binary protection analysis.\n"
        "3. Potential security implications for any identified weaknesses.\n"
        "4. Actionable remediation steps for the identified issues.\n"
        "The report data is in JSON format. Prioritize critical and high-risk information. "
        "Do not invent information not present in the report.\n\n"
        "--- MobSF iOS Report Data ---\n"
    )

    # Add scan metadata
    metadata = parsed_data.get("scan_metadata", {})
    prompt += f"Tool: {metadata.get('tool', 'N/A')}\n"
    prompt += f"Report ID: {metadata.get('report_id', 'N/A')}\n"
    prompt += f"Scan Date: {metadata.get('scan_date', 'N/A')}\n"
    prompt += f"MobSF Version: {metadata.get('mobsf_version', 'N/A')}\n"
    prompt += f"App Security Score: {metadata.get('app_security_score', 'N/A')}\n"
    prompt += f"Grade: {metadata.get('grade', 'N/A')}\n\n"

    # App Information
    app_info = parsed_data.get("app_information", {})
    file_info = parsed_data.get("file_information", {})
    prompt += "App Information:\n"
    prompt += f"  App Name: {app_info.get('App Name', 'N/A')}\n"
    prompt += f"  Identifier: {app_info.get('Identifier', 'N/A')}\n"
    prompt += f"  App Type: {app_info.get('App Type', 'N/A')}\n"
    prompt += f"  SDK Name: {app_info.get('SDK Name', 'N/A')}\n"
    prompt += f"  Version: {app_info.get('Version', 'N/A')}\n"
    prompt += f"  Build: {app_info.get('Build', 'N/A')}\n"
    prompt += f"  Platform Version: {app_info.get('Platform Version', 'N/A')}\n"
    prompt += f"  Min OS Version: {app_info.get('Min OS Version', 'N/A')}\n"
    prompt += f"  Supported Platforms: {', '.join(app_info.get('Supported Platforms', ['N/A']))}\n\n"

    # File Information
    prompt += "File Information:\n"
    prompt += f"  File Name: {file_info.get('File Name', 'N/A')}\n"
    prompt += f"  Size: {file_info.get('Size', 'N/A')}\n"
    prompt += f"  MD5: {file_info.get('MD5', 'N/A')}\n"
    prompt += f"  SHA1: {file_info.get('SHA1', 'N/A')}\n"
    prompt += f"  SHA256: {file_info.get('SHA256', 'N/A')}\n\n"

    # Summary of Findings
    summary = parsed_data.get("summary", {})
    findings_severity = summary.get("findings_severity", {})
    prompt += "Summary of Findings:\n"
    prompt += f"  Total Issues: {summary.get('total_issues', 0)}\n"
    prompt += f"  High Severity: {findings_severity.get('High', 0)}\n"
    prompt += f"  Medium Severity: {findings_severity.get('Medium', 0)}\n"
    prompt += f"  Info Severity: {findings_severity.get('Info', 0)}\n"
    prompt += f"  Secure Findings: {findings_severity.get('Secure', 0)}\n"
    prompt += f"  Hotspot Findings: {findings_severity.get('Hotspot', 0)}\n\n"

    # IPA Binary Code Analysis Findings (High & Warning)
    ipa_code_analysis = parsed_data.get("ipa_binary_code_analysis_findings", [])
    high_warning_ipa_code_findings = [f for f in ipa_code_analysis if f.get('severity') in ['high', 'warning']]

    if high_warning_ipa_code_findings:
        prompt += "Detailed IPA Binary Code Analysis Findings (High and Warning Severity):\n"
        for i, finding in enumerate(high_warning_ipa_code_findings):
            prompt += f"  Finding {i+1}:\n"
            prompt += f"    Issue: {finding.get('issue', 'N/A')}\n"
            prompt += f"    Description: {finding.get('description', 'N/A')}\n"
            prompt += f"    Severity: {finding.get('severity', 'N/A')}\n"
            if 'standards' in finding:
                standards = finding['standards']
                prompt += f"    Standards:\n"
                prompt += f"      CWE: {standards.get('CWE', 'N/A')}\n"
                prompt += f"      OWASP Top 10: {standards.get('OWASP Top 10', 'N/A')}\n"
                prompt += f"      OWASP MASVS: {standards.get('OWASP MASVS', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No High or Warning severity IPA Binary Code Analysis findings reported.\n\n"

    # IPA Binary Analysis Findings (Protections)
    ipa_binary_analysis = parsed_data.get("ipa_binary_analysis_findings", [])
    if ipa_binary_analysis:
        prompt += "IPA Binary Analysis (Protections):\n"
        for i, finding in enumerate(ipa_binary_analysis):
            prompt += f"  Protection {i+1}:\n"
            prompt += f"    Protection: {finding.get('protection', 'N/A')}\n"
            prompt += f"    Status: {finding.get('status', 'N/A')}\n"
            prompt += f"    Severity: {finding.get('severity', 'N/A')}\n"
            prompt += f"    Description: {finding.get('description', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No IPA Binary Analysis findings reported.\n\n"
        
    # App Transport Security Findings
    ats_findings = parsed_data.get("app_transport_security_findings", [])
    if ats_findings:
        prompt += "App Transport Security (ATS) Findings:\n"
        for i, finding in enumerate(ats_findings):
            prompt += f"  ATS Finding {i+1}:\n"
            prompt += f"    Issue: {finding.get('issue', 'N/A')}\n"
            prompt += f"    Severity: {finding.get('severity', 'N/A')}\n"
            prompt += f"    Description: {finding.get('description', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No App Transport Security (ATS) findings reported.\n\n"

    # OFAC Sanctioned Countries
    ofac_countries = parsed_data.get("ofac_sanctioned_countries", [])
    if ofac_countries:
        prompt += "OFAC Sanctioned Countries:\n"
        for i, country_data in enumerate(ofac_countries):
            prompt += f"  Country {i+1}:\n"
            prompt += f"    Domain: {country_data.get('domain', 'N/A')}\n"
            prompt += f"    Country/Region: {country_data.get('country_region', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No OFAC Sanctioned Countries detected.\n\n"

    # Domain Malware Check
    domain_malware_check = parsed_data.get("domain_malware_check", [])
    if domain_malware_check:
        prompt += "Domain Malware Check:\n"
        for i, domain_data in enumerate(domain_malware_check):
            prompt += f"  Domain {i+1}:\n"
            prompt += f"    Domain: {domain_data.get('domain', 'N/A')}\n"
            prompt += f"    Status: {domain_data.get('status', 'N/A')}\n"
            if domain_data.get('geolocation'):
                geo = domain_data['geolocation']
                prompt += f"    Geolocation:\n"
                prompt += f"      IP: {geo.get('IP', 'N/A')}\n"
                prompt += f"      Country: {geo.get('Country', 'N/A')}\n"
                prompt += f"      Region: {geo.get('Region', 'N/A')}\n"
                prompt += f"      City: {geo.get('City', 'N/A')}\n"
                prompt += f"      Latitude: {geo.get('Latitude', 'N/A')}\n"
                prompt += f"      Longitude: {geo.get('Longitude', 'N/A')}\n"
            prompt += "\n"
    else:
        prompt += "No Domain Malware Check findings reported.\n\n"

    # Scan Logs (optional, depending on verbosity desired for LLM)
    scan_logs = parsed_data.get("scan_logs", [])
    if scan_logs:
        prompt += "Scan Logs (Recent Entries):\n"
        for i, log_entry in enumerate(scan_logs[-5:]): # Last 5 entries
            prompt += f"  Log {i+1}: Timestamp={log_entry.get('timestamp', 'N/A')}, Event={log_entry.get('event', 'N/A')}, Error={log_entry.get('error', 'N/A')}\n"
        prompt += "\n"


    prompt += "\n--- End MobSF iOS Report Data ---\n"
    prompt += "Please provide the summary, key findings, implications, and remediation steps based on the above. "
    prompt += "Format your response with clear headings: 'Summary', 'Key Findings', 'Implications', 'Remediation Steps'."
    
    return prompt

def _format_nikto_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for an LLM based on the structured JSON output
    from the refactored Nikto parser.
    """
    prompt = (
        "As a cybersecurity analyst, analyze the following Nikto Web Server Scan Report "
        "and provide:\n"
        "1. A concise summary of the scan results, including the target host, port, HTTP server, and overall security posture based on findings.\n"
        "2. Key findings regarding missing security headers (e.g., X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options) and identified uncommon headers.\n"
        "3. Potential security implications for any identified weaknesses (e.g., missing security headers allowing clickjacking, MIME-sniffing, or insecure transport).\n"
        "4. Actionable remediation steps to improve the web server's security configuration.\n"
        "5. Provide Statistics, the test links, references, and any other relevant information from the report.\n"
        "6. If nothing significant is found, provide the information extracted from the report and state that the findings are informational.\n"
        "7. Suggest that a ZAP scan might provide more in-depth vulnerability details if the Nikto scan appears to only find low-risk or informational issues.\n"
        "The report data is in JSON format. Do not invent information not present in the report.\n\n"
        "--- Nikto Report Data ---\n"
    )

    # Add scan metadata
    metadata = parsed_data.get("scan_metadata", {})
    file_meta = parsed_data.get("file_metadata", {})
    prompt += f"Tool: {metadata.get('tool', 'N/A')}\n"
    prompt += f"Source File: {file_meta.get('filename', 'N/A')}\n"
    prompt += f"Nikto Version: {metadata.get('nikto_version', 'N/A')}\n"
    prompt += f"Scan Start Time: {metadata.get('start_time', 'N/A')}\n"
    prompt += f"Scan End Time: {metadata.get('end_time', 'N/A')}\n"
    prompt += f"Scan Elapsed Time: {metadata.get('elapsed_time', 'N/A')}\n"
    prompt += f"CLI Options: {metadata.get('cli_options', 'N/A')}\n\n"


    # Add Host Details
    host_details = parsed_data.get("host_details", {})
    prompt += "Host Details:\n"
    prompt += f" - Hostname: {host_details.get('hostname', 'N/A')}\n"
    prompt += f" - IP: {host_details.get('ip', 'N/A')}\n"
    prompt += f" - Port: {host_details.get('port', 'N/A')}\n"
    prompt += f" - HTTP Server: {host_details.get('http_server', 'N/A')}\n"
    prompt += f" - Site: {metadata.get('site', 'N/A')}\n"
    
    statistics = host_details.get("statistics", {})
    if statistics:
        prompt += " - Statistics:\n"
        prompt += f"   - Requests: {statistics.get('requests', 'N/A')}\n"
        prompt += f"   - Errors: {statistics.get('errors', 'N/A')}\n"
        prompt += f"   - Findings: {statistics.get('findings', 'N/A')}\n"
    prompt += "\n"

    # Add Vulnerabilities (previously findings)
    vulnerabilities = parsed_data.get("vulnerabilities", [])
    if vulnerabilities:
        prompt += "Identified Vulnerabilities/Findings:\n"
        for i, vuln in enumerate(vulnerabilities):
            prompt += f"Finding {i + 1}:\n"
            prompt += f" - Name: {vuln.get('name', 'N/A')}\n"
            prompt += f" - Risk: {vuln.get('risk', 'N/A')}\n"
            prompt += f" - Description: {vuln.get('description', 'N/A')}\n"
            prompt += f" - URI: {vuln.get('uri', 'N/A')}\n"
            if vuln.get('references'):
                prompt += " - References:\n"
                for ref in vuln['references']:
                    prompt += f"   - {ref}\n"
            prompt += "\n"

    prompt += "--- End Nikto Report Data ---\n\n"
    prompt += "Please provide the analysis based on the data above. "
    prompt += "Format your response with clear headings: 'Summary', 'Key Findings', 'Implications', and 'Remediation Steps'."
    
    return prompt

def _format_cloud_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for the LLM based on generic, chunked report data.

    This function instructs the LLM to analyze fragmented text, identify the
    context (like the tool and target), and generate a structured summary,
    list of findings, and remediation advice.

    Args:
        parsed_data (Dict[str, Any]): The generically parsed report data,
                                       containing text chunks.

    Returns:
        str: A formatted prompt ready to be sent to an LLM.
    """
    # Start with a role and a clear objective for the LLM.
    prompt = (
        "You are an expert cloud security analyst. Your task is to analyze the following text chunks from a cloud security assessment report. The text may be disjointed or fragmented.\n\n"
        "Synthesize the information to produce a comprehensive cloud security assessment report. Your report must include:\n"
        "1.  **Cloud Context:**\n"
        "    - Cloud Provider (AWS/Azure/GCP/Other)\n"
        "    - Assessment Scope (Account ID/Resource Groups/Regions)\n"
        "    - Assessment Date/Time\n"
        "    - Security Standards Compliance (CIS, NIST, PCI-DSS, etc.)\n\n"
        "2.  **Executive Summary:**\n"
        "    - Total number of findings by severity (Critical/High/Medium/Low/Informational)\n"
        "    - Overall security posture assessment\n"
        "    - Most critical risks that need immediate attention\n\n"
        "3.  **Key Findings by Service Category:**\n"
        "    For each affected cloud service (e.g., IAM, S3, EC2, VPC, etc.):\n"
        "    - Service name and affected resources\n"
        "    - Number of findings by severity\n"
        "    - Brief description of key security issues\n\n"
        "4.  **Detailed Findings:**\n"
        "    For each critical/high severity finding:\n"
        "    - **Title:** Clear, concise description of the issue\n"
        "    - **Severity:** Critical/High/Medium/Low\n"
        "    - **Resource ID/ARN:** Affected cloud resource\n"
        "    - **Description:** Detailed explanation of the vulnerability\n"
        "    - **Impact:** Potential business impact if exploited\n"
        "    - **Remediation:** Step-by-step remediation guidance\n"
        "    - **References:** Relevant security best practices or standards\n\n"
        "5.  **Recommendations:**\n"
        "    - Prioritized action items\n"
        "    - Quick wins for immediate risk reduction\n"
        "    - Long-term security improvements\n\n"
        "Present your analysis using clear markdown formatting with appropriate headings. "
        "Only include information that can be directly derived from the provided text chunks.\n\n"
    )
    
    # Append the file metadata for context
    file_metadata = parsed_data.get("file_metadata", {})
    prompt += "--- Source File Metadata ---\n"
    prompt += f"Filename: {file_metadata.get('filename', 'N/A')}\n"
    prompt += f"Last Modified: {file_metadata.get('last_modified', 'N/A')}\n\n"

    # Append the actual text chunks for the LLM to analyze
    prompt += "--- Raw Report Text Chunks ---\n"
    content_chunks = parsed_data.get("content_chunks", [])
    if not content_chunks:
        prompt += "No text content was extracted from the report.\n"
    else:
        for chunk in content_chunks:
            chunk_id = chunk.get('chunk_id', 'N/A')
            chunk_text = chunk.get('text', '').strip()
            prompt += f"--- [Chunk {chunk_id}] ---\n{chunk_text}\n\n"

    prompt += "--- End of Report Text ---\n"
    prompt += "Please begin your analysis now."
    
    return prompt

def _format_sql_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a detailed prompt for the LLM based on generic, chunked report data.

    This function instructs the LLM to analyze fragmented text, identify the
    context (like the tool and target), and generate a structured summary,
    list of findings, and remediation advice.

    Args:
        parsed_data (Dict[str, Any]): The generically parsed report data,
                                       containing text chunks.

    Returns:
        str: A formatted prompt ready to be sent to an LLM.
    """
    # Start with a role and a clear objective for the LLM.
    prompt = (
        "You are an expert in web application security with deep expertise in SQL injection vulnerabilities. "
        "Your task is to analyze the following SQLMap scan results and provide a comprehensive security assessment.\n\n"
        "Synthesize the information to produce a detailed SQL injection vulnerability report. Your report must include:\n"
        "1.  **Scan Overview:**\n"
        "    - Target URL and HTTP methods tested\n"
        "    - Database management system (DBMS) and version if identified\n"
        "    - Scan date and duration\n"
        "    - Parameters tested for SQL injection\n\n"
        "2.  **Executive Summary:**\n"
        "    - Total number of SQL injection vulnerabilities found by type (boolean-based blind, time-based blind, error-based, etc.)\n"
        "    - Overall risk assessment (Critical/High/Medium/Low/None)\n"
        "    - Most critical vulnerabilities that require immediate attention\n\n"
        "3.  **Vulnerability Details:**\n"
        "    For each confirmed SQL injection vulnerability:\n"
        "    - **Vulnerability Type:** (e.g., Boolean-based blind, Time-based blind, Error-based, UNION query, etc.)\n"
        "    - **Affected Parameter:** The vulnerable parameter and HTTP method (GET/POST/Header/Cookie)\n"
        "    - **Injection Point:** The exact location in the request where injection was successful\n"
        "    - **Confidence Level:** (e.g., High/Medium/Low) based on the scan results\n"
        "    - **Technical Details:** Specific payloads that triggered the vulnerability\n\n"
        "4.  **Impact Assessment:**\n"
        "    - Potential data exposure (tables, columns, records that could be accessed)\n"
        "    - Database operations that could be performed (SELECT, INSERT, UPDATE, DELETE, etc.)\n"
        "    - Business impact of successful exploitation\n\n"
        "5.  **Remediation Recommendations:**\n"
        "    - Parameterized queries implementation guidance\n"
        "    - Input validation and sanitization techniques\n"
        "    - Web Application Firewall (WAF) rules if applicable\n"
        "    - Additional security controls to implement\n\n"
        "6.  **Verification Steps:**\n"
        "    - How to verify the vulnerability has been patched\n"
        "    - Recommended retesting approach\n\n"
        "Present your analysis using clear markdown formatting with appropriate headings. "
        "Only include information that can be directly derived from the provided SQLMap scan results.\n\n"
    )
    
    # Append the file metadata for context
    file_metadata = parsed_data.get("file_metadata", {})
    prompt += "--- Source File Metadata ---\n"
    prompt += f"Filename: {file_metadata.get('filename', 'N/A')}\n"
    prompt += f"Last Modified: {file_metadata.get('last_modified', 'N/A')}\n\n"

    # Append the actual text chunks for the LLM to analyze
    prompt += "--- Raw Report Text Chunks ---\n"
    content_chunks = parsed_data.get("content_chunks", [])
    if not content_chunks:
        prompt += "No text content was extracted from the report.\n"
    else:
        for chunk in content_chunks:
            chunk_id = chunk.get('chunk_id', 'N/A')
            chunk_text = chunk.get('text', '').strip()
            prompt += f"--- [Chunk {chunk_id}] ---\n{chunk_text}\n\n"

    prompt += "--- End of Report Text ---\n"
    prompt += "Please begin your analysis now."
    
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
    elif report_type.lower() == "mobsf_android":
        prompt = _format_mobsf_android_summary_prompt(parsed_data)
    elif report_type.lower() == "mobsf_ios":
        prompt = _format_mobsf_ios_summary_prompt(parsed_data)
    elif report_type.lower() == "nikto":
        prompt = _format_nikto_summary_prompt(parsed_data)
    elif report_type.lower() == "cloud":
        prompt = _format_cloud_summary_prompt(parsed_data)
    elif report_type.lower() == "sqlmap":
        prompt = _format_sql_summary_prompt(parsed_data)
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


# Example usage (for testing summarizer.py directly if needed)
if __name__ == "__main__":
    print("--- Testing summarizer.py directly ---")
    # This requires a dummy local_llm and parsed data.
    # In a real run, main.py will handle loading and parsing.

    # Mock LLM instance for local testing without actual model download/load
    class MockLlama:
        def create_chat_completion(self, messages, max_tokens, temperature, stop):
            # For simplicity, mock the chat completion response
            full_prompt = messages[0]['content'] if messages else ""
            if "summarize the following conversation history" in full_prompt.lower():
                return {"choices": [{"message": {"content": "Mocked summary of the conversation history."}}]}
            elif "Nmap Report Data" in full_prompt:
                 return {"choices": [{"message": {"content": "Mocked Nmap report summary."}}]}
            elif "ZAP Report Data" in full_prompt:
                 return {"choices": [{"message": {"content": "Mocked ZAP report summary."}}]}
            elif "SSLScan Report Data" in full_prompt: # New mock response for SSLScan
                return {"choices": [{"message": {"content": "Mocked SSLScan report summary."}}]}
            elif "Mobsf Android Report Data" in full_prompt: # New mock response for SSLScan
                return {"choices": [{"message": {"content": "Mocked Mobsf Android report summary."}}]}
            else:
                return {"choices": [{"message": {"content": "Mocked LLM response."}}]}

    # Override generate_response for this test block
    _original_generate_response = generate_response
    def generate_response(llm_instance, prompt, max_tokens=256, temperature=0.7, stop=["</s>"]):
        return llm_instance.create_chat_completion(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=temperature,
            stop=stop
        )["choices"][0]["message"]["content"]

    dummy_llm_instance = MockLlama()
    print("Using Mock LLM for summarizer test.")


    # Dummy Nmap parsed data
    dummy_nmap_data = {
        "scan_metadata": {
            "scan_initiated_by": "User",
            "timestamp": "Fri Jun 18 10:00:00 2025 IST",
            "target": "example.com (192.168.1.1)",
            "nmap_version": "7.92",
            "scan_type": "Port Scan",
            "scan_duration": "10.5 seconds"
        },
        "hosts": [
            {
                "ip_address": "192.168.1.1",
                "hostname": "example.com",
                "status": "up",
                "latency": "0.002s",
                "os_detection": {
                    "os_guesses": ["Linux 3.10 - 4.11"],
                    "device_type": ["general purpose"]
                },
                "ports": [
                    {
                        "port_id": 22, "protocol": "tcp", "state": "open", "service": "ssh",
                        "version": "OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)",
                        "script_outputs": {"ssh-hostkey": "2048 SHA256:abcd... (RSA)"}
                    },
                    {
                        "port_id": 80, "protocol": "tcp", "state": "open", "service": "http",
                        "version": "Apache httpd 2.4.29 ((Ubuntu))",
                        "script_outputs": {"http-title": "Apache2 Ubuntu Default Page"}
                    }
                ]
            }
        ]
    }

    # Dummy ZAP parsed data
    dummy_zap_data = {
        "scan_metadata": {
            "tool": "Checkmarx ZAP Report",
            "report_id": "12345-abcde",
            "generated_at": "2025-06-18T10:05:00",
            "site": "http://testphp.vulnweb.com",
            "zap_version": "2.10.0"
        },
        "summary": {
            "risk_counts": {"High": 1, "Medium": 2, "Low": 3, "Informational": 5, "False Positives": 0},
            "total_alerts": 11
        },
        "vulnerabilities": [
            {
                "name": "SQL Injection", "risk": "High",
                "description": "SQL Injection vulnerability found in parameter 'id'.",
                "urls": [{"url": "http://testphp.vulnweb.com/listproducts.php?cat=1", "method": "GET", "parameter": "id", "attack": "id=1'%20OR%201=1--", "evidence": "Error message with SQL syntax"}],
                "solution": "Use parameterized queries or prepared statements.",
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                "cwe_id": 89
            },
            {
                "name": "Cross Site Scripting (XSS)", "risk": "Medium",
                "description": "Reflected XSS vulnerability identified.",
                "urls": [{"url": "http://testphp.vulnweb.com/search.php?test=1", "method": "GET", "parameter": "test", "attack": "<script>alert(1)</script>", "evidence": "Reflected script in response"}],
                "solution": "Implement proper input validation and output encoding.",
                "references": ["https://owasp.org/www-community/attacks/xss/"],
                "cwe_id": 79
            }
        ]
    }

    # Dummy SSLScan parsed data
    dummy_sslscan_data = {
        "scan_metadata": {
            "tool": "SSLScan Report",
            "initiated_by": "Maaz",
            "timestamp": "2025-04-19 12:29:21",
            "target_host": "hackthissite.org",
            "tool_version": "2.1.5",
            "openssl_version": "3.4.0",
            "connected_ip": "137.74.187.102",
            "tested_server": "hackthissite.org",
            "tested_port": 443,
            "sni_name": "hackthissite.org"
        },
        "protocols": [
            {"name": "SSLv2", "status": "disabled"},
            {"name": "SSLv3", "status": "disabled"},
            {"name": "TLSv1.2", "status": "enabled"},
            {"name": "TLSv1.3", "status": "disabled"}
        ],
        "security_features": {
            "tls_fallback_scsv": "Server supports TLS Fallback SCSV",
            "tls_renegotiation": "Session renegotiation not supported",
            "tls_compression": "Compression disabled",
            "heartbleed": ["TLSv1.2 not vulnerable to heartbleed"]
        },
        "supported_ciphers": [
            {"status": "Preferred", "tls_version": "TLSv1.2", "bits": 256, "name": "ECDHE-RSA-AES256-GCM-SHA384", "curve": "P-256", "dhe_bits": 256}
        ],
        "key_exchange_groups": [
            {"tls_version": "TLSv1.2", "bits": 128, "name": "secp256r1", "details": "NIST P-256"}
        ],
        "ssl_certificate": {
            "signature_algorithm": "sha256WithRSAEncryption",
            "rsa_key_strength": 4096,
            "subject": "hackthisjogneh42n5o7gbzrewxee3vyu6ex37ukyvdw6jm66npakiyd.onion",
            "altnames": ["DNS: hackthissite.org", "DNS:www.hackthissite.org"],
            "issuer": "HARICA DV TLS RSA",
            "not_valid_before": "Mar 25 04:43:22 2025 GMT",
            "not_valid_after": "Mar 25 04:43:22 2026 GMT"
        }
    }


    if dummy_llm_instance:
        print("\n--- Testing with Nmap Report ---")
        nmap_summary = summarize_report_with_llm(dummy_llm_instance, dummy_nmap_data, "nmap")
        print("Generated Nmap Summary:")
        print(nmap_summary)

        print("\n--- Testing with ZAP Report ---")
        zap_summary = summarize_report_with_llm(dummy_llm_instance, dummy_zap_data, "zap")
        print("Generated ZAP Summary:")
        print(zap_summary)
        
        print("\n--- Testing with SSLScan Report ---") # New test call
        sslscan_summary = summarize_report_with_llm(dummy_llm_instance, dummy_sslscan_data, "sslscan")
        print("Generated SSLScan Summary:")
        print(sslscan_summary)

        # Test summarize_chat_history_segment
        print("\n--- Testing chat history summarization ---")
        test_history_segment = [
            {"role": "user", "content": "What is SQL injection?"},
            {"role": "assistant", "content": "SQL injection is a web security vulnerability that allows an attacker to alter the SQL queries made by an application."},
            {"role": "user", "content": "How do I prevent it?"},
            {"role": "assistant", "content": "You can prevent SQL injection by using parameterized queries, prepared statements, and input validation."}
        ]
        
        # Temporarily set a dummy config for this test if not importing real config
        class DummyConfig:
            DEFAULT_SUMMARIZE_MAX_TOKENS = 150
        
        # Use the actual config if available, otherwise use dummy
        current_config = config if 'config' in locals() else DummyConfig()
        
        history_summary = summarize_chat_history_segment(dummy_llm_instance, test_history_segment, max_tokens=current_config.DEFAULT_SUMMARIZE_MAX_TOKENS)
        print("Generated History Summary:")
        print(history_summary)

    else:
        print("Skipping summarizer tests as LLM instance could not be loaded.")
    
    # Restore original generate_response after testing
    generate_response = _original_generate_response
