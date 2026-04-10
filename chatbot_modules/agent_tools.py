from typing import List, Dict, Any

# Tool definitions in Gemini/OpenAI function calling format
SECURITY_TOOLS = [
    {
        "function_declarations": [
            {
                "name": "nmap_scan",
                "description": "Perform an asynchronous network discovery or vulnerability scan using Nmap. Progress will be shown in a live terminal.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_ip": {"type": "string", "description": "IP address, Domain, or CIDR range (e.g., '192.168.1.1', 'example.com')."},
                        "protocol_type": {"type": "string", "enum": ["TCP", "UDP"]},
                        "scan_type": {
                            "type": "string", 
                            "enum": ["default", "os", "fragmented", "aggressive", "tcp_syn", "vuln", "udp", "ping_sweep", "tcp_connect", "null", "fin", "xmas", "ack", "window", "decoy"],
                            "description": "The Nmap scan type. Always ask the user to choose."
                        },
                        "timing": {"type": "integer", "description": "Timing template (0-5). Always ask the user to choose."}
                    },
                    "required": ["target_ip", "protocol_type", "scan_type", "timing"]
                }
            },
            {
                "name": "zap_scan",
                "description": "Perform an asynchronous web application vulnerability scan using OWASP ZAP. Progress will be shown in a live terminal.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The full website URL to scan (e.g., 'http://testphp.vulnweb.com')."},
                        "scan_mode": {"type": "string", "enum": ["Quick Scan", "Full Scan"], "description": "Select Quick or Full. Always ask the user."},
                        "use_ajax": {"type": "boolean", "description": "Set to true to use AJAX Spider for modern SPAs/dynamic sites. Always ask the user."},
                        "auth_config": {
                            "type": "object",
                            "description": "Optional configuration for Form-Based Authentication. You do not strictly have to ask for this if unneeded.",
                            "properties": {
                                "login_url": {"type": "string"},
                                "username_field": {"type": "string"},
                                "password_field": {"type": "string"},
                                "username": {"type": "string"},
                                "password": {"type": "string"}
                            }
                        }
                    },
                    "required": ["target_url", "scan_mode", "use_ajax"]
                }
            },
            {
                "name": "ssl_scan",
                "description": "Perform an asynchronous SSL/TLS configuration check. Progress will be shown in a live terminal.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_host": {"type": "string", "description": "The hostname or IP to check SSL config."}
                    },
                    "required": ["target_host"]
                }
            },
            {
                "name": "sql_injection_scan",
                "description": "Perform an asynchronous specialized SQL injection audit. Progress will be shown in a live terminal.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The target URL to test for SQLi."},
                        "scan_mode": {"type": "string", "enum": ["quick", "full", "deep"], "description": "Select the verbosity level. Always ask the user."}
                    },
                    "required": ["target_url", "scan_mode"]
                }
            },
            {
                "name": "packet_sniffer",
                "description": "Perform an asynchronous network traffic capture. Progress will be shown in a live terminal.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_ip": {"type": "string", "description": "IP address to monitor traffic for."},
                        "duration": {"type": "integer", "description": "Seconds to capture packets. ALWAYS ask user."},
                        "max_packets": {"type": "integer", "description": "Maximum packets to capture. ALWAYS ask user."}
                    },
                    "required": ["target_ip", "duration", "max_packets"]
                }
            },
            {
                "name": "api_security_scan",
                "description": "Perform an asynchronous API security audit. Progress will be shown in a live terminal.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The base API URL."},
                        "definition_url": {"type": "string", "description": "The URL to the Swagger/OpenAPI spec JSON or YAML file."},
                        "auth_token": {"type": "string", "description": "Optional Bearer token or API key for authentication."}
                    },
                    "required": ["target_url", "definition_url"]
                }
            },
            {
                "name": "killchain_audit",
                "description": "Perform an asynchronous full-spectrum kill chain analysis. Progress will be shown in a live terminal.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "The target domain or URL for the audit."},
                        "profile": {"type": "string", "enum": ["Recon Only", "Network Audit", "Web Audit", "Full Scan"], "description": "Audit profile type. ALWAYS ask user."},
                        "aggression": {"type": "string", "enum": ["Normal", "Stealth", "Attack"], "description": "Intensity level. ALWAYS ask user."}
                    },
                    "required": ["target", "profile", "aggression"]
                }
            },
            {
                "name": "semgrep_sast_scan",
                "description": "Perform an asynchronous Static Application Security Testing (SAST) scan. Progress will be shown in a live terminal.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "git_url": {"type": "string", "description": "The full Git repository URL to audit."}
                    },
                    "required": ["git_url"]
                }
            },
            {
                "name": "scanner_analysis",
                "description": "Automatically analyze the results of a completed scan and provide a detailed security summary.",
                "parameters": {
                    "type": "object",
                    "properties": {
                         "scanner_type": {"type": "string", "enum": ["zap", "api", "nmap", "killchain"], "description": " The tool that generated the report."},
                         "target": {"type": "string", "description": "The target URL or IP that was scanned."}
                    },
                    "required": ["scanner_type"]
                }
            }
        ]
    }
]
