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
                        "protocol_type": {"type": "string", "enum": ["TCP", "UDP"], "default": "TCP"},
                        "scan_type": {
                            "type": "string", 
                            "enum": ["default", "os", "fragmented", "aggressive", "tcp_syn", "vuln", "udp", "ping_sweep", "tcp_connect", "null", "fin", "xmas", "ack", "window", "decoy"],
                            "default": "default"
                        },
                        "timing": {"type": "integer", "description": "Timing template (0-5).", "default": 4}
                    },
                    "required": ["target_ip"]
                }
            },
            {
                "name": "zap_scan",
                "description": "Perform an asynchronous web application vulnerability scan using OWASP ZAP. Progress will be shown in a live terminal.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The full website URL to scan (e.g., 'http://testphp.vulnweb.com')."},
                        "scan_type": {"type": "string", "enum": ["Quick Scan", "Full Scan"], "default": "Quick Scan"}
                    },
                    "required": ["target_url"]
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
                        "scan_mode": {"type": "string", "enum": ["quick", "full", "deep"], "default": "quick"}
                    },
                    "required": ["target_url"]
                }
            },
            {
                "name": "packet_sniffer",
                "description": "Perform an asynchronous network traffic capture. Progress will be shown in a live terminal.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_ip": {"type": "string", "description": "IP address to monitor traffic for."},
                        "duration": {"type": "integer", "description": "Seconds to capture packets. Ask user if not specified.", "default": 30},
                        "max_packets": {"type": "integer", "description": "Maximum packets to capture. Ask user if not specified.", "default": 50}
                    },
                    "required": ["target_ip"]
                }
            },
            {
                "name": "api_security_scan",
                "description": "Perform an asynchronous API security audit. Progress will be shown in a live terminal.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The base API URL."},
                        "definition_url": {"type": "string", "description": "The URL to the Swagger/OpenAPI spec JSON or YAML file."}
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
                        "profile": {"type": "string", "enum": ["full_audit", "stealth", "recon_only"], "default": "full_audit"}
                    },
                    "required": ["target"]
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
                        "file_path": {"type": "string", "description": "The path to the generated report PDF file."}
                    },
                    "required": ["file_path"]
                }
            }
        ]
    }
]
