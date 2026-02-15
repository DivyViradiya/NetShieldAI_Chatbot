from typing import List, Dict, Any

# Tool definitions in Gemini/OpenAI function calling format
SECURITY_TOOLS = [
    {
        "function_declarations": [
            {
                "name": "nmap_scan",
                "description": "Perform a network discovery or vulnerability scan using Nmap.",
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
                "description": "Perform a web application vulnerability scan using OWASP ZAP.",
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
                "description": "Check SSL/TLS configuration and identify weak ciphers or deprecated protocols.",
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
                "description": "Perform a specialized SQL injection audit on a target URL.",
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
                "description": "Capture and analyze network traffic for a specific target IP.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_ip": {"type": "string", "description": "IP address to monitor traffic for."},
                        "duration": {"type": "integer", "description": "Seconds to capture packets.", "default": 30},
                        "max_packets": {"type": "integer", "description": "Maximum packets to capture.", "default": 50}
                    },
                    "required": ["target_ip"]
                }
            },
            {
                "name": "api_security_scan",
                "description": "Perform a security audit on an API using its Swagger/OpenAPI definition.",
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
                "description": "Perform a full-spectrum kill chain analysis (Recon, Weaponization, Exploitation).",
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
                "description": "Perform a Static Application Security Testing (SAST) scan on a Git repository.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "git_url": {"type": "string", "description": "The full Git repository URL to audit."}
                    },
                    "required": ["git_url"]
                }
            }
        ]
    }
]
