import sys
import os
sys.path.insert(0, os.path.abspath('d:/NetShield/NetShieldAI_Chatbot'))
from chatbot_modules.graph_utils import build_graph_from_report, create_base_graph, generate_graph_summary

mock_nmap_data = {
    "scan_metadata": {
        "tool": "nmap",
        "generated_at": "2023-10-27T10:00:00Z",
        "report_id": "mock_report_1"
    },
    "metadata": {
        "target_ip": "192.168.1.100",
        "host_status": "UP"
    },
    "open_ports": [
        {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service_name": "http",
            "service_version": "Apache httpd 2.4.41"
        },
        {
            "port": 22,
            "protocol": "tcp",
            "state": "filtered",
            "service_name": "ssh",
            "service_version": "OpenSSH 8.2p1"
        }
    ]
}

g = build_graph_from_report(create_base_graph(), mock_nmap_data, 'nmap')
print("--- NMAP GRAPH ---")
print(generate_graph_summary(g))

mock_zap_data = {
    "scan_metadata": {
        "tool": "zap",
        "generated_at": "2023-10-27T11:00:00Z",
        "report_id": "mock_report_2"
    },
    "metadata": {
        "target_url": "http://192.168.1.100"
    },
    "findings": [
        {
            "url": "http://192.168.1.100/login",
            "name": "SQL Injection",
            "risk_level": "High",
            "confidence": "Certain",
            "predicted_score": 9.8
        }
    ]
}

g2 = build_graph_from_report(g, mock_zap_data, 'zap')
print("--- HYBRID ZAP GRAPH ---")
print(generate_graph_summary(g2))
