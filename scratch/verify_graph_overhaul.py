import sys
import os
import networkx as nx
import json

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from chatbot_modules import graph_utils

def test_graph_overhaul():
    print("--- Starting Graph Overhaul Verification ---")
    G = graph_utils.create_base_graph()
    
    # 1. Simulate Nmap Scan
    nmap_data = {
        "scan_metadata": {"target_ip": "127.0.0.1", "report_id": "NMAP_001", "scan_date": "2026-04-18"},
        "open_ports": [
            {"port": 80, "protocol": "tcp", "service_name": "http", "service_version": "Apache/2.4.41", "state": "open"}
        ]
    }
    G = graph_utils.build_graph_from_report(G, nmap_data, "nmap")
    print("[+] Ingested Nmap data.")
    
    # 2. Simulate ZAP Scan (Entity Resolution should trigger)
    zap_data = {
        "scan_metadata": {"target_url": "http://127.0.0.1/login", "report_id": "ZAP_001", "generated_at": "2026-04-18"},
        "findings": [
            {"name": "XSS Finding", "risk_level": "High", "url": "http://127.0.0.1/login", "cweid": "79", "description": "Cross-site scripting"}
        ]
    }
    G = graph_utils.build_graph_from_report(G, zap_data, "zap")
    print("[+] Ingested ZAP data (Triggering Entity Resolution).")
    
    # 3. Simulate PCAP Data
    pcap_data = {
        "scan_metadata": {"report_id": "PCAP_001"},
        "active_conversations": [
            {"src_ip": "127.0.0.1", "dst_ip": "8.8.8.8", "protocol": "DNS", "bytes": 512}
        ]
    }
    G = graph_utils.build_graph_from_report(G, pcap_data, "pcap")
    print("[+] Ingested PCAP data.")
    
    # --- VERIFICATION ---
    nodes = list(G.nodes(data=True))
    edges = list(G.edges(data=True))
    
    print(f"\nGraph Stats: {len(nodes)} Nodes, {len(edges)} Edges")
    
    # Check for Host:127.0.0.1
    host_node = "Host:127.0.0.1"
    if G.has_node(host_node):
        print(f"[SUCCESS] Host node found: {host_node}")
    else:
        print("[FAIL] Host node missing.")
        
    # Check for WebApplication:127.0.0.1
    app_node = "WebApplication:127.0.0.1"
    if G.has_node(app_node):
        print(f"[SUCCESS] WebApp node found: {app_node}")
        # Check link to Host
        if G.has_edge(app_node, host_node):
            print(f"[SUCCESS] Cross-tool Entity Resolution verified: {app_node} -> {host_node}")
        else:
            print("[FAIL] WebApp not linked to Host.")
    else:
        print("[FAIL] WebApp node missing.")
        
    # Check for CWE enrichment
    cwe_node = "CWE:CWE-79"
    if G.has_node(cwe_node):
        data = G.nodes[cwe_node]
        print(f"[SUCCESS] CWE node found: {cwe_node}")
        print(f"         Enrichment Data: Risk Score={data.get('risk_score')}, CVE Count={data.get('cve_count')}")
        if data.get('risk_score'):
            print("[SUCCESS] CWE Enrichment verified.")
        else:
            print("[FAIL] CWE node found but not enriched. (Check mapping path)")
    else:
        print("[FAIL] CWE node missing.")

    # Check Summary
    summary = graph_utils.generate_graph_summary(G)
    print("\n--- Graph Summary Context for LLM ---\n")
    print(summary)
    
if __name__ == "__main__":
    test_graph_overhaul()
