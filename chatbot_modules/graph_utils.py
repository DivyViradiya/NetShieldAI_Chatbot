import networkx as nx
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

def create_base_graph() -> nx.MultiDiGraph:
    """Returns an empty MultiDiGraph for a new session."""
    return nx.MultiDiGraph()

def serialize_graph(graph: nx.MultiDiGraph) -> str:
    """Converts a NetworkX graph to a JSON string for SQLite storage."""
    try:
        data = nx.node_link_data(graph)
        return json.dumps(data)
    except Exception as e:
        logger.error(f"Failed to serialize graph: {e}")
        return "{}"

def deserialize_graph(graph_json: str) -> nx.MultiDiGraph:
    """Converts a JSON string back into a NetworkX MultiDiGraph."""
    if not graph_json or graph_json.strip() == "":
        return create_base_graph()
    try:
        data = json.loads(graph_json)
        return nx.node_link_graph(data)
    except Exception as e:
        logger.error(f"Failed to deserialize graph, returning empty: {e}")
        return create_base_graph()

def generate_graph_summary(graph: nx.MultiDiGraph) -> str:
    """Creates a text summarization of the graph topology to feed into the LLM context."""
    if graph.number_of_nodes() == 0:
        return "No logical graph data available for this session."
    
    summary = f"Topology Context ({graph.number_of_nodes()} Nodes, {graph.number_of_edges()} Edges):\n"
    for u, v, data in graph.edges(data=True):
        edge_label = data.get('label', 'CONNECTED_TO')
        props = ", ".join([f"{k}='{v}'" for k, v in data.items() if k != 'label'])
        prop_str = f" {{{props}}}" if props else ""
        summary += f"[{u}] -[:{edge_label}{prop_str}]-> [{v}]\n"
        
    return summary

def build_graph_from_report(existing_graph: nx.MultiDiGraph, parsed_data: Dict[str, Any], tool_type: str) -> nx.MultiDiGraph:
    """
    Ingests parsed JSON from various scanners and updates the NetworkX graph 
    based on the NetShieldAI Graph Protocol (User Refined).
    """
    G = existing_graph
    
    # Safely extract top-level metadata
    metadata = parsed_data.get("metadata", {})
    if not metadata and "scan_metadata" in parsed_data:
        metadata = parsed_data["scan_metadata"]
        
    report_id = metadata.get("report_id", "Unknown_Report")
    scan_date = metadata.get("scan_date", metadata.get("generated_at", "Unknown_Date"))
    tool_name = metadata.get("tool", tool_type)
    
    # NMAP PARSER (Network Topology)
    if tool_type == "nmap":
        cli_args = metadata.get("scan_arguments", "")
        duration = parsed_data.get("summary", {}).get("scan_duration_sec", "")
        security_posture = metadata.get("security_posture", "Unknown")
        threats_detected = parsed_data.get("summary", {}).get("threats_detected", 0)
        
        scan_node = f"ScanEvent:{report_id}"
        G.add_node(scan_node, type="ScanEvent", report_id=report_id, timestamp=scan_date, tool=tool_name, 
                   cli_arguments=cli_args, duration_sec=duration, security_posture=security_posture, threats_detected=threats_detected)
        
        target_ip = metadata.get("target_ip", "Unknown_IP")
        status = metadata.get("host_status", "UP")
        
        host_node = f"Host:{target_ip}"
        G.add_node(host_node, type="Host", ip_address=target_ip, status=status)
        G.add_edge(scan_node, host_node, label="ASSESSED")
        
        for port_info in parsed_data.get("open_ports", []):
            p_num = port_info.get('port')
            p_proto = port_info.get('protocol', 'tcp')
            port_id = f"{p_num}/{p_proto}"
            port_node = f"Port:{port_id}"
            
            G.add_node(port_node, type="Port", port_id=port_id, number=p_num, protocol=p_proto, 
                       tctr_magnitude=port_info.get('tctr_magnitude_percent'), 
                       intelligence=port_info.get('intelligence_breakdown'))
            G.add_edge(host_node, port_node, label="EXPOSES", state=port_info.get('state', 'Unknown'))
            
            s_name = port_info.get('service_name', 'Unknown')
            s_ver = port_info.get('service_version', '')
            service_id = f"{s_name}_{s_ver}" if s_ver else f"{s_name}"
            service_node = f"Service:{service_id}"
            G.add_node(service_node, type="Service", service_id=service_id, name=s_name, version=s_ver)
            
            G.add_edge(port_node, service_node, label="DELIVERS")
            G.add_edge(host_node, service_node, label="HOSTS")
            
            # Add process if available
            p_desc = port_info.get('process', '')
            if p_desc:
                proc_node = f"Process:{p_desc}"
                G.add_node(proc_node, type="Process", description=p_desc)
                G.add_edge(service_node, proc_node, label="EXECUTED_BY")

    # ZAP PARSER (Web Topology)
    elif tool_type == "zap":
        scan_node = f"ScanEvent:{report_id}"
        alert_summary = parsed_data.get("alert_summary", {})
        G.add_node(scan_node, type="ScanEvent", report_id=report_id, tool=tool_name, generated_at=scan_date, 
                   alerts_high=alert_summary.get("High", 0), alerts_medium=alert_summary.get("Medium", 0), 
                   alerts_low=alert_summary.get("Low", 0), alerts_total=alert_summary.get("Total", 0))
        
        target_url = metadata.get("target_url", "Unknown_URL")
        domain_name = target_url.split("//")[-1].split("/")[0] if "//" in target_url else target_url
        
        app_node = f"WebApplication:{domain_name}"
        G.add_node(app_node, type="WebApplication", domain_name=domain_name)
        G.add_edge(scan_node, app_node, label="SCANNED_APP")
        
        for finding in parsed_data.get("findings", []):
            ep_url = finding.get('url', target_url)
            ep_node = f"Endpoint:{ep_url}"
            G.add_node(ep_node, type="Endpoint", url=ep_url)
            G.add_edge(app_node, ep_node, label="HAS_ENDPOINT")
            
            v_title = finding.get('name', 'Unknown Vulnerability')
            vuln_node = f"VulnerabilityType:{v_title}"
            G.add_node(vuln_node, type="VulnerabilityType", title=v_title, risk_level=finding.get('risk_level', 'Unknown'))
            G.add_edge(ep_node, vuln_node, label="VULNERABLE_TO")

    # API SECURITY AUDIT PARSER (API Topology)
    elif tool_type == "api":
        scan_node = f"ScanEvent:{report_id}"
        summary = parsed_data.get("summary", {})
        meta = parsed_data.get("metadata", {})
        G.add_node(scan_node, type="ScanEvent", report_id=report_id, tool="API Security Audit", generated_at=scan_date, 
                   audited_count=summary.get("audited"), findings_total=summary.get("Total", 0))
        
        target_url = meta.get("target_url", "Unknown_API")
        api_node = f"APIAsset:{target_url}"
        G.add_node(api_node, type="APIAsset", base_url=target_url)
        G.add_edge(scan_node, api_node, label="ASSESSED_API")
        
        for finding in parsed_data.get("findings", []):
            ep_url = finding.get('url', target_url)
            ep_node = f"APIEndpoint:{ep_url}"
            G.add_node(ep_node, type="APIEndpoint", url=ep_url, method=finding.get("method"))
            G.add_edge(api_node, ep_node, label="HAS_ROUTE")
            
            v_name = finding.get('name', 'Unknown API Vulnerability')
            vuln_node = f"VulnerabilityType:{v_name}"
            G.add_node(vuln_node, type="VulnerabilityType", title=v_name, risk_level=finding.get('risk_level'), 
                       tctr_impact=finding.get("tctr_magnitude"), ai_logic=finding.get("ai_breakdown")[:200])
            G.add_edge(ep_node, vuln_node, label="VULNERABLE_TO", priority=finding.get("priority"), cwe=finding.get("cwe"))

    # SSL PARSER (Infrastructure & Crypto Topology)
    elif tool_type == "ssl":
        scan_node = f"ScanEvent:{report_id}"
        G.add_node(scan_node, type="ScanEvent", report_id=report_id, timestamp=scan_date, tool="SSL Scanner")
        
        target = metadata.get("target", "Unknown_Target")
        ep_node = f"Endpoint:{target}"
        config = parsed_data.get("server_configuration", {})
        G.add_node(ep_node, type="Endpoint", target=target, overall_grade=metadata.get("grade", "N/A"), 
                   tls_compression=config.get("tls_compression"), secure_renegotiation=config.get("secure_renegotiation"), 
                   ocsp_stapling=config.get("ocsp_stapling"), fallback_scsv=config.get("fallback_scsv"))
        G.add_edge(scan_node, ep_node, label="ASSESSED")
        
        cert = parsed_data.get("certificate_chain", {})
        if cert:
            subject = cert.get('subject', 'Unknown')
            cert_node = f"Certificate:{subject}"
            G.add_node(cert_node, type="Certificate", subject=subject, issuer=cert.get('issuer'), 
                       leaf_expiry=cert.get('leaf_expiry'), signature_algorithm=cert.get("signature_algorithm"), key_type=cert.get("key_type"))
            G.add_edge(ep_node, cert_node, label="PRESENTS")
            
        for proto, ciphers in parsed_data.get("protocols", {}).items():
            proto_node = f"Protocol:{proto}"
            G.add_node(proto_node, type="Protocol", name=proto)
            G.add_edge(ep_node, proto_node, label="SUPPORTS")
            
            for c in ciphers:
                cipher_name = c.get('cipher')
                cipher_node = f"Cipher:{cipher_name}"
                G.add_node(cipher_node, type="Cipher", name=cipher_name, bits=c.get('bits'))
                G.add_edge(ep_node, cipher_node, label="NEGOTIATES", protocol=proto, status=c.get('status'))
                
        for vuln in parsed_data.get("vulnerabilities", []):
            v_name = vuln.get('name', 'SSL Vulnerability')
            vuln_node = f"VulnerabilityType:{v_name}"
            G.add_node(vuln_node, type="VulnerabilityType", name=v_name, severity=vuln.get("severity"), description=vuln.get("description", "")[:50], 
                       tctr_magnitude=vuln.get("tctr_magnitude_percent"), intelligence=vuln.get("intelligence_breakdown"))
            G.add_edge(ep_node, vuln_node, label="VULNERABLE_TO")

    # SQL INJECTION PARSER (Database Topology)
    elif tool_type == "sql":
        scan_node = f"ScanEvent:{report_id}"
        G.add_node(scan_node, type="ScanEvent", report_id=report_id, timestamp=scan_date, tool="SQLi Scanner", ml_threat_index=metadata.get("ml_threat_index"))
        
        target = metadata.get("target_url", "Unknown_URL")
        ep_node = f"Endpoint:{target}"
        G.add_node(ep_node, type="Endpoint", url=target, database_status=metadata.get("database_status"), data_extraction_possible=metadata.get("data_extraction"))
        G.add_edge(scan_node, ep_node, label="ASSESSED")
        
        db_fps = parsed_data.get("database_fingerprint", {})
        db_name = db_fps.get('detected_dbms', 'Unknown')
        db_ver = db_fps.get('version', 'Unknown')
        db_node = f"DBMS:{db_name}"
        G.add_node(db_node, type="DBMS", name=db_name, version=db_ver)
        G.add_edge(ep_node, db_node, label="BACKED_BY")
        
        schema_name = db_fps.get('current_database', 'Unknown')
        schema_node = f"DatabaseSchema:{schema_name}"
        G.add_node(schema_node, type="DatabaseSchema", name=schema_name)
        G.add_edge(ep_node, schema_node, label="CONNECTS_TO_SCHEMA")
        
        user_name = db_fps.get('current_user', 'Unknown')
        user_node = f"DatabaseUser:{user_name}"
        G.add_node(user_node, type="DatabaseUser", username=user_name)
        G.add_edge(ep_node, user_node, label="EXECUTES_AS")
        
        for vuln in parsed_data.get("vulnerabilities", []):
            v_name = vuln.get("title", "Unknown SQLi")
            vuln_node = f"VulnerabilityType:{v_name}"
            G.add_node(vuln_node, type="VulnerabilityType", title=v_name, risk_level=vuln.get("risk_level"), remediation=vuln.get("remediation", "")[:50])
            G.add_edge(ep_node, vuln_node, label="VULNERABLE_TO", injection_type=vuln.get("injection_type"), payload=vuln.get("payload"), parameter=vuln.get("parameter"))

    # SEMGREP PARSER (SAST / Code Topology)
    elif tool_type == "semgrep":
        scan_node = f"ScanEvent:{report_id}"
        summary = parsed_data.get("summary_counts", {})
        G.add_node(scan_node, type="ScanEvent", report_id=report_id, tool="Semgrep SAST", generated_at=scan_date, 
                   total_findings=summary.get("Total",0), error_count=summary.get("Error",0), warning_count=summary.get("Warning",0))
        
        for finding in parsed_data.get("findings", []):
            f_path = finding.get("file", "Unknown_File")
            file_node = f"CodeFile:{f_path}"
            G.add_node(file_node, type="CodeFile", file_path=f_path)
            G.add_edge(scan_node, file_node, label="ANALYZED_FILE")
            
            rule_name = finding.get("rule", "Unknown_Rule")
            rule_node = f"SastRule:{rule_name}"
            G.add_node(rule_node, type="SastRule", name=rule_name, severity=finding.get("severity"), description=finding.get("description", "")[:50], suggested_fix=finding.get("suggested_fix", "")[:50])
            
            G.add_edge(file_node, rule_node, label="VIOLATES_RULE", line_number=finding.get("line"), vulnerable_code=finding.get("vulnerable_code")[:50])

    # KILLCHAIN PARSER (Attack Path Topology)
    elif tool_type == "killchain":
        scan_node = f"ScanEvent:{report_id}"
        meta = parsed_data.get("metadata", {})
        risks = parsed_data.get("risk_summary", {})
        G.add_node(scan_node, type="ScanEvent", report_id=report_id, tool="Kill Chain Audit", generated_at=scan_date, 
                   profile=meta.get("profile"), aggression=meta.get("aggression"),
                   total_findings=risks.get("total",0), critical_count=risks.get("critical",0))
        
        phases = parsed_data.get("phase_analysis", {})
        recon = phases.get("recon", {})
        net = phases.get("network_audit", {})
        web = phases.get("web_audit", {})
        traffic = phases.get("traffic_audit", {})
        
        target = meta.get("target", "Target")
        target_node = f"Asset:{target}"
        G.add_node(target_node, type="Asset", name=target, ip=recon.get("target_ip"), server=recon.get("server"), 
                   os=net.get("os"), waf=web.get("waf"), packets_captured=traffic.get("packets"))
        G.add_edge(scan_node, target_node, label="AUDITED")
        
        for vuln in parsed_data.get("vulnerabilities", []):
            v_title = vuln.get("title", "Unknown Finding")
            vuln_node = f"VulnerabilityType:{v_title}"
            G.add_node(vuln_node, type="VulnerabilityType", title=v_title, severity=vuln.get("severity"), ml_risk=vuln.get("ml_threat_score"))
            G.add_edge(target_node, vuln_node, label="VULNERABLE_TO", cwe=vuln.get("cwe"))

    return G
