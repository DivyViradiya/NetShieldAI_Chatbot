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
            
            G.add_node(port_node, type="Port", port_id=port_id, number=p_num, protocol=p_proto)
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

    # ZAP / API PARSERS (Web Topology)
    elif tool_type in ["zap", "api"]:
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
            
            v_name = finding.get('name', 'Unknown Vulnerability')
            vuln_node = f"VulnerabilityType:{v_name}"
            G.add_node(vuln_node, type="VulnerabilityType", name=v_name, risk_level=finding.get('risk_level', 'Unknown'), 
                       description=finding.get("description", "")[:50], solution=finding.get("solution", "")[:50])
            
            G.add_edge(ep_node, vuln_node, label="VULNERABLE_TO", confidence=finding.get('confidence', 'Unknown'), predicted_score=finding.get('predicted_score', 0))

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
            G.add_node(vuln_node, type="VulnerabilityType", name=v_name, severity=vuln.get("severity"), description=vuln.get("description", "")[:50])
            G.add_edge(ep_node, vuln_node, label="VULNERABLE_TO")

    # SQL INJECTION PARSER (Database Topology)
    elif tool_type == "sql":
        scan_node = f"ScanEvent:{report_id}"
        G.add_node(scan_node, type="ScanEvent", report_id=report_id, timestamp=scan_date, tool="SQLi Scanner")
        
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
            G.add_edge(ep_node, vuln_node, label="VULNERABLE_TO", injection_type=vuln.get("injection_type"), payload=vuln.get("payload"))

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
        sim_node = f"AttackSimulation:{report_id}"
        total_critical = sum(1 for v in parsed_data.get("vulnerabilities", []) if v.get("severity", "").upper() == "CRITICAL")
        total_high = sum(1 for v in parsed_data.get("vulnerabilities", []) if v.get("severity", "").upper() == "HIGH")
        G.add_node(sim_node, type="AttackSimulation", report_id=report_id, target_profile=metadata.get("profile", "full_audit"), scan_date=scan_date, total_critical=total_critical, total_high=total_high)
        
        recon_node = "KillchainPhase:Reconnaissance"
        weap_node = "KillchainPhase:Weaponization"
        G.add_node(recon_node, type="KillchainPhase", name="Reconnaissance")
        G.add_node(weap_node, type="KillchainPhase", name="Weaponization")
        
        G.add_edge(sim_node, recon_node, label="MAPPED_TO")
        G.add_edge(sim_node, weap_node, label="MAPPED_TO")
        
        phases = parsed_data.get("phase_analysis", {})
        
        recon = phases.get("recon", {})
        if "target_ip" in recon:
            host_node = f"Host:{recon['target_ip']}"
            G.add_node(host_node, type="Host", ip_address=recon['target_ip'])
            G.add_edge(host_node, recon_node, label="DISCOVERED_IN")
            
        weap = phases.get("weaponization", {})
        stack_node = None
        if "server" in weap or "language" in weap:
            stack_node = f"TechStack:{weap.get('server', 'Unknown')}_{weap.get('language', 'Unknown')}"
            G.add_node(stack_node, type="TechStack", server_type=weap.get('server'), language=weap.get('language'))
            G.add_edge(stack_node, weap_node, label="WEAPONIZED_DURING")
            
        for vuln in parsed_data.get("vulnerabilities", []):
            ep_url = vuln.get("evidence", "Unknown_Endpoint")
            ep_node = f"Endpoint:{ep_url}"
            G.add_node(ep_node, type="Endpoint", url=ep_url)
            
            if stack_node:
                G.add_edge(ep_node, stack_node, label="RUNS_ON")
                
            v_name = vuln.get("title", "Unknown")
            vuln_node = f"VulnerabilityType:{v_name}"
            G.add_node(vuln_node, type="VulnerabilityType", title=v_name, cwe=vuln.get("cwe_id", ""), severity=vuln.get("severity"))
            
            G.add_edge(ep_node, vuln_node, label="HAS_WEAPONIZED_EXPLOIT", payload=vuln.get("payload"), parameter=vuln.get("parameter"), evidence=vuln.get("evidence"))
            G.add_edge(vuln_node, weap_node, label="UTILIZED_IN")

    return G
