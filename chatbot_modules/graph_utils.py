import networkx as nx
import json
import logging
import os
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# --- CWE DATA CACHE ---
_CWE_MAPPING = {}
_CWE_TEXT_MAPPING = {}

def _load_cwe_mapping():
    """Lazy-loads the CWE risk mapping from the JSON profile."""
    global _CWE_MAPPING
    if _CWE_MAPPING:
        return _CWE_MAPPING
    
    # Path relative to chatbot_modules/graph_utils.py -> ../CWE_Profiles/cwe_profiles_mapping.json
    mapping_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                "CWE_Profiles", "cwe_profiles_mapping.json")
    try:
        if os.path.exists(mapping_path):
            with open(mapping_path, 'r') as f:
                _CWE_MAPPING = json.load(f)
            logger.info(f"Successfully loaded {len(_CWE_MAPPING)} CWE profiles from {mapping_path}")
        else:
            logger.error(f"CWE mapping file NOT FOUND at: {mapping_path}")
    except Exception as e:
        logger.error(f"Error reading CWE mapping: {e}")
    return _CWE_MAPPING

def _load_cwe_text_mapping():
    """Lazy-loads textual descriptions from the pre-converted CWE JSON summary."""
    global _CWE_TEXT_MAPPING
    if _CWE_TEXT_MAPPING:
        return _CWE_TEXT_MAPPING
    
    json_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                             "CWE_Profiles", "cwe_text_summary.json")
    try:
        if os.path.exists(json_path):
            with open(json_path, 'r', encoding='utf-8') as f:
                _CWE_TEXT_MAPPING = json.load(f)
            logger.info(f"Successfully loaded {len(_CWE_TEXT_MAPPING)} CWE text descriptions.")
    except Exception as e:
        logger.error(f"Failed to load CWE textual data: {e}")
    return _CWE_TEXT_MAPPING

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

def _get_or_create_node(G: nx.MultiDiGraph, node_id: str, **kwargs) -> str:
    """Helper for Entity Resolution: Updates attributes of existing nodes or creates new ones."""
    if G.has_node(node_id):
        # Update existing node attributes with any new data provided
        for k, v in kwargs.items():
            if v is not None:
                G.nodes[node_id][k] = v
    else:
        G.add_node(node_id, **kwargs)
    return node_id

def _enrich_cwe_node(G: nx.MultiDiGraph, cwe_id: str):
    """Enriches a CWE node with risk metrics from the mapping file."""
    if not cwe_id or not cwe_id.startswith("CWE-"):
        return
    
    mapping = _load_cwe_mapping()
    
    # Extract numeric part (e.g., "79" from "CWE-79")
    numeric_id = cwe_id.replace("CWE-", "").strip()
    cwe_data = mapping.get(numeric_id, {})
    
    if not cwe_data:
        logger.debug(f"No risk data found for {cwe_id} (numeric key: {numeric_id})")
        return

    _get_or_create_node(G, f"CWE:{cwe_id}", 
                        type="CWE", 
                        cwe_id=cwe_id, 
                        risk_score=cwe_data.get("actual_risk_score"),
                        base_score=cwe_data.get("base_score_mean"),
                        cve_count=cwe_data.get("cve_count"))
    
    # Textual Enrichment
    text_mapping = _load_cwe_text_mapping()
    text_data = text_mapping.get(numeric_id, {})
    if text_data:
        G.nodes[f"CWE:{cwe_id}"].update({
            "name": text_data.get("name"),
            "summary": text_data.get("summary"),
            "description": text_data.get("description")
        })

def generate_graph_summary(graph: nx.MultiDiGraph) -> str:
    """Creates a structured text summarization of the graph for LLM context."""
    if graph.number_of_nodes() == 0:
        return "No logical graph data available for this session."
    
    # Calculate some basic metrics for high-level reasoning
    hosts = [n for n, d in graph.nodes(data=True) if d.get('type') == 'Host']
    vulns = [n for n, d in graph.nodes(data=True) if d.get('type') == 'VulnerabilityType']
    
    summary = f"### Security Topology Intelligence ({graph.number_of_nodes()} Entities detected)\n"
    summary += f"- **Assets**: {items_to_str(hosts)}\n"
    
    # Critical Paths / High Risk Nodes
    high_risk_vulns = []
    for n, d in graph.nodes(data=True):
        if d.get('type') == 'VulnerabilityType':
            level = str(d.get('risk_level', '')).upper()
            if 'HIGH' in level or 'CRITICAL' in level:
                # Try to get the name/summary from the connected CWE node if available
                node_label = n.replace("VulnerabilityType:", "")
                cwe_nodes = [v for u, v, data in graph.out_edges(n, data=True) if data.get('label') in ['MAPPED_TO', 'ROOT_CAUSE']]
                if cwe_nodes and graph.nodes[cwe_nodes[0]].get('summary'):
                    summary_text = graph.nodes[cwe_nodes[0]].get('summary')
                    high_risk_vulns.append(f"{node_label} ({summary_text})")
                else:
                    high_risk_vulns.append(node_label)

    if high_risk_vulns:
        summary += f"- **Critical Vulnerabilities**: {', '.join(high_risk_vulns)}\n"

    summary += "\n#### Topological Relationships:\n"
    for u, v, data in graph.edges(data=True):
        edge_label = data.get('label', 'CONNECTED_TO')
        # Skip internal ScanEvent noise to keep summary focused on topology
        if "ScanEvent" in u: continue
        
        props = ", ".join([f"{k}='{v}'" for k, v in data.items() if k not in ['label', 'report_id']])
        prop_str = f" ({props})" if props else ""
        summary += f"- {u} --[{edge_label}]--> {v}{prop_str}\n"
    
    return summary

def items_to_str(items: List[str]) -> str:
    return ", ".join([i.split(":", 1)[-1] for i in items]) if items else "None"

def run_security_inference(G: nx.MultiDiGraph):
    """
    Runs an inference pass to propagate risk and criticality across the topology.
    """
    # 1. Criticality Tagging
    critical_ports = {3306, 5432, 27017, 3389, 22, 6379, 1521}
    for n, d in G.nodes(data=True):
        if d.get('type') == 'Port' and d.get('num') in critical_ports:
            G.nodes[n]['criticality'] = 'HIGH'
            G.nodes[n]['note'] = 'High-Value Data Service/Management Port'

    # 2. Risk Propagation (Blast Radius)
    # If a node is vulnerable, tag its neighbors as 'INDIRECTLY_EXPOSED'
    vulnerable_nodes = [n for n, d in G.nodes(data=True) if d.get('type') == 'VulnerabilityType']
    for v_node in vulnerable_nodes:
        # Find who is vulnerable to this
        for target in G.predecessors(v_node):
            G.nodes[target]['security_state'] = 'VULNERABLE'
            # Propagate to whoever uses this target (Blast Radius)
            for upstream in G.predecessors(target):
                if G.nodes[upstream].get('type') in ['WebApplication', 'Host']:
                    G.nodes[upstream]['blast_radius'] = 'AT_RISK'

def build_graph_from_report(existing_graph: nx.MultiDiGraph, parsed_data: Dict[str, Any], tool_type: str) -> nx.MultiDiGraph:
    """
    Ingests parsed JSON and builds a unified cross-tool security model.
    """
    G = existing_graph
    
    metadata = parsed_data.get("metadata") or parsed_data.get("scan_metadata", {})
    report_id = metadata.get("report_id", "Unknown")
    scan_date = metadata.get("scan_date", metadata.get("generated_at", "Unknown"))
    
    # Common Event Node
    scan_node = f"ScanEvent:{report_id}"
    _get_or_create_node(G, scan_node, type="ScanEvent", tool=tool_type, timestamp=scan_date)

    # NMAP (Network Core)
    if tool_type == "nmap":
        target_ip = metadata.get("target_ip")
        host_node = _get_or_create_node(G, f"Host:{target_ip}", type="Host", ip=target_ip, status=metadata.get("host_status", "UP"))
        G.add_edge(scan_node, host_node, label="ASSESSED")
        
        for p in parsed_data.get("open_ports", []):
            p_id = f"{p.get('port')}/{p.get('protocol', 'tcp')}"
            port_node = _get_or_create_node(G, f"Port:{p_id}", type="Port", num=p.get('port'), proto=p.get('protocol'))
            G.add_edge(host_node, port_node, label="EXPOSES", state=p.get('state'))
            
            s_name = p.get('service_name', 'Unknown')
            service_node = _get_or_create_node(G, f"Service:{s_name}", type="Service", name=s_name, version=p.get('service_version'))
            G.add_edge(port_node, service_node, label="RUNS")
            
            if p.get('tctr_magnitude_percent'):
                G.nodes[port_node]['tctr_score'] = p.get('tctr_magnitude_percent')

    # ZAP (Web Application Findings)
    elif tool_type == "zap":
        target_url = metadata.get("target_url", "")
        domain = target_url.split("//")[-1].split("/")[0] if "//" in target_url else target_url
        app_node = _get_or_create_node(G, f"WebApplication:{domain}", type="WebApplication", domain=domain)
        
        # Cross-tool Entity Resolution: Try to link Domain to IP if we have Nmap data
        for n, d in G.nodes(data=True):
            if d.get('type') == 'Host' and d.get('ip') and d.get('ip') in target_url:
                G.add_edge(app_node, n, label="RESOLVES_TO")
                G.add_edge(n, app_node, label="SERVES")

        for f in parsed_data.get("findings", []):
            ep_url = f.get('url', target_url)
            ep_node = _get_or_create_node(G, f"Endpoint:{ep_url}", type="Endpoint", url=ep_url)
            G.add_edge(app_node, ep_node, label="CONTAINS")
            
            v_name = f.get('name', 'Finding')
            vuln_node = _get_or_create_node(G, f"VulnerabilityType:{v_name}", type="VulnerabilityType", title=v_name, risk_level=f.get('risk_level'))
            G.add_edge(ep_node, vuln_node, label="HAS_VULN", description=f.get('description', '')[:100])
            
            # CWE Enrichment
            cwe_id = None
            if 'cweid' in f and f['cweid']: 
                cwe_id = f"CWE-{f['cweid']}"
            elif 'cwe' in f and f['cwe']: 
                cwe_id = f['cwe'] if f['cwe'].startswith("CWE-") else f"CWE-{f['cwe']}"
            
            if cwe_id:
                _enrich_cwe_node(G, cwe_id)
                G.add_edge(vuln_node, f"CWE:{cwe_id}", label="MAPPED_TO")

    # PCAP (Traffic / Lateral Movement)
    elif tool_type == "pcap":
        for conv in parsed_data.get("active_conversations", []):
            src_ip = conv.get('src_ip')
            dst_ip = conv.get('dst_ip')
            if src_ip and dst_ip:
                src_node = _get_or_create_node(G, f"Host:{src_ip}", type="Host", ip=src_ip)
                dst_node = _get_or_create_node(G, f"Host:{dst_ip}", type="Host", ip=dst_ip)
                G.add_edge(src_node, dst_node, label="TALKS_TO", proto=conv.get('protocol'), byte_count=conv.get('bytes'))

    # KILLCHAIN (Attack Sequential Path)
    elif tool_type == "killchain":
        phases = parsed_data.get("phase_analysis", {})
        target = metadata.get("target", "Asset")
        recon_ip = phases.get("recon", {}).get("target_ip")
        asset_node = _get_or_create_node(G, f"Asset:{target}", type="Asset", ip=recon_ip)
        
        # Sequence path: Recon -> Network -> Web -> Traffic
        p_recon = _get_or_create_node(G, f"Phase:Recon", type="AttackPhase", name="Reconnaissance")
        p_net = _get_or_create_node(G, f"Phase:Network", type="AttackPhase", name="Network Exploitation")
        p_web = _get_or_create_node(G, f"Phase:Web", type="AttackPhase", name="Web Assessment")
        
        G.add_edge(p_recon, p_net, label="NEXT_PHASE")
        G.add_edge(p_net, p_web, label="NEXT_PHASE")
        G.add_edge(asset_node, p_recon, label="OBSERVED_IN")

        for v in parsed_data.get("vulnerabilities", []):
            v_title = v.get('title', 'Finding')
            v_node = _get_or_create_node(G, f"VulnerabilityType:{v_title}", type="VulnerabilityType", risk_level=v.get('severity'))
            G.add_edge(asset_node, v_node, label="VULNERABLE_TO", score=v.get('ml_threat_score'))
            
            if v.get('cwe'):
                cwi = str(v['cwe'])
                cwe_id = cwi if cwi.startswith("CWE-") else f"CWE-{cwi}"
                _enrich_cwe_node(G, cwe_id)
                G.add_edge(v_node, f"CWE:{cwe_id}", label="ROOT_CAUSE")

    # SEMGREP (SAST)
    elif tool_type == "semgrep":
        for f in parsed_data.get("findings", []):
            file_path = f.get('file', 'Unknown')
            file_node = _get_or_create_node(G, f"CodeFile:{file_path}", type="CodeFile", path=file_path)
            vuln_node = _get_or_create_node(G, f"VulnerabilityType:{f.get('rule')}", type="VulnerabilityType", risk_level=f.get('severity'))
            G.add_edge(file_node, vuln_node, label="CONTAINS_FLAW", line=f.get('line'))
            
            project_node = _get_or_create_node(G, "Asset:ProjectRoot", type="Project")
            G.add_edge(project_node, file_node, label="PART_OF")

    # Run security inference to propagate findings
    run_security_inference(G)

    return G
