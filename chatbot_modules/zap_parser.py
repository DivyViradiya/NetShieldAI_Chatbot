import os
import re
import json
import uuid
from typing import Dict, Any
from datetime import datetime

# It's assumed pdf_extractor.py exists and works as intended.
try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    try:
        from pdf_extractor import extract_text_from_pdf
    except ImportError:
        print("Error: pdf_extractor.py not found. Please ensure it is in the same directory.")
        def extract_text_from_pdf(pdf_path: str) -> str:
            raise NotImplementedError("pdf_extractor.py not found.")

def parse_zap_report(raw_zap_text: str) -> Dict[str, Any]:
    """
    Parses raw ZAP report text into a structured dictionary.
    """
    raw_zap_text = re.sub(r'\r\n|\r', '\n', raw_zap_text)

    report = {
        "scan_metadata": {
            "tool": "Checkmarx ZAP Report",
            "report_id": str(uuid.uuid4()),
            "generated_at": None, "site": None, "zap_version": None
        },
        "summary": {
            "risk_counts": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "False Positives": 0},
            "total_alerts": 0, "alerts_by_name": [], "scanned_urls": set()
        },
        "vulnerabilities": []
    }

    # --- Metadata ---
    site_match = re.search(r"Site:\s*(https?://[^\s]+)", raw_zap_text)
    if site_match:
        report["scan_metadata"]["site"] = site_match.group(1).strip()
        report["summary"]["scanned_urls"].add(site_match.group(1).strip())

    generated_on_match = re.search(r"Generated on\s*(.*)", raw_zap_text)
    if generated_on_match:
        try:
            generated_datetime_str = generated_on_match.group(1).strip()
            report["scan_metadata"]["generated_at"] = datetime.strptime(generated_datetime_str, "%a, %d %b %Y %H:%M:%S").isoformat()
        except ValueError:
            report["scan_metadata"]["generated_at"] = generated_datetime_str

    zap_version_match = re.search(r"ZAP Version:\s*([\d.]+)", raw_zap_text)
    if zap_version_match:
        report["scan_metadata"]["zap_version"] = zap_version_match.group(1).strip()

    # --- Summary of Alerts Table ---
    summary_alerts_table_match = re.search(
        r"Summary of Alerts\s*Risk Level\s*Number of Alerts\s*"
        r"High\s+(\d+)\s*"
        r"Medium\s+(\d+)\s*"
        r"Low\s+(\d+)\s*"
        r"Informational\s+(\d+)\s*"
        r"False Positives:\s*(\d+)",
        raw_zap_text, re.DOTALL
    )
    if summary_alerts_table_match:
        groups = summary_alerts_table_match.groups()
        report["summary"]["risk_counts"]["High"] = int(groups[0])
        report["summary"]["risk_counts"]["Medium"] = int(groups[1])
        report["summary"]["risk_counts"]["Low"] = int(groups[2])
        report["summary"]["risk_counts"]["Informational"] = int(groups[3])
        report["summary"]["risk_counts"]["False Positives"] = int(groups[4])
        report["summary"]["total_alerts"] = sum(int(g) for g in groups[:4])

    # --- Alerts List by Name ---
    alerts_table_content_match = re.search(
        r"Alerts\s*Name\s*Risk Level\s*Number of\s*Instances\s*(.*?)(?=Alert Detail|Sequence Details|\Z)",
        raw_zap_text, re.DOTALL
    )
    if alerts_table_content_match:
        alerts_content = alerts_table_content_match.group(1).strip()
        alert_line_pattern = re.compile(r"^(.*?)\s+(High|Medium|Low|Informational)\s+(\d+)$", re.MULTILINE)
        for match in alert_line_pattern.finditer(alerts_content):
            report["summary"]["alerts_by_name"].append({
                "name": match.group(1).replace('\n', ' ').strip(),
                "risk_level": match.group(2).strip(),
                "instances_count": int(match.group(3))
            })

    # --- Alert Detail Sections ---
    alert_details_text_match = re.search(r"Alert Detail\s*(.*?)(?=\s*Sequence Details|\Z)", raw_zap_text, re.DOTALL)
    if alert_details_text_match:
        alert_details_text = alert_details_text_match.group(1)
        alert_detail_sections = re.split(r'\n(?=High\n|Medium\n|Low\n|Informational\n)', alert_details_text)
        
        for section in alert_detail_sections:
            section = section.strip()
            if not section: continue

            header_match = re.match(r"^(High|Medium|Low|Informational)\n(.*?)\n\nDescription", section, re.DOTALL)
            if not header_match: continue

            vuln = {
                "id": str(uuid.uuid4()), "name": header_match.group(2).replace('\n', ' ').strip(),
                "risk": header_match.group(1).strip(), "description": None, "urls": [], "instances_count": 0,
                "solution": None, "references": [], "cwe_id": None, "wasc_id": None, "plugin_id": None
            }
            
            # Use specific lookaheads to prevent over-matching
            def extract_main_field(field_name, text, stop_words):
                stop_pattern = '|'.join([f"\\n{word}\\n" for word in stop_words])
                match = re.search(rf"\n{field_name}\n(.*?)(?={stop_pattern}|\Z)", text, re.DOTALL)
                return re.sub(r'\s+', ' ', match.group(1)).strip() if match else None

            vuln["description"] = extract_main_field("Description", section, ["URL", "Solution", "Reference"])
            vuln["solution"] = extract_main_field("Solution", section, ["Reference", "CWE Id"])
            
            ref_match = re.search(r"\nReference\n(.*?)(?=\nCWE Id|\nPlugin Id|\Z)", section, re.DOTALL)
            if ref_match:
                vuln["references"] = [url.strip() for url in ref_match.group(1).split('\n') if url.strip().startswith('http')]

            cwe_match = re.search(r"CWE Id\s+(\d+)", section)
            if cwe_match: vuln["cwe_id"] = int(cwe_match.group(1))
            wasc_match = re.search(r"WASC Id\s+(\d+)", section)
            if wasc_match: vuln["wasc_id"] = int(wasc_match.group(1))
            plugin_match = re.search(r"Plugin Id\s+(\d+)", section)
            if plugin_match: vuln["plugin_id"] = int(plugin_match.group(1))

            # FINAL CORRECTION: Accurately parse each field within an instance
            instance_blocks = re.split(r'\nURL\n', section)
            for block in instance_blocks[1:]:
                instance_detail = {"url": None, "method": None, "parameter": None, "attack": None, "evidence": None, "other_info": None}
                
                url_part, *rest = block.split('\n', 1)
                instance_detail["url"] = url_part.strip()
                report["summary"]["scanned_urls"].add(instance_detail["url"])
                
                if rest:
                    field_text = rest[0]
                    field_map = {}
                    # Use a regex to find all key-value pairs in the instance block
                    pattern = re.compile(r"^(Method|Parameter|Attack|Evidence|Other Info)\n(.*?)(?=\n(?:Method|Parameter|Attack|Evidence|Other Info)$|\Z)", re.DOTALL | re.MULTILINE)
                    for match in pattern.finditer(field_text):
                        key = match.group(1)
                        value = re.sub(r'\s+', ' ', match.group(2)).strip()
                        field_map[key] = value

                    instance_detail["method"] = field_map.get('Method')
                    instance_detail["parameter"] = field_map.get('Parameter')
                    instance_detail["attack"] = field_map.get('Attack')
                    instance_detail["evidence"] = field_map.get('Evidence')
                    instance_detail["other_info"] = field_map.get('Other Info')
                
                vuln["urls"].append(instance_detail)
            
            count_match = re.search(r"\nInstances\s+(\d+)", section)
            vuln["instances_count"] = int(count_match.group(1)) if count_match else len(vuln["urls"])
            
            report["vulnerabilities"].append(vuln)

    report["summary"]["scanned_urls"] = sorted(list(report["summary"]["scanned_urls"]))
    return report

def process_zap_report_file(pdf_path: str) -> Dict[str, Any]:
    # This function remains the same
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"ZAP report not found: {pdf_path}")
    print(f"Processing ZAP report: {pdf_path}")
    try:
        raw_text = extract_text_from_pdf(pdf_path)
        if not raw_text.strip():
            raise ValueError("Extracted text from PDF is empty.")
        report_data = parse_zap_report(raw_text)
        report_data["file_metadata"] = {
            "filename": os.path.basename(pdf_path),
            "file_size": os.path.getsize(pdf_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(pdf_path)).isoformat()
        }
        return report_data
    except Exception as e:
        print(f"Error processing ZAP report {pdf_path}: {e}")
        raise

if __name__ == "__main__":
    # This main block remains the same
    import sys
    if not os.path.exists("pdf_extractor.py"):
        print("Warning: pdf_extractor.py not found. Please create it.")
    if len(sys.argv) > 1:
        report_path = sys.argv[1]
        try:
            report = process_zap_report_file(report_path)
            print(f"Successfully processed ZAP report: {report_path}")
            print(f"Found {len(report['vulnerabilities'])} unique vulnerability types.")
            print(f"Risk counts: {report['summary']['risk_counts']}")
            output_path = os.path.splitext(report_path)[0] + "_parsed.json"
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"Structured output saved to: {output_path}")
        except Exception as e:
            print(f"An error occurred: {e}")
            sys.exit(1)
    else:
        print("Usage: python zap_parser.py <path_to_zap_report.pdf>")