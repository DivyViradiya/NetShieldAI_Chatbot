import os
import re
import json
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Import the PDF extractor for text extraction
try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    # This block is for standalone execution or when pdf_extractor is not in the same package
    # In a real scenario, you'd ensure pdf_extractor.py is available or handle its absence.
    # For this exercise, we'll assume it's either present or a dummy is created by __main__
    # if this script is run directly.
    print("Warning: pdf_extractor not found as a package module. Attempting direct import.")
    try:
        from pdf_extractor import extract_text_from_pdf
    except ImportError:
        print("Error: pdf_extractor.py not found. Please ensure it's in the same directory or install pypdf and run the script once to generate a dummy.")
        # Define a dummy function to prevent immediate crash if not found during import
        def extract_text_from_pdf(pdf_path: str) -> str:
            raise NotImplementedError("pdf_extractor.py not found or not implemented. Cannot extract text from PDF.")


def parse_zap_report(raw_zap_text: str) -> Dict[str, Any]:
    """
    Parses raw ZAP report text into a structured dictionary based on the provided PDF format.

    Args:
        raw_zap_text: The raw text content of a ZAP report.

    Returns:
        dict: A structured dictionary containing ZAP report information.
    """
    # Standardize newlines for easier regex matching
    raw_zap_text = re.sub(r'\r\n', '\n', raw_zap_text)
    raw_zap_text = re.sub(r'\r', '\n', raw_zap_text)

    report = {
        "scan_metadata": {
            "tool": "Checkmarx ZAP Report",
            "report_id": str(uuid.uuid4()),
            "generated_at": None,
            "site": None,
            "zap_version": None
        },
        "summary": {
            "risk_counts": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "False Positives": 0},
            "total_alerts": 0,
            "alerts_by_name": [],
            "scanned_urls": set()
        },
        "vulnerabilities": []
    }

    # --- Extract Scan Metadata ---
    site_match = re.search(r"Site: (https?://[^\s]+)", raw_zap_text)
    if site_match:
        report["scan_metadata"]["site"] = site_match.group(1).strip()
        report["summary"]["scanned_urls"].add(site_match.group(1).strip())

    generated_on_match = re.search(r"Generated on (.*)", raw_zap_text)
    if generated_on_match:
        try:
            generated_datetime_str = generated_on_match.group(1).strip()
            # The format is "Fri, 4 Jul 2025 10:28:39"
            report["scan_metadata"]["generated_at"] = datetime.strptime(generated_datetime_str, "%a, %d %b %Y %H:%M:%S").isoformat()
        except ValueError:
            report["scan_metadata"]["generated_at"] = generated_datetime_str

    zap_version_match = re.search(r"iSec Engine 1.0 Version: (\d+\.\d+\.\d+)", raw_zap_text)
    if zap_version_match:
        report["scan_metadata"]["zap_version"] = zap_version_match.group(1).strip()

    # --- Parse "Summary of Alerts" Table ---
    # Updated regex to match the format: "Risk Level Number of Alerts\nHigh 3\nMedium 4..."
    summary_alerts_table_match = re.search(
        r"Summary of Alerts\s*\n"
        r"Risk Level\s+Number of Alerts\s*\n" # Matches "Risk Level Number of Alerts"
        r"High\s+(\d+)\s*\n" # Matches "High 3"
        r"Medium\s+(\d+)\s*\n" # Matches "Medium 4"
        r"Low\s+(\d+)\s*\n"
        r"Informational\s+(\d+)\s*\n"
        r"False Positives:\s*(\d+)", # Matches "False Positives: 0"
        raw_zap_text,
        re.DOTALL
    )

    if summary_alerts_table_match:
        report["summary"]["risk_counts"]["High"] = int(summary_alerts_table_match.group(1))
        report["summary"]["risk_counts"]["Medium"] = int(summary_alerts_table_match.group(2))
        report["summary"]["risk_counts"]["Low"] = int(summary_alerts_table_match.group(3))
        report["summary"]["risk_counts"]["Informational"] = int(summary_alerts_table_match.group(4))
        report["summary"]["risk_counts"]["False Positives"] = int(summary_alerts_table_match.group(5))
        report["summary"]["total_alerts"] = sum(report["summary"]["risk_counts"][key] for key in ["High", "Medium", "Low", "Informational"])

    # --- Parse "Alerts" Table (Summary of Names and Instances) ---
    # Updated regex for the header and the content to match the new format
    alerts_table_content_match = re.search(
        r"Alerts\s*\n"
        r"Name\s+Risk Level\s*Number of\s*\n\s*Instances\s*\n" # Matches "Name Risk LevelNumber of\nInstances"
        r"(.*?)(?=Alert Detail)",
        raw_zap_text,
        re.DOTALL
    )

    if alerts_table_content_match:
        alerts_content = alerts_table_content_match.group(1).strip()
        
        # Updated regex to capture Name, Risk Level, and Instances without quotes
        # This pattern is more robust for names that might span multiple lines
        alert_line_pattern = re.compile(
            r"(.+?)\s+" # Name (can be multi-line, non-greedy, ends with space before risk)
            r"(High|Medium|Low|Informational)\s+" # Risk Level
            r"(\d+)", # Instances
            re.DOTALL
        )
        
        for match in alert_line_pattern.finditer(alerts_content):
            name = match.group(1).replace('\n', ' ').strip() # Replace newlines in name with spaces
            risk = match.group(2).strip()
            instances = int(match.group(3))

            report["summary"]["alerts_by_name"].append({
                "name": name,
                "risk_level": risk,
                "instances_count": instances
            })

    # --- Parse "Alert Detail" Sections ---
    # Find the start of the first "Alert Detail" section
    alert_detail_start_match = re.search(r"Alert Detail", raw_zap_text)
    if not alert_detail_start_match:
        # No alert details found, return report as is
        report["summary"]["scanned_urls"] = list(report["summary"]["scanned_urls"])
        return report

    # Get the text from the start of "Alert Detail" onwards
    alert_details_text = raw_zap_text[alert_detail_start_match.end():].strip()

    # Find the start of "Sequence Details" to limit the alert detail parsing
    sequence_details_match = re.search(r"Sequence Details", alert_details_text)
    if sequence_details_match:
        alert_details_text = alert_details_text[:sequence_details_match.start()].strip()


    # Split this text into individual alert detail blocks
    # Each block starts with a Risk Level (High, Medium, Low, Informational) followed immediately by the alert name
    # and then the "Description" keyword.
    # The pattern now accounts for the risk and name being concatenated, and the description starting immediately.
    alert_detail_sections = re.split(
        r"(?=(?:High|Medium|Low|Informational)[A-Za-z\s()-]+?\nDescription)", # Lookahead for next alert start
        alert_details_text,
        re.MULTILINE
    )
    # Filter out any empty strings that might result from the split
    alert_detail_sections = [s.strip() for s in alert_detail_sections if s.strip()]

    for section in alert_detail_sections:
        if not section.strip():
            continue # Skip empty sections

        vuln = {
            "id": str(uuid.uuid4()),
            "name": None,
            "risk": None,
            "description": None,
            "urls": [], # To store URL, Method, Parameter, Attack, Evidence, Other Info
            "instances_count": 0,
            "solution": None,
            "references": [],
            "cwe_id": None,
            "wasc_id": None,
            "plugin_id": None
        }

        # Extract Risk Level and Name (now concatenated, e.g., "HighCross Site Scripting (DOM Based)")
        # This regex captures the risk and then the rest of the line as the name, until "Description"
        risk_name_match = re.match(
            r"^\s*(High|Medium|Low|Informational)(.+?)\s*\nDescription",
            section,
            re.DOTALL | re.MULTILINE
        )

        if risk_name_match:
            vuln["risk"] = risk_name_match.group(1).strip()
            # Remove the risk prefix from the name and clean up newlines/extra spaces
            name_raw = risk_name_match.group(2).strip()
            vuln["name"] = re.sub(r'\s+', ' ', name_raw).strip()
        else:
            # If we can't get both name and risk, it's likely not a valid alert start for this section
            continue

        # Description (now directly follows "Description" label, can be multi-line)
        # Use a non-greedy match and lookahead for the next field label or end of section
        desc_match = re.search(
            r"Description\s*(.*?)(?=URL|Method|Parameter|Attack|Evidence|Other\s*Info|Instances|Solution|Reference|CWE Id|WASC Id|Plugin Id|\Z)",
            section,
            re.DOTALL
        )
        if desc_match:
            cleaned_description = re.sub(r'\s+', ' ', desc_match.group(1)).strip()
            vuln["description"] = cleaned_description

        # URLs, Method, Parameter, Attack, Evidence, Other Info (can have multiple instances)
        # Split by 'URL' to get individual instances. 'URL' can be followed immediately by http.
        instance_sections = re.split(r"(?=URLhttps?://)", section)
        # The first element might be the description and other fields before the first URL
        # We only care about sections starting with 'URL'
        instance_sections = [s for s in instance_sections if s.strip().startswith("URLhttp")]

        for inst_section in instance_sections:
            instance_detail = {
                "url": None,
                "method": None,
                "parameter": None,
                "attack": None,
                "evidence": None,
                "other_info": None
            }

            # Extract URL (directly follows "URL" label, can be multi-line due to wrapping)
            url_m = re.search(r"URL(https?://[^\s]+(?:[\s\S]*?)(?=\nMethod|\nParameter|\nAttack|\nEvidence|\nOther Info|\Z))", inst_section)
            if url_m:
                instance_detail["url"] = re.sub(r'\s+', '', url_m.group(1)).strip() # Remove all whitespace for URL
                report["summary"]["scanned_urls"].add(instance_detail["url"])

            # Extract Method
            method_m = re.search(r"Method\s*([^\n]+)", inst_section)
            if method_m:
                instance_detail["method"] = method_m.group(1).strip()

            # Extract Parameter (can be empty or multi-line)
            param_m = re.search(
                r"Parameter\s*(.*?)(?=(?:Attack|Evidence|Other Info|URL|Instances|Solution|Reference|CWE Id|WASC Id|Plugin Id|\Z))",
                inst_section,
                re.DOTALL
            )
            if param_m:
                instance_detail["parameter"] = param_m.group(1).strip()

            # Extract Attack (can be multi-line)
            attack_m = re.search(
                r"Attack\s*(.*?)(?=(?:Evidence|Other Info|URL|Instances|Solution|Reference|CWE Id|WASC Id|Plugin Id|\Z))",
                inst_section,
                re.DOTALL
            )
            if attack_m:
                instance_detail["attack"] = attack_m.group(1).strip()

            # Extract Evidence (can be empty or multi-line)
            evidence_m = re.search(
                r"Evidence\s*(.*?)(?=(?:Other Info|URL|Instances|Solution|Reference|CWE Id|WASC Id|Plugin Id|\Z))",
                inst_section,
                re.DOTALL
            )
            if evidence_m:
                instance_detail["evidence"] = evidence_m.group(1).strip()

            # Extract Other Info (can be multi-line)
            other_info_m = re.search(
                r"Other Info\s*(.*?)(?=(?:URL|Instances|Solution|Reference|CWE Id|WASC Id|Plugin Id|\Z))",
                inst_section,
                re.DOTALL
            )
            if other_info_m:
                instance_detail["other_info"] = re.sub(r'\s+', ' ', other_info_m.group(1)).strip() # Clean up newlines

            # If any of the main fields (URL, Method, Parameter, Attack, Evidence, Other Info) were found, add the instance
            if any(instance_detail.values()):
                vuln["urls"].append(instance_detail)


        # Instances Count
        instances_match = re.search(r"Instances\s*(\d+)", section)
        if instances_match:
            vuln["instances_count"] = int(instances_match.group(1))

        # Solution (can be multi-line)
        solution_match = re.search(
            r"Solution\s*(.*?)(?=Reference|CWE Id|WASC Id|Plugin Id|\Z)",
            section,
            re.DOTALL
        )
        if solution_match:
            cleaned_solution = re.sub(r'\s+', ' ', solution_match.group(1)).strip()
            vuln["solution"] = cleaned_solution

        # References (can be multi-line, multiple URLs)
        references_section_match = re.search(
            r"Reference\s*(.*?)(?=CWE Id|WASC Id|Plugin Id|\Z)",
            section,
            re.DOTALL
        )
        if references_section_match:
            refs_text = references_section_match.group(1).strip()
            # Split by newlines and filter out empty strings, then clean
            raw_refs = [line.strip() for line in refs_text.split('\n') if line.strip()]
            # Filter out lines that might be part of the solution or other fields
            filtered_refs = [ref for ref in raw_refs if ref.startswith("http")]
            vuln["references"] = filtered_refs

        # CWE Id, WASC Id, Plugin Id (directly follow their labels, Plugin Id can be empty)
        cwe_match = re.search(r"CWE Id\s*(\d+)", section)
        if cwe_match:
            vuln["cwe_id"] = int(cwe_match.group(1))

        wasc_match = re.search(r"WASC Id\s*(\d+)", section)
        if wasc_match:
            vuln["wasc_id"] = int(wasc_match.group(1))

        # Plugin Id can be present but empty, or followed by a number
        plugin_match = re.search(r"Plugin Id\s*(\d*)", section) # Capture optional digits
        if plugin_match and plugin_match.group(1).strip(): # Check if captured group is not empty
            vuln["plugin_id"] = int(plugin_match.group(1).strip())
        else:
            vuln["plugin_id"] = None # Explicitly set to None if empty or not found

        report["vulnerabilities"].append(vuln)

    # Convert sets to lists for JSON serialization
    report["summary"]["scanned_urls"] = list(report["summary"]["scanned_urls"])

    return report

def process_zap_report_file(pdf_path: str) -> Dict[str, Any]:
    """
    Processes a ZAP report PDF file and returns structured data.

    Args:
        pdf_path: Path to the ZAP report PDF file.

    Returns:
        dict: Structured ZAP report data.
    """
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"ZAP report not found: {pdf_path}")

    print(f"Processing ZAP report: {pdf_path}")

    # Extract text from PDF
    try:
        raw_text = extract_text_from_pdf(pdf_path)
        if not raw_text.strip():
            raise ValueError("Extracted text is empty or contains only whitespace.")

        # Parse the ZAP report
        report_data = parse_zap_report(raw_text)

        # Add file metadata
        report_data["file_metadata"] = {
            "filename": os.path.basename(pdf_path),
            "file_size": os.path.getsize(pdf_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(pdf_path)).isoformat()
        }

        return report_data

    except Exception as e:
        print(f"Error processing ZAP report {pdf_path}: {str(e)}")
        raise

if __name__ == "__main__":
    # Example usage
    import sys
    
    # This check needs to be adjusted for the environment it runs in.
    # In a typical script, you'd ensure pdf_extractor is available.
    # Here, we'll ensure a dummy is created if it's missing for standalone execution.
    if not os.path.exists("pdf_extractor.py"):
        with open("pdf_extractor.py", "w") as f:
            f.write("""
import PyPDF2
import os

def extract_text_from_pdf(pdf_path: str) -> str:
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"The PDF file was not found: {pdf_path}")
    extracted_text = ""
    try:
        with open(pdf_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            for page_num in range(len(reader.pages)):
                page = reader.pages[page_num]
                text = page.extract_text()
                if text:
                    extracted_text += text + "\\n"
    except PyPDF2.errors.PdfReadError as e:
        raise PyPDF2.errors.PdfReadError(f"Error reading PDF file {pdf_path}: {e}. It might be corrupted or encrypted.")
    except Exception as e:
        raise Exception(f"Error extracting text from PDF {pdf_path}: {e}")
    return extracted_text

if __name__ == "__main__":
    # Dummy usage for pdf_extractor.py
    print("This is a dummy pdf_extractor.py. It requires an actual PDF file and 'pypdf' library to function fully.")
""")
        print("Created a dummy 'pdf_extractor.py'. Please ensure 'pypdf' is installed (`pip install pypdf`).")

    if len(sys.argv) > 1:
        report_path = sys.argv[1]
        try:
            report = process_zap_report_file(report_path)
            print(f"Successfully processed ZAP report: {report_path}")
            print(f"Found {len(report['vulnerabilities'])} vulnerabilities")
            print(f"Risk counts: {report['summary']['risk_counts']}")

            # Save structured output to a JSON file
            output_path = os.path.splitext(report_path)[0] + "_parsed.json"
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Structured output saved to: {output_path}")

        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
    else:
        print("Usage: python zap_parser.py <path_to_zap_report.pdf>")
        print("\nNo file path provided. Please provide a path to a ZAP report PDF file.")
