import os
import re
import json
import uuid
from typing import Dict, Any
from datetime import datetime

# It's assumed pdf_extractor.py exists and works as intended.
# Keeping the original import/stub logic for consistency.
try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    try:
        from pdf_extractor import extract_text_from_pdf
    except ImportError:
        print("Error: pdf_extractor.py not found. Please ensure it is in the same directory.")
        def extract_text_from_pdf(pdf_path: str) -> str:
            raise NotImplementedError("pdf_extractor.py not found.")

# --- Helper function for cleaning text blocks ---
def clean_text_block(text: str) -> str:
    """Removes excessive whitespace, page breaks, and page numbers from text blocks."""
    # Remove internal page break markers
    text = re.sub(r'--PAGE-BREAK--', ' ', text, flags=re.DOTALL)
    text = re.sub(r'--ALERT-SPLIT--', ' ', text, flags=re.DOTALL) # Clean up new alert split marker
    # Remove embedded page X of Y markers that often appear in PDF extractions
    text = re.sub(r'Page \d+ of \d+', '', text).strip()
    # Remove newlines and compress internal whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def parse_zap_report(raw_zap_text: str) -> Dict[str, Any]:
    """
    Parses raw ZAP report text into a structured dictionary,
    specifically tailored for the compact PDF format provided by the user.
    """
    raw_zap_text = re.sub(r'\r\n|\r', '\n', raw_zap_text)
    # 1. Normalize the page break/header markers for easier parsing
    raw_zap_text = re.sub(r'\n(Page \d+ of \d+)\n', '\n--PAGE-BREAK--\n', raw_zap_text, flags=re.DOTALL)

    # 2. **CRITICAL FIX**: Insert a custom delimiter between the Charset Mismatch references and the 
    #    adjacent Modern Web Application title, which are currently running together.
    raw_zap_text = re.sub(
        r"(detection\s*)\n(Modern Web Application\nInformational Risk Predicted Score)",
        r"\1\n--ALERT-SPLIT--\n\2",
        raw_zap_text,
        flags=re.DOTALL
    )

    report = {
        "scan_metadata": {
            "tool": "ZAP Scanner",
            "report_id": str(uuid.uuid4()),
            "generated_at": None, "target_url": None, "scan_date": None
        },
        "summary": {
            "risk_counts": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Total": 0},
            "alerts_by_name": [],
            "scanned_urls": set()
        },
        "vulnerabilities": []
    }

    # --- 1. Metadata and Summary ---
    
    # Target URL (Adjusted to account for lack of space before SCAN DATE)
    target_match = re.search(r"TARGET URL:\s*\n(https?://[^\s]+)SCAN DATE:", raw_zap_text)
    if target_match:
        url = target_match.group(1).strip().replace('SCAN', '')
        report["scan_metadata"]["target_url"] = url
        report["summary"]["scanned_urls"].add(url)

    # Scan Date & Time
    scan_date_match = re.search(r"SCAN DATE:\s*\n(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", raw_zap_text)
    if scan_date_match:
        date_str = scan_date_match.group(1).strip()
        try:
            report["scan_metadata"]["scan_date"] = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").isoformat()
        except ValueError:
            report["scan_metadata"]["scan_date"] = date_str

    # Report Generated Date/Time
    report_gen_match = re.search(r"REPORT GENERATED:\s*\n(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", raw_zap_text)
    if report_gen_match:
        report_gen_str = report_gen_match.group(1).strip()
        try:
            report["scan_metadata"]["generated_at"] = datetime.strptime(report_gen_str, "%Y-%m-%d %H:%M:%S").isoformat()
        except ValueError:
            report["scan_metadata"]["generated_at"] = report_gen_str

    # Risk Count Summary Table
    summary_table_match = re.search(
        r"Scan Summary\s*Risk Level\s*Count\s*"
        r"High\s+(\d+)\s*"
        r"Medium\s+(\d+)\s*"
        r"Low\s+(\d+)\s*"
        r"Informational\s+(\d+)\s*"
        r"Total\s+(\d+)",
        raw_zap_text, re.DOTALL
    )
    if summary_table_match:
        groups = summary_table_match.groups()
        report["summary"]["risk_counts"]["High"] = int(groups[0])
        report["summary"]["risk_counts"]["Medium"] = int(groups[1])
        report["summary"]["risk_counts"]["Low"] = int(groups[2])
        report["summary"]["risk_counts"]["Informational"] = int(groups[3])
        report["summary"]["risk_counts"]["Total"] = int(groups[4])
        report["summary"]["total_alerts"] = int(groups[4])
        
    # --- 2. Detailed Findings (Vulnerabilities) ---
    
    # Added ALERT_SPLIT to the lookahead for the alert boundary
    NEXT_ALERT_START_LOOKAHEAD = r"(?=\n(?:--PAGE-BREAK--|--ALERT-SPLIT--|\s*)[^\n]*?\n(?:Medium|Low|Informational) Risk Predicted Score|\Z)"

    alert_pattern = re.compile(
        # Group 1: Title - captures everything up to the risk classification.
        r"^(?P<title>.*?)\n" 
        # Group 2, 3, 4: Risk, Score, Confidence
        r"(?P<risk>Medium|Low|Informational) Risk Predicted Score: (?P<score>[^\s]+) Confidence: (?P<confidence>[^\n]+)\n"
        # Group 5: URL
        r"URL: (?P<url>https?://[^\s]+)\n"
        # Group 6: Description (non-greedy, stops before 'Solution:')
        r"Description:\n(?P<description>.*?)\n"
        # Group 7: Solution (non-greedy, stops before 'Reference:')
        r"Solution:\n(?P<solution>.*?)\n"
        # Group 8: References (non-greedy, stops before the next alert or end of text)
        r"Reference:\n(?P<references>.*?)"
        # Use the combined lookahead boundary
        + NEXT_ALERT_START_LOOKAHEAD,
        re.DOTALL | re.MULTILINE
    )

    # Start searching for alerts after the summary header
    alert_blocks = raw_zap_text.split("Detailed Findings")[1] if "Detailed Findings" in raw_zap_text else raw_zap_text
    
    # Refined list of titles using raw strings (r"") to avoid SyntaxWarnings and handle regex special characters.
    potential_start_titles = [
        r"Missing Anti-clickjacking Header", 
        r"Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field\(s\)",
        r"Server Leaks Version Information via \"Server\" HTTP Response Header Field",
        r"User Controllable HTML Element Attribute \(Potential XSS\)",
        r"Content Security Policy \(CSP\) Header Not Set",
        r"X-Content-Type-Options Header Missing",
        r"Authentication Request Identified",
        r"Charset Mismatch \(Header Versus Meta Content-Type Charset\)",
        r"Modern Web Application"
    ]
    
    for match in alert_pattern.finditer(alert_blocks):
        data = match.groupdict()
        
        # --- Title Cleaning ---
        raw_title = data['title'].strip()
        
        # 1. Clean the raw title text (removes newlines, breaks)
        title = clean_text_block(raw_title)

        # 2. Find the actual title by matching the expected start of an alert name within the captured title block
        title_pattern = re.compile('|'.join(potential_start_titles) + r'|Absence of Anti-CSRF Tokens', re.DOTALL)
        title_match = title_pattern.search(title)
        
        if title_match:
            title = title[title_match.start():].strip()
        
        # 3. Final cleanup and specific fix for the 'Field(s)' truncation
        title = re.sub(r'^--PAGE-BREAK--', '', title).strip()
        
        # Explicitly fix the most common and problematic truncated title if heuristic match failed
        if title == "Field(s)" and data['risk'] == "Low" and data['confidence'] == "Medium":
            title = "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)"
            
        if not title:
            continue
        
        # --- Metadata Extraction ---
        cwe_match = re.search(r"cwe\.mitre\.org/data/definitions/(\d+)\.html", data['references'])
        cwe_id = int(cwe_match.group(1)) if cwe_match else None
        
        references = [
            line.strip() for line in data['references'].split('\n')
            if line.strip().startswith('http')
        ]

        # Build the vulnerability object
        vuln = {
            "id": str(uuid.uuid4()),
            "name": title,
            "risk": data['risk'],
            "predicted_score": data['score'] if data['score'] != 'N/A' else None,
            "confidence": data['confidence'],
            "url": data['url'],
            "description": clean_text_block(data['description']),
            "solution": clean_text_block(data['solution']),
            "references": references,
            "cwe_id": cwe_id,
            "wasc_id": None, "plugin_id": None, "instances_count": 1 
        }
        
        report["vulnerabilities"].append(vuln)
        
        # Add the URL to the scanned list
        report["summary"]["scanned_urls"].add(vuln['url'])

        # Add alert name to summary list if it's new
        if vuln['name'] not in [a['name'] for a in report["summary"]["alerts_by_name"]]:
             report["summary"]["alerts_by_name"].append({
                 "name": vuln['name'],
                 "risk_level": vuln['risk'],
                 "instances_count": 1
             })


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
        
        # Ensure 'scanned_urls' is not a set before dumping to JSON
        report_data["summary"]["scanned_urls"] = sorted(list(report_data["summary"]["scanned_urls"]))

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
    # The example usage remains as provided by the user
    sample_pdf_path = r"D:\NetShieldAI_Chatbot\Data\reports\zap_report.pdf"
    try:
        # NOTE: This will fail if pdf_extractor.py is not available in the path
        zap_report = process_zap_report_file(sample_pdf_path)
        print(json.dumps(zap_report, indent=2))
    except NotImplementedError:
        print("Please ensure 'pdf_extractor.py' is implemented to run the file processing.")
    except Exception as e:
        print(f"Failed to process ZAP report: {e}")