import os
import sys
import re
import json
import uuid
from typing import Union, Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

# Add the current directory to Python path to ensure local imports work
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Now import pdf_extractor
try:
    from pdf_extractor import extract_text_from_pdf
except ImportError as e:
    print(f"Error importing pdf_extractor: {e}")
    print(f"Current Python path: {sys.path}")
    print(f"Current directory: {os.getcwd()}")
    print("Files in current directory:", os.listdir('.'))
    
    # Define a fallback function if import fails
    def extract_text_from_pdf(pdf_path: str) -> Optional[str]:
        print(f"ERROR: Could not import pdf_extractor. Cannot extract text from {pdf_path}")
        return None


# In a real scenario, if this were part of a larger system,
# you might have a generic text extractor or directly pass content.
# For this example, we'll assume the content is read into a string.


def parse_nikto_report(raw_nikto_text: str) -> Dict[str, Any]:
    """
    Parses raw Nikto report text into a structured dictionary.

    Args:
        raw_nikto_text (str): The raw text content of a Nikto report.

    Returns:
        dict: A structured dictionary containing Nikto report information.
    """
    # Standardize newlines for easier regex matching
    raw_nikto_text = re.sub(r'\r\n', '\n', raw_nikto_text)
    raw_nikto_text = re.sub(r'\r', '\n', raw_nikto_text)

    report_data: Dict[str, Any] = {
        "scan_metadata": {
            "tool": "Nikto Report"  # Identify the tool
        },
        "host_details": {},
        "findings": [],
        "scan_summary": {}
    }

    # --- Parse Host Details ---
    # Target Hostname
    match = re.search(r'Target hostname\s*([^\n]+)', raw_nikto_text)
    if match:
        report_data["host_details"]["hostname"] = match.group(1).strip()
    
    # Target IP
    match = re.search(r'Target IP\s*([\d\.]{7,15})', raw_nikto_text)
    if match:
        report_data["host_details"]["ip"] = match.group(1).strip()

    # Target Port
    match = re.search(r'Target Port\s*(\d+)', raw_nikto_text)
    if match:
        report_data["host_details"]["port"] = int(match.group(1))

    # HTTP Server
    match = re.search(r'HTTP Server\s*([^\n]+)', raw_nikto_text)
    if match:
        report_data["host_details"]["http_server"] = match.group(1).strip()
    
    # Site Link (Name)
    match = re.search(r'Site Link \(Name\)\s*(https?:\/\/[^\s]+)', raw_nikto_text)
    if match:
        report_data["host_details"]["site_link_name"] = match.group(1).strip()

    # Site Link (IP)
    match = re.search(r'Site Link \(IP\)\s*(https?:\/\/[^\s]+)', raw_nikto_text)
    if match:
        report_data["host_details"]["site_link_ip"] = match.group(1).strip()

    # --- Parse Findings ---
    # Each finding block starts with 'URI /' and ends before the next 'URI /' or 'Host Summary'
    findings_blocks = re.split(r'(?=URI /)', raw_nikto_text)
    
    for block in findings_blocks:
        if block.strip().startswith("URI /"):
            finding: Dict[str, Any] = {}
            
            # URI
            uri_match = re.search(r'URI\s*([^\n]+)', block)
            if uri_match:
                finding["uri"] = uri_match.group(1).strip()
            
            # HTTP Method
            method_match = re.search(r'HTTP Method\s*([^\n]+)', block)
            if method_match:
                finding["http_method"] = method_match.group(1).strip()
            
            # Description (can be multiline, so be careful with lookahead)
            description_match = re.search(r'Description\s*([^\n]+(?:\n\s*[^\n]+)*?)(?=\nTest Links|\nReferences|$)', block, re.DOTALL)
            if description_match:
                finding["description"] = description_match.group(1).strip()
            
            # Test Links
            test_links_match = re.search(r'Test Links\s*(https?:\/\/[^\n]+(?:\nhttps?:\/\/[^\n]+)*)', block)
            if test_links_match:
                finding["test_links"] = [link.strip() for link in test_links_match.group(1).splitlines() if link.strip()]

            # References (can be multiline)
            references_match = re.search(r'References\s*([^\n]*?(?:\n\s*[^\n]*)*?)(?=\nURI /|\nHost Summary|$)', block, re.DOTALL)
            if references_match and references_match.group(1).strip():
                # Split by newline and filter out empty strings, then strip each.
                # Handle cases where references might be empty or just whitespace after 'References'
                refs = [ref.strip() for ref in references_match.group(1).splitlines() if ref.strip()]
                if refs:
                    finding["references"] = refs
                else:
                    finding["references"] = [] # Explicitly empty if no meaningful references

            if finding: # Only add if we found at least some data for the finding
                report_data["findings"].append(finding)

    # --- Parse Host Summary ---
    host_summary_section_match = re.search(r'Host Summary\s*(.*?)(?=Scan Summary|$)', raw_nikto_text, re.DOTALL)
    if host_summary_section_match:
        host_summary_text = host_summary_section_match.group(1)
        
        # Start Time
        match = re.search(r'Start Time\s*([^\n]+)', host_summary_text)
        if match:
            report_data["scan_metadata"]["start_time_host_summary"] = match.group(1).strip()
        
        # End Time
        match = re.search(r'End Time\s*([^\n]+)', host_summary_text)
        if match:
            report_data["scan_metadata"]["end_time_host_summary"] = match.group(1).strip()
        
        # Elapsed Time
        match = re.search(r'Elapsed Time\s*([\d\.]+\s*seconds?)', host_summary_text)
        if match:
            report_data["scan_metadata"]["elapsed_time_host_summary"] = match.group(1).strip()
        
        # Statistics
        match = re.search(r'Statistics\s*(\d+)\s*requests,\s*(\d+)\s*errors,\s*(\d+)\s*findings', host_summary_text)
        if match:
            report_data["host_details"]["statistics"] = {
                "requests": int(match.group(1)),
                "errors": int(match.group(2)),
                "findings": int(match.group(3))
            }

    # --- Parse Scan Summary ---
    scan_summary_section_match = re.search(r'Scan Summary\s*(.*)', raw_nikto_text, re.DOTALL)
    if scan_summary_section_match:
        scan_summary_text = scan_summary_section_match.group(1)

        # Software Details
        match = re.search(r'Software\s*Details\s*([^\n]+)', scan_summary_text)
        if match:
            report_data["scan_summary"]["software"] = match.group(1).strip()

        # CLI Options
        match = re.search(r'CLI\s*Options\s*([^\n]+(?:\n\s*[^\n]+)*)', scan_summary_text)
        if match:
            report_data["scan_summary"]["cli_options"] = match.group(1).strip()
        
        # Hosts Tested
        match = re.search(r'Hosts\s*Tested\s*(\d+)', scan_summary_text)
        if match:
            report_data["scan_summary"]["hosts_tested"] = int(match.group(1))

        # Start Time (Scan Summary)
        match = re.search(r'Start\s*Time\s*([^\n]+)', scan_summary_text)
        if match:
            report_data["scan_summary"]["start_time"] = match.group(1).strip()

        # End Time (Scan Summary)
        match = re.search(r'End\s*Time\s*([^\n]+)', scan_summary_text)
        if match:
            report_data["scan_summary"]["end_time"] = match.group(1).strip()

        # Elapsed Time (Scan Summary)
        match = re.search(r'Elapsed\s*Time\s*([\d\.]+\s*seconds?)', scan_summary_text)
        if match:
            report_data["scan_summary"]["elapsed_time"] = match.group(1).strip()

    return report_data

def process_nikto_report_file(pdf_file_path: str) -> Optional[Dict[str, Any]]:
    """
    Reads a Nikto PDF report, extracts text, and calls the parser function.
    Returns a dictionary with structured report data.
    """
    print(f"\nProcessing Nikto PDF: {pdf_file_path}")
    raw_text = extract_text_from_pdf(pdf_file_path)

    if not raw_text:
        print(f"  Failed to extract text from {pdf_file_path}. Skipping.")
        return None

    structured_data = parse_nikto_report(raw_text)

    # Add source file name to metadata
    structured_data["scan_metadata"]["source_file_name"] = os.path.basename(pdf_file_path)

    # Generate a report ID if one doesn't exist
    if "report_id" not in structured_data["scan_metadata"]:
        structured_data["scan_metadata"]["report_id"] = str(uuid.uuid4())

    # CORRECTED LINE: Use the 'findings' key instead of 'hosts' or 'vulnerabilities'.
    # Also, the log message is now more accurate.
    print(f"  Processed {len(structured_data['findings'])} finding(s) from {os.path.basename(pdf_file_path)}.")
    
    return structured_data

if __name__ == "__main__":
    # Ensure this script can find pdf_extractor.py
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root_dir = os.path.dirname(current_script_dir)  # Go up one level to VulnScanAI
    
    # Add project root to path for module imports
    if project_root_dir not in sys.path:
        sys.path.insert(0, project_root_dir)
    
    # Use the nikto_reports_data directory in the project root
    pdf_reports_directory = os.path.join(project_root_dir,"documents", "Nikto_test")
    
    print(f"Looking for Nikto PDF files in: {pdf_reports_directory}\n")

    if not os.path.exists(pdf_reports_directory):
        print(f"Error: Directory '{pdf_reports_directory}' not found.")
        sys.exit(1)
    
    # Get all PDF files in the directory
    pdf_files = [f for f in os.listdir(pdf_reports_directory) 
                if f.lower().endswith('.pdf') and os.path.isfile(os.path.join(pdf_reports_directory, f))]
    
    if not pdf_files:
        print(f"No PDF files found in {pdf_reports_directory}")
        sys.exit(1)
    
    print(f"Found {len(pdf_files)} PDF file(s) to process:\n")
    
    for filename in pdf_files:
        pdf_path = os.path.join(pdf_reports_directory, filename)
        print(f"--- Processing {filename} ---")
        
        try:
            # Extract text from PDF
            raw_text = extract_text_from_pdf(pdf_path)
            if not raw_text:
                print(f"  Failed to extract text from {filename}")
                continue
                
            # Parse the Nmap report
            parsed_data = parse_nikto_report(raw_text)
            
            # Add source file info
            parsed_data["scan_metadata"]["source_file"] = filename
            
            # Print the parsed data
            print(json.dumps(parsed_data, indent=2))
            print("\n" + "="*80 + "\n")  # Separator for clarity     
        except Exception as e:
            print(f"Error processing {filename}: {e}")
            import traceback
            traceback.print_exc()  # Print full traceback for debugging
            print("\n" + "="*80 + "\n")
    