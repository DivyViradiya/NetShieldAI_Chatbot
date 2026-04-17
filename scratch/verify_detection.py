import sys
import os

# Add chatbot_modules and current dir to path
sys.path.append(r'd:\NetShield\NetShieldAI_Chatbot')

from chatbot_modules.pdf_extractor import extract_text_from_pdf
from app import detect_report_type_from_content

test_reports = [
    (r'd:\NetShield\NetShieldAI\.results\DivyaViradiya_2\network_scanner\network_192.168.29.48_2026-04-16_115953.pdf', 'nmap'),
    (r'd:\NetShield\NetShieldAI\.results\DivyaViradiya_2\zap_scanner\Audit_zap_example.com_2026-04-11_102416.pdf', 'zap'),
    (r'd:\NetShield\NetShieldAI\.results\DivyaViradiya_2\sql_scanner\sql_testasp.vulnweb.com_showforum.asp_id_1_2026-04-11_092839.pdf', 'sql'),
    (r'd:\NetShield\NetShieldAI\.results\DivyaViradiya_2\ssl_scanner\ssl_google.com_20260416_145050.pdf', 'sslscan'),
    (r'd:\NetShield\NetShieldAI\.results\DivyaViradiya_2\killchain\reports\Audit_killchain_example.com_2026-04-10_225816.pdf', 'killchain'),
    (r'd:\NetShield\NetShieldAI\.results\DivyaViradiya_2\api_scanner\Audit_api_httpbin.org_2026-04-10_233657.pdf', 'api'),
    (r'd:\NetShield\NetShieldAI\.results\DivyaViradiya_2\semgrep_scanner\Audit_semgrep_AirImprovement.zip_2026-04-09_181352.pdf', 'semgrep'),
    (r'd:\NetShield\NetShieldAI\.results\DivyaViradiya_2\packet_sniffer\Audit_pcap_analysis_report_192.168.29.1_2026-04-11_095347.pdf', 'pcap')
]

print(f"{'FILE':<80} | {'EXPECTED':<10} | {'DETECTED':<10} | {'STATUS'}")
print("-" * 120)

all_passed = True
for pdf_path, expected in test_reports:
    try:
        if not os.path.exists(pdf_path):
             print(f"{os.path.basename(pdf_path):<80} | {expected:<10} | {'NOT FOUND':<10} | SKIP")
             continue
             
        text = extract_text_from_pdf(pdf_path)
        detected = detect_report_type_from_content(text, os.path.basename(pdf_path))
        
        status = "PASS" if detected == expected else "FAIL"
        if status == "FAIL": all_passed = False
        
        print(f"{os.path.basename(pdf_path):<80} | {expected:<10} | {detected:<10} | {status}")
    except Exception as e:
        print(f"{os.path.basename(pdf_path):<80} | {expected:<10} | ERROR      | FAIL ({e})")
        all_passed = False

if all_passed:
    print("\nALL DETECTION TESTS PASSED!")
    sys.exit(0)
else:
    print("\nSOME TESTS FAILED!")
    sys.exit(1)
