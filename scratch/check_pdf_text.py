import sys
import os

# Add chatbot_modules to path
sys.path.append(r'd:\NetShield\NetShieldAI_Chatbot')

from chatbot_modules.pdf_extractor import extract_text_from_pdf

pdf_path = r'd:\NetShield\NetShieldAI\.results\DivyaViradiya_2\network_scanner\network_192.168.29.48_2026-04-16_115953.pdf'

try:
    text = extract_text_from_pdf(pdf_path)
    print("--- FIRST 500 CHARACTERS ---")
    print(text[:500])
    print("--- FIRST 20 LINES ---")
    lines = [line.strip().lower() for line in text.splitlines() if line.strip()][:20]
    for line in lines:
        print(f"DEBUG: '{line}'")
except Exception as e:
    print(f"Error: {e}")
