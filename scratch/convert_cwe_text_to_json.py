import csv
import json
import os

def convert():
    csv_path = r"d:\NetShield\NetShieldAI_Chatbot\CWE_Profiles\cwe_profiles.csv"
    json_path = r"d:\NetShield\NetShieldAI_Chatbot\CWE_Profiles\cwe_text_summary.json"
    
    if not os.path.exists(csv_path):
        print(f"Error: CSV not found at {csv_path}")
        return

    # Increase field size limit for large descriptions
    csv.field_size_limit(10**7)

    cwe_data = {}
    print(f"Reading {csv_path}...")
    
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                cid = row.get('cwe_id', '').strip()
                desc = row.get('description_join', '')
                
                if cid and desc:
                    numeric_id = cid.replace("CWE-", "").strip()
                    # Summary = First sentence
                    summary = desc.split(". ")[0].strip(".")
                    
                    cwe_data[numeric_id] = {
                        "name": summary[:100], # Use first sentence as a quasi-name
                        "summary": summary[:200],
                        "description": desc[:500] # Truncated for memory efficiency
                    }
                    count += 1
        
        print(f"Writing {count} entries to {json_path}...")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(cwe_data, f, indent=2)
            
        print("Success!")
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    convert()
