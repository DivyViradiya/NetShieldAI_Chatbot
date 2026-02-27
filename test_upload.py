import requests
import sys

URL = "http://127.0.0.1:8000/upload_report"

def upload(file_path):
    print(f"Uploading {file_path}...")
    
    # We will use the file_path mechanism to avoid dealing with multipart/form-data for the test
    params = {
        "user_id": "test_user_graph_01",
        "llm_mode": "gemini",
        "file_path": file_path
    }
    
    try:
        response = requests.post(URL, params=params)
        print(response.status_code)
        print(response.json())
        return response.json().get('session_id')
    except Exception as e:
        print(f"Failed: {e}")
        return None

if __name__ == "__main__":
    import os
    abs_path = os.path.abspath("d:/NetShield/NetShieldAI_Chatbot/sample_nmap_full.txt")
    print(f"Testing with {abs_path}")
    
    # Needs the backend running... we will actually just test the graph logic directly first
