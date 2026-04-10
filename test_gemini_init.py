import os
import sys
import logging
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(r"d:\NetShield\NetShieldAI_Chatbot")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Setup dummy logging to console
logging.basicConfig(level=logging.INFO)

try:
    from chatbot_modules import config
    import chatbot_modules.gemini_llm as gemini_llm
    from chatbot_modules.agent_tools import SECURITY_TOOLS
    
    print("Attempting to load Gemini model with tools...")
    
    # We use the key from config which reads .env
    api_key = config.GEMINI_API_KEY
    if not api_key:
        print("GEMINI_API_KEY not found in config, using DUMMY_KEY for parsing test")
        api_key = "DUMMY_KEY"
         
    model = gemini_llm.load_model(
        api_key=api_key,
        model_name="gemini-2.5-flash",
        tools=SECURITY_TOOLS
    )
    print("\n[SUCCESS] Model loaded with tools! Schema parsed correctly.")
except Exception as e:
    print(f"\n[FAILURE] {e}")
    sys.exit(1)
    
print("Verification complete.")
