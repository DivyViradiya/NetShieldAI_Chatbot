import sys
try:
    from chatbot_modules import agent_tools
    print("Syntax check PASSED: agent_tools.py loaded successfully.")
except Exception as e:
    print(f"Syntax check FAILED: {e}")
    sys.exit(1)
