# chatbot_modules/gemini_llm.py
import os
from pathlib import Path
from dotenv import load_dotenv
import google.generativeai as genai
import asyncio

# Load environment variables from .env file
env_path = Path('..') / '.env'
load_dotenv(dotenv_path=env_path)

def load_model(*args, **kwargs):
    """
    Loads and configures the Gemini model.
    Args:
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments. Can include 'api_key'.
    Returns:
        The configured Gemini model instance.
    """
    # Get API key from kwargs or environment
    api_key = kwargs.get('api_key') or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not provided in environment or kwargs")
        
    genai.configure(api_key=api_key)
    return genai.GenerativeModel("gemini-2.0-flash")

async def generate_response(model, prompt: str, max_tokens: int = 2048) -> str:
    """
    Generates a response from the Gemini model.
    Args:
        model: The loaded Gemini model instance.
        prompt (str): The input prompt for the model.
        max_tokens (int): The maximum number of tokens to generate.
    Returns:
        str: The generated response text.
    """
    try:
        # Run the synchronous generate_content in a thread pool
        def _generate():
            response = model.generate_content(
                prompt, 
                generation_config={"max_output_tokens": max_tokens}
            )
            return response.text.strip()
            
        return await asyncio.to_thread(_generate)
    except Exception as e:
        print(f"Error in Gemini generate_response: {str(e)}")
        raise

def main():
    """Test the Gemini LLM with a simple interactive prompt."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY not found in environment variables or .env file.")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Tried to load .env from: {env_path.absolute()}")
        return

    print("Loading Gemini model...")
    try:
        model = load_model(api_key=api_key)
        print("Model loaded. Type 'exit' to quit.")
        
        async def chat_loop():
            while True:
                user_input = input("\nYou: ").strip()
                if user_input.lower() in ('exit', 'quit'):
                    break
                    
                response = await generate_response(model, user_input)
                print(f"\nGemini: {response}")
        
        asyncio.run(chat_loop())
            
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()