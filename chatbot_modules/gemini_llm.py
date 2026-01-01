# chatbot_modules/gemini_llm.py
import os
from pathlib import Path
from dotenv import load_dotenv
import google.generativeai as genai
import logging

# Setup logging
logger = logging.getLogger(__name__)

# Load environment variables from .env file
env_path = Path('..') / '.env'
load_dotenv(dotenv_path=env_path)

def load_model(api_key: str = None, model_name: str = "gemini-1.5-flash", **kwargs):
    """
    Loads and configures the Gemini model.
    
    Args:
        api_key (str): The Google API key.
        model_name (str): The specific model ID to load (e.g., 'gemini-1.5-flash').
        **kwargs: Arbitrary keyword arguments.
        
    Returns:
        The configured Gemini model instance.
    """
    # Get API key from argument, kwargs, or environment
    key_to_use = api_key or kwargs.get('api_key') or os.environ.get("GEMINI_API_KEY")
    
    if not key_to_use:
        raise ValueError("GEMINI_API_KEY not provided in environment or arguments")
        
    try:
        genai.configure(api_key=key_to_use)
        # CRITICAL FIX: Use the model_name passed from config, do not hardcode!
        model = genai.GenerativeModel(model_name)
        logger.info(f"Gemini model loaded successfully: {model_name}")
        return model
    except Exception as e:
        logger.error(f"Failed to load Gemini model {model_name}: {e}")
        raise e

async def generate_response(model, prompt: str, max_tokens: int = 8192) -> str:
    """
    Generates a response from the Gemini model asynchronously.
    """
    try:
        # Use safe generation config
        generation_config = genai.types.GenerationConfig(
            max_output_tokens=max_tokens,
            temperature=0.7
        )

        # CRITICAL UPDATE: Use native async method if available for better performance
        response = await model.generate_content_async(
            prompt, 
            generation_config=generation_config
        )
        
        # Check for safety blocks
        if response.prompt_feedback and response.prompt_feedback.block_reason:
            logger.warning(f"Response blocked by safety filters: {response.prompt_feedback.block_reason}")
            return "I cannot answer this query due to safety restrictions."

        return response.text.strip()
            
    except Exception as e:
        logger.error(f"Error in Gemini generate_response: {str(e)}")
        # If the error is a 429, we want to let it propagate so app.py can catch and retry it
        raise e

def main():
    """Test the Gemini LLM with a simple interactive prompt."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY not found.")
        return

    print("Loading Gemini model...")
    import asyncio
    try:
        # Test loading with a specific model
        model = load_model(api_key=api_key, model_name="gemini-1.5-flash")
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

if __name__ == "__main__":
    main()