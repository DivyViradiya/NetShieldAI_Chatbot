import os
from pathlib import Path
from dotenv import load_dotenv
import google.generativeai as genai
import logging
import asyncio

# Setup logging
logger = logging.getLogger(__name__)

# Load environment variables
env_path = Path('..') / '.env'
load_dotenv(dotenv_path=env_path)

def load_model(api_key: str = None, model_name: str = "gemini-1.5-flash", **kwargs):
    """Loads and configures the Gemini model."""
    key_to_use = api_key or kwargs.get('api_key') or os.environ.get("GEMINI_API_KEY")
    if not key_to_use:
        raise ValueError("GEMINI_API_KEY not provided in environment or arguments")
    try:
        genai.configure(api_key=key_to_use)
        model = genai.GenerativeModel(model_name)
        logger.info(f"Gemini model loaded successfully: {model_name}")
        return model
    except Exception as e:
        logger.error(f"Failed to load Gemini model {model_name}: {e}")
        raise e

async def generate_response(model, prompt: str, max_tokens: int = 8192) -> str:
    """Standard Async Generation (Non-Streaming)"""
    try:
        generation_config = genai.types.GenerationConfig(max_output_tokens=max_tokens, temperature=0.7)
        response = await model.generate_content_async(prompt, generation_config=generation_config)
        
        if response.prompt_feedback and response.prompt_feedback.block_reason:
            return "I cannot answer this query due to safety restrictions."
        return response.text.strip()
    except Exception as e:
        logger.error(f"Error in Gemini generate_response: {str(e)}")
        raise e

# --- NEW STREAMING FUNCTION ---
async def generate_response_stream(model, prompt: str, max_tokens: int = 8192):
    """
    Generates a response asynchronously and yields text chunks (Streaming).
    """
    try:
        generation_config = genai.types.GenerationConfig(max_output_tokens=max_tokens, temperature=0.7)
        
        # stream=True is the key here
        response = await model.generate_content_async(prompt, generation_config=generation_config, stream=True)
        
        async for chunk in response:
            if chunk.text:
                yield chunk.text
                
    except Exception as e:
        logger.error(f"Error in Gemini streaming: {str(e)}")
        yield f"\n[System Error: {str(e)}]"