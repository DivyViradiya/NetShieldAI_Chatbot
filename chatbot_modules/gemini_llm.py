import os
from pathlib import Path
from dotenv import load_dotenv
import google.generativeai as genai
import logging
import asyncio
import json

# Setup logging
logger = logging.getLogger(__name__)

# Load environment variables
env_path = Path('..') / '.env'
load_dotenv(dotenv_path=env_path)

def load_model(api_key: str = None, model_name: str = "gemini-2.5-flash", tools: list = None, **kwargs):
    """Loads and configures the Gemini model with optional tools."""
    key_to_use = api_key or kwargs.get('api_key') or os.environ.get("GEMINI_API_KEY")
    if not key_to_use:
        raise ValueError("GEMINI_API_KEY not provided")
    try:
        genai.configure(api_key=key_to_use)
        # Initialize model with tools if provided
        model = genai.GenerativeModel(model_name, tools=tools)
        logger.info(f"Gemini model loaded: {model_name} (Tools: {True if tools else False})")
        return model
    except Exception as e:
        logger.error(f"Failed to load Gemini model: {e}")
        raise e

async def generate_response(model, prompt: str, max_tokens: int = 8192) -> dict:
    """
    Standard Async Generation. 
    Returns a dict: {"text": str, "tool_call": dict or None}
    """
    try:
        generation_config = genai.types.GenerationConfig(max_output_tokens=max_tokens, temperature=0.7)
        response = await model.generate_content_async(prompt, generation_config=generation_config)
        
        # Check for safety blocks
        if response.prompt_feedback and response.prompt_feedback.block_reason:
            return {"text": "I cannot answer this query due to safety restrictions.", "tool_call": None}

        # Handle Function Calls and Text
        tool_call = None
        full_text = ""
        
        if response.candidates and response.candidates[0].content.parts:
            for part in response.candidates[0].content.parts:
                if part.function_call:
                    tool_call = {
                        "name": part.function_call.name,
                        "args": dict(part.function_call.args)
                    }
                if part.text:
                    full_text += part.text

        return {
            "text": full_text.strip() if full_text else "Initiating scan...",
            "tool_call": tool_call
        }
    except Exception as e:
        logger.error(f"Error in Gemini generate_response: {str(e)}")
        raise e

# --- NEW STREAMING FUNCTION ---
async def generate_response_stream(model, prompt: str, max_tokens: int = 8192):
    """
    Generates a response asynchronously and yields chunks. 
    Note: Function calls usually come in the first chunk or as a separate non-text part.
    """
    try:
        generation_config = genai.types.GenerationConfig(max_output_tokens=max_tokens, temperature=0.7)
        response = await model.generate_content_async(prompt, generation_config=generation_config, stream=True)
        
        async for chunk in response:
            # Check for function call in the chunk
            if chunk.candidates[0].content.parts:
                for part in chunk.candidates[0].content.parts:
                    if part.function_call:
                        # We yield a special JSON string for the tool call
                        yield f"__TOOL_CALL__:{part.function_call.name}:{json.dumps(dict(part.function_call.args))}"
                    elif part.text:
                        yield part.text
                
    except Exception as e:
        logger.error(f"Error in Gemini streaming: {str(e)}")
        yield f"\n[System Error: {str(e)}]"