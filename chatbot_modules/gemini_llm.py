import os
from pathlib import Path
from dotenv import load_dotenv
from google import genai
from google.genai import types
import logging
import asyncio
import json

from chatbot_modules.config import LogColors

# Setup logging
logger = logging.getLogger(__name__)

# Load environment variables (absolute path resolution)
env_path = Path(__file__).resolve().parent.parent / '.env'
load_dotenv(dotenv_path=env_path)

class GeminiModelWrapper:
    def __init__(self, client: genai.Client, model_name: str, tools: list = None):
        self.client = client
        self.model_name = model_name
        self.tools = tools

def load_model(api_key: str = None, model_name: str = "gemini-3.8-flash", tools: list = None, **kwargs):
    """Loads and configures the Gemini model with optional tools."""
    key_to_use = api_key or kwargs.get('api_key') or os.environ.get("GEMINI_API_KEY")
    if not key_to_use:
        raise ValueError("GEMINI_API_KEY not provided")
    try:
        client = genai.Client(api_key=key_to_use)
        model = GeminiModelWrapper(client, model_name, tools)
        logger.info(f"{LogColors.SUCCESS}[SUCCESS] Gemini model loaded: {model_name} (Tools: {True if tools else False}){LogColors.RESET}")
        return model
    except Exception as e:
        logger.error(f"Failed to load Gemini model: {e}")
        raise e

def _proto_to_dict(obj):
    """Recursively converts protobuf MapComposite/RepeatedComposite to native Python dict/list."""
    if hasattr(obj, 'items'):
        return {k: _proto_to_dict(v) for k, v in obj.items()}
    elif hasattr(obj, '__iter__') and not isinstance(obj, str):
        return [_proto_to_dict(item) for item in obj]
    else:
        return obj

async def generate_response(model: GeminiModelWrapper, prompt: str, max_tokens: int = 8192, attachments: list = None) -> dict:
    """
    Standard Async Generation. 
    Returns a dict: {"text": str, "tool_call": dict or None}
    """
    try:
        # Build multimodal content parts
        content = [prompt]
        if attachments:
            for att in attachments:
                content.append({
                    "mime_type": att["mime_type"],
                    "data": att["data"]
                })
        
        config_kwargs = {
            "max_output_tokens": max_tokens,
            "temperature": 0.7,
        }
        # Enable chain-of-thought thinking budget for Gemini 4 reasoning models if supported
        if "gemini-4" in getattr(model, "model_name", "") and hasattr(types, "ThinkingConfig"):
            config_kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=2048)

        config = types.GenerateContentConfig(**config_kwargs)
        if model.tools:
            config.tools = model.tools

        response = await model.client.aio.models.generate_content(
            model=model.model_name,
            contents=content,
            config=config
        )
        
        # Check for safety blocks
        if not response.candidates:
            if response.prompt_feedback and response.prompt_feedback.block_reason:
                return {"text": "I cannot answer this query due to safety restrictions.", "tool_call": None}

        # Handle Function Calls and Text
        tool_call = None
        full_text = ""
        
        if response.candidates and response.candidates[0].content and response.candidates[0].content.parts:
            for part in response.candidates[0].content.parts:
                if part.function_call:
                    # CANONICAL SCHEMA: {"tool": str, "parameters": dict, "monitor_mode": "terminal"}
                    tool_call = {
                        "tool": part.function_call.name,
                        "parameters": _proto_to_dict(part.function_call.args),
                        "monitor_mode": "terminal"
                    }
                try:
                    if part.text:
                        full_text += part.text
                except Exception:
                    pass

        return {
            "text": full_text.strip() if full_text else ("Initiating scan..." if tool_call else ""),
            "tool_call": tool_call
        }
    except Exception as e:
        err_msg = str(e)
        if any(code in err_msg for code in ["503", "429", "UNAVAILABLE", "ResourceExhausted", "high demand"]):
            logger.warning(f"Transient Gemini API issue ({model.model_name}): {err_msg}")
        else:
            logger.error(f"Error in Gemini generate_response ({model.model_name}): {err_msg}")
        raise e

# --- NEW STREAMING FUNCTION ---
async def generate_response_stream(model: GeminiModelWrapper, prompt: str, max_tokens: int = 8192, attachments: list = None):
    """
    Generates a response asynchronously and yields chunks. 
    Note: Function calls usually come in the first chunk or as a separate non-text part.
    """
    try:
        # Build multimodal content parts
        content = [prompt]
        if attachments:
            for att in attachments:
                content.append({
                    "mime_type": att["mime_type"],
                    "data": att["data"]
                })
        
        config_kwargs = {
            "max_output_tokens": max_tokens,
            "temperature": 0.7,
        }
        # Enable chain-of-thought thinking budget for Gemini 4 reasoning models if supported
        if "gemini-4" in getattr(model, "model_name", "") and hasattr(types, "ThinkingConfig"):
            config_kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=2048)

        config = types.GenerateContentConfig(**config_kwargs)
        if model.tools:
            config.tools = model.tools

        response = await model.client.aio.models.generate_content_stream(
            model=model.model_name,
            contents=content,
            config=config
        )
        
        async for chunk in response:
            # Check for function call in the chunk
            if chunk.candidates and chunk.candidates[0].content and chunk.candidates[0].content.parts:
                for part in chunk.candidates[0].content.parts:
                    if part.function_call:
                        # We yield a special JSON string for the tool call
                        args_dict = _proto_to_dict(part.function_call.args)
                        yield f"__TOOL_CALL__:{part.function_call.name}:{json.dumps(args_dict)}"
                    try:
                        if part.text:
                            yield part.text
                    except Exception:
                        pass
                
    except Exception as e:
        logger.error(f"Error in Gemini streaming: {str(e)}")
        yield f"\n[System Error: {str(e)}]"
