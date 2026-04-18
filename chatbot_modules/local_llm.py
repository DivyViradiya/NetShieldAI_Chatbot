import os
import logging
from huggingface_hub import hf_hub_download
from llama_cpp import Llama
import asyncio
from chatbot_modules.config import LogColors

# Initialize module logger
logger = logging.getLogger(__name__)

# --- CHANGE 1: Set defaults to your specific Qwen model ---
def load_model(
    model_id: str = "bartowski/Qwen2.5-Coder-3B-Instruct-GGUF", 
    model_basename: str = "Qwen2.5-Coder-3B-Instruct-Q4_K_M.gguf", 
    local_dir: str = None
) -> Llama:
    """Loads the local Qwen GGUF model."""
    
    if local_dir is None:
        # Default to a 'pretrained_language_model' folder in the current project
        current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        local_dir = os.path.join(current_dir, "pretrained_language_model")

    if not os.path.exists(local_dir):
        os.makedirs(local_dir)
        
    model_path = os.path.join(local_dir, model_basename)
    
    if not os.path.exists(model_path):
        logger.info(f"{LogColors.INIT}[INIT] Model not found. Downloading {model_basename}...{LogColors.RESET}")
        hf_hub_download(repo_id=model_id, filename=model_basename, local_dir=local_dir, local_dir_use_symlinks=False)
    else:
        logger.info(f"{LogColors.INIT}[INIT] Loading local model from {model_path}{LogColors.RESET}")

    # Initialize Llama
    llm = Llama(
        model_path=model_path,
        n_ctx=8192, 
        n_gpu_layers=-1,
        n_batch=512,
        chat_format="chatml",
        verbose=False  # <--- THIS suppresses the repack/loading logs
    )
    return llm

async def generate_response(llm: Llama, prompt: str, max_tokens: int = 2048) -> dict:
    """Standard Async Generation (Non-Streaming)"""
    response = await asyncio.to_thread(
        llm.create_chat_completion,
        messages=[
            {"role": "system", "content": "You are a helpful cybersecurity coding assistant."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=max_tokens,
        temperature=0.7,
    )
    return {
        "text": response["choices"][0]["message"]["content"],
        "tool_call": None # Local model doesn't support native tool calls yet
    }

# Note: Streaming functionality (generate_response_stream) has been 
# deprecated and removed. The async /chat_stream endpoint now falls back 
# to the local model via the blocking execute_with_retry wrapper.