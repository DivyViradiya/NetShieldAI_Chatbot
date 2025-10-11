import os
from huggingface_hub import hf_hub_download
from llama_cpp import Llama
import asyncio # <--- ADD THIS LINE

def load_model(model_id: str, model_basename: str, local_dir: str = "models") -> Llama:
    """
    Loads a local GGUF language model, downloading it if not present.
    Args:
        model_id (str): The Hugging Face model ID (e.g., "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF").
        model_basename (str): The specific GGUF filename (e.g., "openhermes-2.5-mistral-7b-dpo.Q4_K_M.gguf").
        local_dir (str): Directory to store the downloaded model.
    Returns:
        Llama: An instance of the loaded language model.
    """
    # Ensure the local_dir exists 
    if not os.path.exists(local_dir):
        os.makedirs(local_dir)

    model_path = os.path.join(local_dir, model_basename)

    # Check if the GGUF model file exists in local_dir 
    if not os.path.exists(model_path):
        print(f"Model not found at {model_path}. Downloading from Hugging Face...")
        # Use hf_hub_download to download it 
        hf_hub_download(
            repo_id=model_id,
            filename=model_basename,
            local_dir=local_dir,
            local_dir_use_symlinks=False # Use False to ensure physical download for llama.cpp
        )
        print("Download complete.")
    else:
        print(f"Model already exists at {model_path}. Loading...")

    # Initialize the Llama model
    # n_gpu_layers is set to -1 to offload all layers to the GPU if CUDA is available,
    # or 0 to use CPU. Adjust based on your system's GPU memory.
    llm = Llama(
        model_path=model_path,
        n_ctx=4096,  # Context window size (adjust based on model capability and memory)
        n_threads=os.cpu_count(), # Use half of available CPU cores
        n_gpu_layers=-1, # -1 to enable GPU acceleration if supported
        verbose=False # Set to True for more detailed logging from llama_cpp
    )
    return llm

# Make the generate_response function async
async def generate_response(llm: Llama, prompt: str, max_tokens: int = 2048) -> str:
    """
    Generates a response from the loaded Llama model.
    Args:
        llm (Llama): The loaded Llama model instance.
        prompt (str): The input prompt string.
        max_tokens (int): The maximum number of tokens to generate.
    Returns:
        str: The generated response text.
    """
    # Run the synchronous create_chat_completion in a thread pool to avoid blocking the event loop
    response = await asyncio.to_thread(
        llm.create_chat_completion,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
        temperature=0.7, # A common default, can be tuned
        stop=["</s>"] # Common stop token, can be expanded
    )
    # Extract the response content from the completion object
    return response["choices"][0]["message"]["content"]

if __name__ == "__main__":
    # --- Example Usage (for testing) ---
    # Define the model to download and load.
    # This uses the same model_id and filename as in the S3_Model_Download.ipynb
    MODEL_ID = "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF"
    MODEL_BASENAME = "openhermes-2.5-mistral-7b.Q4_K_M.gguf"
    # Adjust this path if your pretrained_language_model folder is elsewhere
    MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pretrained_language_model")

    print("--- Testing Model Loading ---")
    try:
        # Load the model
        model = load_model(MODEL_ID, MODEL_BASENAME, MODEL_DIR)

        # Test generating a response (now needs to be awaited)
        import asyncio
        
        async def test_generation():
            test_prompt = "What is the capital of France?"
            print(f"\n--- Testing Model Response for prompt: '{test_prompt}' ---")
            generated_text = await generate_response(model, test_prompt, max_tokens=50)
            print(f"Generated Response: {generated_text}")

            test_prompt_2 = "Explain what an Nmap SYN scan is in one sentence."
            print(f"\n--- Testing Model Response for prompt: '{test_prompt_2}' ---")
            generated_text_2 = await generate_response(model, test_prompt_2, max_tokens=100)
            print(f"Generated Response: {generated_text_2}")

        asyncio.run(test_generation())

    except Exception as e:
        print(f"An error occurred during testing: {e}")
        import traceback
        traceback.print_exc()