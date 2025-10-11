# VulnScanAI - Security Report Analysis Chatbot

VulnScanAI is an intelligent chatbot designed to analyze security reports (Nmap, ZAP, SSLScan, MobSF, Nikto) and provide interactive insights using either a local LLM (OpenHermes 2.5 Mistral 7B) or Google's Gemini, enhanced with RAG (Retrieval-Augmented Generation) capabilities.

## Features

- **Multiple Report Formats**: Supports PDF, TXT, MD
- **Security Tools Integration**: Works with Nmap, ZAP, SSLScan, MobSF (Android/iOS), and Nikto reports
- **Dual LLM Support**:
  - Local: OpenHermes 2.5 Mistral 7B (privacy-focused)
  - Cloud: Google's Gemini (requires API key)
- **RAG Implementation**: Enhanced responses using Retrieval-Augmented Generation with Pinecone
- **Interactive Chat**: Natural language interface for querying report details
- **Comprehensive Analysis**: Identifies vulnerabilities, suggests remediations, and provides contextual insights
- **Session Management**: Maintains conversation context with automatic summarization

## Prerequisites

- Python 3.8+
- Git
- [Pinecone](https://www.pinecone.io/) account (for vector storage)
- (Optional) Google Cloud account with Gemini API access
- Sufficient disk space for the language model (~4-8GB)
- At least 8GB RAM (16GB recommended for local LLM)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/VulnScanAI_Chatbot.git
   cd VulnScanAI_Chatbot
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate  # Windows
   # OR
   source venv/bin/activate  # Linux/Mac
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   If requirements.txt doesn't exist, install the following packages:
   ```bash
   pip install fastapi uvicorn python-multipart python-dotenv
   pip install sentence-transformers pinecone-client pypdf2
   pip install llama-cpp-python  # For local LLM support
   pip install google-generativeai  # For Gemini support
   ```

4. Set up environment variables:
   Create a `.env` file in the project root with the following content:
   ```
   # Required for Pinecone
   PINECONE_API_KEY=your_pinecone_api_key
   PINECONE_ENVIRONMENT=your_pinecone_environment
   
   # Required for Gemini
   GEMINI_API_KEY=your_gemini_api_key
   
   # Optional: Configure model paths (defaults shown)
   # LLM_MODEL_DIR=./pretrained_language_model
   # RAG_EMBEDDING_MODEL_PATH=./fine_tuned_owasp_model_advanced
   ```

## Download Models

1. **Local LLM Model**:
   The application will automatically download the OpenHermes 2.5 Mistral 7B model (GGUF format) on first run.
   
   Manual download (optional):
   ```bash
   python -c "from chatbot_modules.local_llm import load_model; load_model()"
   ```

2. **RAG Embedding Model**:
   The fine-tuned SentenceTransformer model should be placed in the `fine_tuned_owasp_model_advanced` directory.

## Usage

### Running the API Server

1. Start the FastAPI server:
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000 --reload
   ```

   The API will be available at `http://localhost:8000`

### API Endpoints

1. **Upload Report**
   ```
   POST /upload/
   Content-Type: multipart/form-data
   
   Form Data:
   - file: [report file]
   - llm_mode: [optional] "local" or "gemini" (default: "local")
   ```
   
   Returns:
   ```json
   {
     "session_id": "unique-session-id",
     "report_type": "detected_report_type",
     "summary": "generated_summary"
   }
   ```

2. **Chat**
   ```
   POST /chat/
   Content-Type: application/json
   
   {
     "message": "Your question about the report",
     "session_id": "session_id_from_upload"
   }
   ```
   
   Returns:
   ```json
   {
     "response": "AI response",
     "session_id": "same_session_id"
   }
   ```

3. **Clear Chat Session**
   ```
   POST /clear_chat/
   Content-Type: application/json
   
   {
     "session_id": "session_id_to_clear"
   }
   ```

### Example Usage with curl

```bash
# Upload a report
curl -X POST -F "file=@path/to/your/report.pdf" http://localhost:8000/upload/

# Chat about the report
curl -X POST -H "Content-Type: application/json" -d '{"message":"What vulnerabilities were found?","session_id":"your-session-id"}' http://localhost:8000/chat/
```

## Project Structure

```
VulnScanAI_Chatbot/
├── .env                    # Environment variables
├── app.py                 # FastAPI application
├── requirements.txt        # Python dependencies
├── Data/                  # Processed data and reports
│   ├── Processed_CVEs/    # CVE data
│   ├── QA_Pairs/          # Security QA pairs
│   └── reports/           # Example reports
├── chatbot_modules/       # Core functionality
│   ├── config.py          # Configuration settings
│   ├── local_llm.py       # Local LLM integration
│   ├── gemini_llm.py      # Google Gemini integration
│   ├── *parser.py         # Report parsers (nmap, zap, ssl, etc.)
│   ├── pdf_extractor.py   # Text extraction from PDFs
│   ├── summarizer.py      # Report summarization
│   └── utils.py           # Utility functions and RAG implementation
├── fine_tuned_owasp_model_advanced/  # Fine-tuned embedding model
└── pretrained_language_model/       # Local LLM model storage
```

## Configuration

Modify `chatbot_modules/config.py` to adjust:
- Default LLM mode (local/gemini)
- Model paths and parameters
- RAG settings (top-k retrieval, chunk sizes)
- Chat history management
- Report-specific keywords for context awareness

## Development

1. **Adding New Report Types**:
   - Create a new parser in `chatbot_modules/` following the pattern of existing parsers
   - Add the report type to the detection logic in `app.py`
   - Update the summarizer with a new prompt template if needed

2. **Customizing the LLM**:
   - For local LLM: Adjust parameters in `local_llm.py`
   - For Gemini: Modify settings in `gemini_llm.py`

## Troubleshooting

- **Model Loading Issues**:
  - Ensure sufficient disk space for model downloads
  - Check internet connectivity for initial model download
  - Verify file permissions in the model directories

- **Pinecone Connection Issues**:
  - Verify API key and environment variables
  - Check your Pinecone dashboard for service status

- **Performance Issues**:
  - For local LLM: Reduce context size if experiencing memory issues
  - For RAG: Adjust chunk size and top-k parameters in config


## Acknowledgments

- OpenHermes 2.5 Mistral 7B for the local LLM
- Google's Gemini for cloud-based inference
- Pinecone for vector storage and retrieval
- All open-source libraries and tools used in this project
