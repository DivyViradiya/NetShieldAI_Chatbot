# NetShieldAI Chatbot

NetShieldAI Chatbot is a powerful, AI-driven backend for analyzing cybersecurity reports and providing intelligent, context-aware assistance. Built with **FastAPI**, it leverages **Retrieval-Augmented Generation (RAG)** to ingest security reports (Nmap, OWASP ZAP, SSLScan) and answer user queries with high precision using either **Google Gemini** or local LLMs (Llama/Mistral).

## 🚀 Key Features

*   **Multi-Report Analysis:** Automatically detects and parses PDF reports from popular security tools:
    *   **Nmap** (Network discovery and security auditing)
    *   **OWASP ZAP** (Web application security scanning)
    *   **SSLScan** (SSL/TLS configuration)
    *   **Generic PDFs** (General documentation extraction)
*   **Dual RAG System:**
    *   **Internal RAG:** Creates a temporary, session-specific vector index for uploaded reports, allowing the AI to answer questions specifically about *your* data without data leakage.
    *   **External RAG:** Falls back to a general cybersecurity knowledge base (OWASP Top 10, etc.) for general queries.
*   **Flexible LLM Support:**
    *   **Cloud:** Google Gemini API (default, high speed/quality).
    *   **Local:** `llama-cpp-python` support for running models like OpenHermes/Mistral locally for privacy.
*   **Session Management:** Robust SQLite-based session tracking, allowing users to pause and resume investigations.
*   **Streaming Responses:** Supports real-time text streaming for a responsive user experience.
*   **Smart Summarization:** Automatically generates executive summaries upon report upload and summarizes long chat histories to maintain context.

## 🔄 System Workflow

The NetShieldAI Chatbot operates through a sophisticated pipeline that combines static analysis, vector search, and generative AI.

### 1. Initialization
*   On startup, `app.py` initializes the global **SentenceTransformer** embedding model and connects to the **Pinecone** vector database.
*   It also pre-loads the configured LLM (Gemini or Local) to ensure low-latency responses.

### 2. Report Ingestion (`POST /upload_report`)
1.  **Upload:** The user uploads a PDF report (Nmap, ZAP, or SSLScan).
2.  **Detection:** The system heuristically identifies the report type based on filename and content signatures.
3.  **Parsing:** The appropriate parser (`nmap_parser.py`, etc.) converts the unstructured PDF into a structured JSON object.
4.  **Indexing (Internal RAG):**
    *   The JSON data is chunked into semantic text blocks.
    *   These chunks are embedded and upserted into a **temporary, session-specific Pinecone namespace** (e.g., `report-uuid-123`). This ensures data isolation.
5.  **Summarization:** The LLM generates an initial "Executive Summary" of the findings, which is returned to the user immediately.

### 3. Interactive Chat (`POST /chat` or `/chat_stream`)
1.  **Context Retrieval:**
    *   **Intent Classification:** The system determines if the user's question is about the *uploaded report* or *general cybersecurity concepts*.
    *   **Internal RAG:** If report-specific, it queries the session's temporary Pinecone namespace.
    *   **External RAG:** If general, it queries the global `owasp-cybersecurity-kb` namespace containing OWASP and Port Scanning knowledge.
2.  **Prompt Construction:** A prompt is built combining:
    *   The user's query.
    *   Retrieved context (chunks from the report or knowledge base).
    *   Recent chat history (for conversational continuity).
3.  **Generation:** The LLM generates a response based on this enriched prompt.
4.  **Persistence:** The message exchange is saved to the SQLite database (`sessions.db`) to maintain history.

### 4. Session Management & Cleanup
*   Users can manage multiple sessions via the sidebar (Rename, Pin, Delete).
*   **Cleanup:** When a session is deleted, the system removes the associated Pinecone namespace and temporary files to free up resources and maintain privacy.

## 🛠️ System Architecture & Modules

The system is organized into modular components within the `chatbot_modules/` directory, ensuring separation of concerns and maintainability.

### 1. Core Infrastructure
*   **`config.py`**: Central hub for API keys (`GEMINI_API_KEY`, `PINECONE_API_KEY`), model paths, and RAG parameters. It also contains the **Heuristic Keyword Lists** used to route user queries between Internal (report-specific) and External (general KB) RAG.
*   **`db_utils.py`**: Manages the **SQLite** persistence layer. Handles the lifecycle (Create, Read, Update, Delete) of `user_sessions` and `chat_history`. Links sessions to their Pinecone vector namespaces.
*   **`utils.py` (The "Brain"):** Orchestrates the RAG workflow.
    *   **Chunking:** Intelligently breaks down JSON report data into semantic text blocks.
    *   **Embedding:** Uses `SentenceTransformers` to generate vector embeddings.
    *   **Retrieval:** Queries Pinecone for relevant context based on user questions.
*   **`cleanup_utils.py`**: Ensures hygiene by deleting temporary Pinecone namespaces and clearing the `uploads/` directory when sessions are deleted.

### 2. LLM & Logic
*   **`gemini_llm.py`**: Interface for the Google Gemini API, supporting both standard and **streaming** responses.
*   **`local_llm.py`**: Wrapper for `llama-cpp-python` to run GGUF models (e.g., Qwen, Mistral) locally, complete with GPU offloading support.
*   **`summarizer.py`**: Contains specialized prompt engineering logic. It acts as a "Security Consultant," generating structured executive summaries and remediation steps from raw report data.

### 3. Report Parsers
These modules transform unstructured PDF text into structured JSON data.
*   **`pdf_extractor.py`**: Robust text extraction from PDF files using `PyPDF2`.
*   **`nmap_parser.py`**: Extracts Target IP, Host Status, and detailed Port/Service info using Regex patterns tuned for NetShieldAI reports.
*   **`zap_parser.py`**: parses OWASP ZAP reports to identify High/Medium risk alerts, CVE IDs, and solutions, handling common PDF formatting quirks.
*   **`ssl_parser.py`**: Detailed extraction of SSL/TLS configurations, including weak ciphers, protocol versions, and certificate validity.

## 📓 Data Pipeline (Notebooks)

The `notebooks/` directory contains the scripts used to build and maintain the RAG system's intelligence.

*   **`S1_Semantic_Search.ipynb`**: The foundation of the system. Fine-tunes a BERT-based `SentenceTransformer` (`all-mpnet-base-v2`) on OWASP Q&A pairs to specialize it for cybersecurity terminology.
*   **`S1-2_Model_Retraining.ipynb`**: Demonstrates continual learning. It takes the model from S1 and further fine-tunes it on specific domains (e.g., Port Scanning) to adapt to new data without losing prior knowledge.
*   **`S2_Embedding_Generation.ipynb`**: The production deployment script. It uses the fine-tuned model to generate embeddings for the entire knowledge base and upserts them into the global **Pinecone** index (`owasp-cybersecurity-kb`).
*   **`S3_Model_Download.ipynb`**: Automates the setup of the local inference engine. It downloads optimized GGUF models (like `Qwen2.5-Coder-3B`) from HuggingFace and verifies they run correctly with `llama-cpp-python`.

## 📊 Data & Sample Reports

The system includes a variety of sample data for testing and knowledge base building, located in the `processed_files/` directory.

### 1. Sample Reports (`processed_files/reports/`)
These files serve as the primary test suite for the PDF parsers:
*   **`nmap_report.pdf`**: Example of network scan results.
*   **`zap_report.pdf`**: Example of web application security findings.
*   **`ssl_report.pdf`**: Example of SSL/TLS configuration analysis.
*   **`extracted_text.txt`**: Intermediate text representation after PDF extraction.

### 2. Knowledge Base QA Pairs (`processed_files/QA_Pairs/`)
Structured JSON datasets used to train the embedding models and populate the external RAG:
*   **`OWASP_Top10_QA/`**: Comprehensive Q&A pairs covering the OWASP Top 10 vulnerabilities (A01-A10 2021).
*   **`PORT_Scanning_QA/`**: Specialized questions and answers regarding port states, protocols, and Nmap usage.
*   **`web Application Scanning QA/`**: Detailed datasets for ZAP scanning and web-specific vulnerabilities.

### 3. CVE Data (`processed_files/Processed_CVEs/`)
*   Contains processed JSON files for CVEs from 2020 through 2025, providing the AI with historical and recent vulnerability context.

## 📋 Prerequisites

*   Python 3.10+
*   **Pinecone API Key:** Required for vector storage.
*   **Gemini API Key:** Required for the default cloud LLM.
*   (Optional) **C++ Compiler:** Required if you plan to build `llama-cpp-python` for local inference.

## ⚙️ Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/your-repo/NetShieldAI_Chatbot.git
    cd NetShieldAI_Chatbot
    ```

2.  **Create a Virtual Environment**
    ```bash
    python -m venv venv
    # Windows
    venv\Scripts\activate
    # Linux/Mac
    source venv/bin/activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Environment Configuration**
    Create a `.env` file in the root directory with the following variables:
    ```env
    # Gemini API Key (Get from Google AI Studio)
    GEMINI_API_KEY=your_gemini_api_key_here

    # Pinecone Vector DB Configuration
    PINECONE_API_KEY=your_pinecone_api_key_here
    PINECONE_ENVIRONMENT=gcp-starter  # or your specific region
    ```

## 🚀 Usage

### Starting the Server
Run the FastAPI server using Uvicorn:

```bash
uvicorn app:app --host 0.0.0.0 --port 5000 --reload
```
The API will be available at `http://localhost:5000`.

### Key Endpoints

*   **`POST /upload_report`**: Upload a PDF file.
    *   **Params:** `file` (PDF), `user_id` (string), `llm_mode` (optional: 'gemini' or 'local').
    *   **Returns:** Session ID and an AI-generated summary of the report.
*   **`POST /chat`**: Send a message to the bot.
    *   **Body:** `{"message": "What ports are open?", "session_id": "...", "user_id": "..."}`
*   **`POST /chat_stream`**: Same as `/chat` but returns a streaming response.
*   **`GET /get_history`**: Retrieve past chat history for a session.
*   **`GET /get_user_sessions`**: List all sessions for a user.

```text
NetShieldAI_Chatbot/
├── app.py                 # Main FastAPI application entry point
├── requirements.txt       # Project dependencies
├── chatbot_modules/       # Core logic modules
│   ├── config.py          # Configuration settings
│   ├── db_utils.py        # SQLite database operations
│   ├── gemini_llm.py      # Google Gemini integration
│   ├── local_llm.py       # Local Llama model integration
│   ├── nmap_parser.py     # Parser for Nmap reports
│   ├── zap_parser.py      # Parser for ZAP reports
│   └── ...
├── data/                  # SQLite database storage
├── fine_tuned_owasp_.../  # Local embedding model files
├── notebooks/             # Data pipeline & model training scripts
└── uploads/               # Temporary storage for uploaded PDF reports (auto-cleaned)
```

