# 🛡️ NetShieldAI Chatbot

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Google Gemini](https://img.shields.io/badge/Google%20Gemini-8E75B2?style=for-the-badge&logo=googlegemini)](https://ai.google.dev/)
[![Pinecone](https://img.shields.io/badge/Pinecone-27272E?style=for-the-badge&logo=pinecone)](https://www.pinecone.io/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

NetShieldAI Chatbot is a sophisticated, AI-driven backend designed for analyzing cybersecurity reports and providing intelligent, context-aware assistance. Built with **FastAPI**, it leverages **Retrieval-Augmented Generation (RAG)** to ingest security reports (Nmap, OWASP ZAP, SSLScan) and answer user queries with high precision using either **Google Gemini** or local LLMs (Llama/Mistral).

---

## 📖 Table of Contents
- [🚀 Key Features](#-key-features)
- [🔄 System Workflow](#-system-workflow)
- [🛠️ System Architecture & Modules](#️-system-architecture--modules)
- [📓 Data Pipeline (Notebooks)](#-data-pipeline-notebooks)
- [📊 Data & Sample Reports](#-data--sample-reports)
- [📂 Project Structure](#-project-structure)
- [📋 Prerequisites](#-prerequisites)
- [⚙️ Installation](#️-installation)
- [🚀 Usage](#-usage)

---

## 🚀 Key Features

*   **🔍 Multi-Report Analysis:** Automatically detects and parses PDF reports from popular security tools:
    *   **Nmap** (Network discovery and security auditing)
    *   **OWASP ZAP** (Web application security scanning)
    *   **SSLScan** (SSL/TLS configuration)
    *   **Generic PDFs** (General documentation extraction)
*   **🧠 Dual RAG System:**
    *   **Internal RAG:** Creates a temporary, session-specific vector index for uploaded reports, allowing the AI to answer questions specifically about *your* data without data leakage.
    *   **External RAG:** Falls back to a general cybersecurity knowledge base (OWASP Top 10, etc.) for general queries.
*   **💻 Flexible LLM Support:**
    *   **Cloud:** Google Gemini API (default, high speed/quality).
    *   **Local:** `llama-cpp-python` support for running models like OpenHermes/Mistral locally for privacy.
*   **📂 Session Management:** Robust SQLite-based session tracking, allowing users to pause and resume investigations.
*   **⚡ Streaming Responses:** Supports real-time text streaming for a responsive user experience.
*   **📝 Smart Summarization:** Automatically generates executive summaries upon report upload and summarizes long chat histories to maintain context.

---

## 🔄 System Workflow

The NetShieldAI Chatbot operates through a sophisticated pipeline that combines static analysis, vector search, and generative AI.

### 1️⃣ Initialization
- On startup, `app.py` initializes the global **SentenceTransformer** embedding model and connects to the **Pinecone** vector database.
- It also pre-loads the configured LLM (Gemini or Local) to ensure low-latency responses.

### 2️⃣ Report Ingestion (`POST /upload_report`)
1.  **Upload:** The user uploads a PDF report (Nmap, ZAP, or SSLScan).
2.  **Detection:** The system heuristically identifies the report type based on filename and content signatures.
3.  **Parsing:** The appropriate parser (`nmap_parser.py`, etc.) converts the unstructured PDF into a structured JSON object.
4.  **Indexing (Internal RAG):**
    - The JSON data is chunked into semantic text blocks.
    - These chunks are embedded and upserted into a **temporary, session-specific Pinecone namespace** (e.g., `report-uuid-123`). This ensures data isolation.
5.  **Summarization:** The LLM generates an initial "Executive Summary" of the findings, which is returned to the user immediately.

### 3️⃣ Interactive Chat (`POST /chat` or `/chat_stream`)
1.  **Context Retrieval:**
    - **Intent Classification:** The system determines if the user's question is about the *uploaded report* or *general cybersecurity concepts*.
    - **Internal RAG:** If report-specific, it queries the session's temporary Pinecone namespace.
    - **External RAG:** If general, it queries the global `owasp-cybersecurity-kb` namespace containing OWASP and Port Scanning knowledge.
2.  **Prompt Construction:** A prompt is built combining:
    - The user's query.
    - Retrieved context (chunks from the report or knowledge base).
    - Recent chat history (for conversational continuity).
3.  **Generation:** The LLM generates a response based on this enriched prompt.
4.  **Persistence:** The message exchange is saved to the SQLite database (`sessions.db`) to maintain history.

### 4️⃣ Session Management & Cleanup
- Users can manage multiple sessions via the sidebar (Rename, Pin, Delete).
- **Cleanup:** When a session is deleted, the system removes the associated Pinecone namespace and temporary files to free up resources and maintain privacy.

---

## 🛠️ System Architecture & Modules

The system is organized into modular components within the `chatbot_modules/` directory.

### 📦 Core Infrastructure
- **`config.py`**: Central hub for API keys (`GEMINI_API_KEY`, `PINECONE_API_KEY`), model paths, and RAG parameters. Contains heuristic keyword lists for query routing.
- **`db_utils.py`**: Manages the **SQLite** persistence layer. Handles the lifecycle of `user_sessions` and `chat_history`.
- **`utils.py`**: Orchestrates the RAG workflow, including chunking, embedding, and retrieval logic.
- **`cleanup_utils.py`**: Ensures hygiene by deleting temporary Pinecone namespaces and clearing the `uploads/` directory.

### 🤖 LLM & Logic
- **`gemini_llm.py`**: Interface for the Google Gemini API, supporting standard and streaming responses.
- **`local_llm.py`**: Wrapper for `llama-cpp-python` to run GGUF models locally with GPU offloading.
- **`summarizer.py`**: Specialized prompt engineering for generating structured executive summaries.

### 📄 Report Parsers
- **`pdf_extractor.py`**: Robust text extraction from PDF files using `PyPDF2`.
- **`nmap_parser.py`**: Extracts Target IP, Host Status, and detailed Port/Service info using tuned Regex.
- **`zap_parser.py`**: Parses OWASP ZAP reports to identify High/Medium risk alerts and CVE IDs.
- **`ssl_parser.py`**: Detailed extraction of SSL/TLS configurations, including weak ciphers and protocol versions.

---

## 📓 Data Pipeline (Notebooks)

The `notebooks/` directory contains the scripts used to build and maintain the system's intelligence.

*   **`S1_Semantic_Search.ipynb`**: Fine-tunes a BERT-based `SentenceTransformer` on OWASP Q&A pairs.
*   **`S1-2_Model_Retraining.ipynb`**: Demonstrates continual learning for specific domains like Port Scanning.
*   **`S2_Embedding_Generation.ipynb`**: Generates embeddings for the knowledge base and upserts them to Pinecone.
*   **`S3_Model_Download.ipynb`**: Automates the setup of local inference engines (e.g., `Qwen2.5-Coder-3B`).

---

## 📊 Data & Sample Reports

Located in the `processed_files/` directory.

### 1. Sample Reports (`processed_files/reports/`)
- `nmap_report.pdf`, `zap_report.pdf`, `ssl_report.pdf`.

### 2. Knowledge Base QA Pairs (`processed_files/QA_Pairs/`)
- **OWASP_Top10_QA**: Comprehensive Q&A covering the OWASP Top 10 (2021).
- **PORT_Scanning_QA**: Specialized questions regarding port states and Nmap.
- **web Application Scanning QA**: Detailed datasets for ZAP scanning.

### 3. CVE Data (`processed_files/Processed_CVEs/`)
- Processed JSON files for CVEs from 2020 through 2025.

---

## 📂 Project Structure

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
└── uploads/               # Temporary storage for uploaded PDF reports
```

---

## 📋 Prerequisites

- Python 3.10+
- **Pinecone API Key:** For vector storage.
- **Gemini API Key:** For the default cloud LLM.
- (Optional) **C++ Compiler:** For `llama-cpp-python` local inference.

---

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
    Create a `.env` file in the root directory:
    ```env
    GEMINI_API_KEY=your_gemini_api_key_here
    PINECONE_API_KEY=your_pinecone_api_key_here
    PINECONE_ENVIRONMENT=gcp-starter
    ```

---

## 🚀 Usage

### Starting the Server
```bash
uvicorn app:app --host 0.0.0.0 --port 5000 --reload
```
The API will be available at `http://localhost:5000`.

### Key Endpoints
- `POST /upload_report`: Upload a PDF file and get an AI summary.
- `POST /chat`: Send a message to the bot.
- `POST /chat_stream`: Streaming response interface.
- `GET /get_history`: Retrieve chat history.
- `GET /get_user_sessions`: List user sessions.

---
