<div align="center">

# 🛡️ NetShieldAI Chatbot: The Autonomous Action Model

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Google Gemini](https://img.shields.io/badge/Google%20Gemini-8E75B2?style=for-the-badge&logo=googlegemini)](https://ai.google.dev/)
[![Pinecone](https://img.shields.io/badge/Pinecone-27272E?style=for-the-badge&logo=pinecone)](https://www.pinecone.io/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

The core intelligence behind NetShieldAI. This API serves as an **Autonomous Security Orchestrator**, translating natural language into complex offensive security workflows while providing context-aware answers grounded via advanced **Retrieval-Augmented Generation (RAG)** and **NetworkX** topology graphs.

</div>

---

## 📖 Table of Contents
1. [Core Capabilities & Architecture](#-core-capabilities--architecture)
2. [🤖 ReAct Orchestrator (Action Model)](#-react-orchestrator-action-model)
3. [🧠 Dual RAG & Ontology System](#-dual-rag--ontology-system)
4. [🛠️ System Modules Deep-Dive](#️-system-modules-deep-dive)
5. [📈 Data Pipeline & Notebooks](#-data-pipeline--notebooks)
6. [📂 Project Structure](#-project-structure)
7. [📋 Prerequisites](#-prerequisites)
8. [⚙️ Installation & Deployment](#️-installation--deployment)

---

## 🚀 Core Capabilities & Architecture

Built on asynchronous **FastAPI** utilizing Starlette `BackgroundTasks` and `run_in_threadpool`, this backend handles concurrent NLP processing without dropping HTTP connections. 

*   **🔍 Universal Report Parsing:** Detects, chunks, and structures results from 7 different scanning architectures including **Nmap, OWASP ZAP, SSLScan, TShark PCAPs, SQLMap, Semgrep, and custom Multi-Stage Kill Chains**.
*   **💻 Dynamic LLM Routing:** Fuses the reasoning capabilities of Cloud LLMs (Google Gemini 1.5 Pro) with privacy-focused Local Inferencing (`llama-cpp-python`). Automatically fails over between models if API quotas are hit.
*   **📂 Multi-Tenant Session Management:** robust SQLite schema (`sessions.db`) tracks historical dialogues, isolated embedded namespaces, and metadata attributes (Pinning, renaming).
*   **⚡ WebSockets & Streaming Response:** Answers are dynamically streamed back (`POST /chat_stream`) ensuring a fluid, low-latency UI terminal feel.

---

## 🤖 ReAct Orchestrator (Action Model)

The chatbot has been upgraded beyond passive Q&A into a full **Security Orchestrator**. Using the **ReAct (Reasoning and Acting)** framework, the LLM is equipped with custom function bounds.

**How it works (`agent_tools.py`):**
1.  **Intent Recognition:** When a user types *"Run a stealth port scan on example.com and intercept traffic for 30 seconds"*.
2.  **Parameter Extraction:** The LLM parses the sentence and formats structured JSON bounding arguments:
    *   `{"name": "nmap_scan", "arguments": {"target_ip": "example.com", "scan_type": "stealth", "protocol_type": "TCP"}}`
    *   `{"name": "packet_sniffer", "arguments": {"target_ip": "example.com", "duration": 30}}`
3.  **Proxy Forwarding:** The backend recognizes the executed function payloads and proxies the exact REST calls back to the primary Flask SOAR logic.
4.  **Local LLM Heuristics:** If using a Local deployment without native Function Calling, the backend runs an active RegExp heuristic (`parse_local_llm_action()`) against the LLM's raw stream to trigger the identical actions.

---

## 🧠 Dual RAG & Ontology System

Rather than passing 30MB PDF files into the prompt window, NetShieldAI utilizes deeply integrated RAG models.

### 1. Internal RAG (Session-Specific)
*   When a report is uploaded (`POST /upload_report`), the content is mapped via `pdf_extractor.py` and typed.
*   The raw structured JSON is chunked explicitly per vulnerability scope to preserve semantics.
*   Embeddings are generated (`all-MiniLM-L6-v2`) and upserted into an isolated, ephemeral **Pinecone Namespace** governed by the `session_uuid`. 
*   **Topology Graphing:** Concurrently, `graph_utils.py` uses **NetworkX** to generate an abstract relationship tree of Host -> Port -> Service -> Vulnerability, enabling exact path-finding queries.

### 2. External RAG (Global Cybersecurity DB)
*   For questions not pertaining to an active report (e.g., *"What is an IDOR?"*), the query is vectorized and hurled against the global `owasp-cybersecurity-kb` namespace containing thousands of curated NVD and OWASP mappings.

---

## 🛠️ System Modules Deep-Dive

The logic is modularized inside the `chatbot_modules/` directory.

### 🤖 LLM Interfacing
- **`gemini_llm.py`:** Standardized SDK wrappers for Gemini execution, injecting `agent_tools.py` arrays.
- **`local_llm.py`:** Wrapper utilizing GPU offloading via `llama-cpp-python` for running GGUF models autonomously.
- **`summarizer.py`:** Background task logic utilizing prompt engineering to provide initial Executive Summaries immediately after file ingestion.

### 📄 Parser Matrix
Specific parsers reconstruct CLI string outputs natively:
- **`nmap_parser.py`:** Reconstructs OS Fingerprints and Port Trees.
- **`zap_parser.py`:** Maps HTML alert layouts into JSON blocks identifying `cwe_id` elements.
- **`pcap_parser.py`:** Extracts anomalous metrics (ARP floods, Traffic bandwidth, TCP resets) from packet logs.
- **`killchain_parser.py` & `api_scanner_parser.py`:** Understands deeply nested, multi-phase dictionary outputs originating from the `tctr_engine.py` risk structures.

### 🧹 Environment Hygiene
- **`cleanup_utils.py` / `namespace_cleaner.py`:** On Session Deletion or End-Of-Life routines, securely truncates specific Pinecone namespaces and purges local `/uploads` buffers.

---

## 📈 Data Pipeline & Notebooks

NetShieldAI_Chatbot's RAG and context pipelines are strictly generated via Jupyer architectures stored in `notebooks/`.

*   **`S1_Semantic_Search.ipynb`:** Initial pre-processing pipelines handling text-chunking over OWASP corpuses.
*   **`S1-2_Model_Retraining.ipynb`:** Pipeline demonstrating Continual Learning logic appending Port Scanning topologies to the base vectors.
*   **`S2_Embedding_Generation.ipynb`:** Mass generation logic syncing hundreds of vectors to Pinecone instances.
*   **`S3_Model_Download.ipynb`:** Setup utility to gracefully download OpenHermes/Mistral parameters from HuggingFace to the system.

*(Reference datasets like `OWASP_Top10_QA` exist within `processed_files/`)*

---

## 📂 Project Structure

```text
NetShieldAI_Chatbot/
├── app.py                      # Main FastAPI uvicorn daemon
├── requirements.txt            # Package dependencies
├── chatbot_modules/            # Modular backend services
│   ├── config.py               # Constants, API references, Heuristic triggers
│   ├── db_utils.py             # SQLite querying and graph storage
│   ├── graph_utils.py          # NetworkX relationship builder
│   ├── agent_tools.py          # ReAct Function Calling definitions
│   ├── local_llm.py / gemini_llm.py
│   └── ..._parser.py           # Report schema mappers (7 modules)
├── data/                       # Local SQLite persistence (sessions.db)
├── notebooks/                  # AI tuning and Pinecone synchronization
├── processed_files/            # Vectorized QA bases & processed CVE logic
└── uploads/                    # Temporary buffered staging for PDF ingestions
```

---

## 📋 Prerequisites

To run the orchestrator securely, ensure you have:
- **Python 3.10+** (optimized for Starlette concurrency handles).
- **Pinecone API Key:** Essential for the Dual-RAG mapping.
- **Gemini API Key:** For ReAct function orchestration (unless exclusively utilizing Local LLMs).
- **C/C++ Build Tools:** Highly recommended for compiling `llama-cpp-python` with native CUDA/Metal acceleration.

---

## ⚙️ Installation & Deployment

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/DivyViradiya07/NetShieldAI_Chatbot.git
    cd NetShieldAI_Chatbot
    ```

2.  **Isolate Environment**
    ```bash
    python -m venv venv
    venv\Scripts\activate  # Windows
    # source venv/bin/activate  # MacOS/Linux
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment Bounds**
    Create a `.env` descriptor at the root layer mapping API services:
    ```env
    GEMINI_API_KEY=your_gemini_api_key_here
    PINECONE_API_KEY=your_pinecone_api_key_here
    PINECONE_ENVIRONMENT=gcp-starter
    ```

### ▶️ Initializing the API Server
Start the autonomous daemon utilizing Uvicorn handles:
```bash
uvicorn app:app --host 0.0.0.0 --port 5000 --reload
```
The FastAPI system will instantly bind to Port **5000** and output live streaming logs of LLM inference bounds and graph topologies.

### Interactivity Scope `(Internal)`
- `POST /upload_report` - Initializes Background RAG chunking and returns Executive Summaries.
- `POST /chat` & `POST /chat_stream` - Invokes ReAct logic and Contextual Retrieval.
- `GET /chatbot/session/{session_id}/graph` - Renders the NetworkX schema mapping JSON nodes.
- `GET /get_user_sessions` - Queries SQLite persistence matrices.
