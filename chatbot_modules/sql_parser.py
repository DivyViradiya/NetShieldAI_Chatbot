import os
import re
import json
from typing import Dict, List, Any
from datetime import datetime

# Assume pdf_extractor.py exists and works as in your original code
# You would place this in the same directory.
try:
    from .pdf_extractor import extract_text_from_pdf
except ImportError:
    from pdf_extractor import extract_text_from_pdf


def parse_sql_report(raw_text: str, chunk_size: int = 250) -> Dict[str, Any]:
    """
    Parses raw text from a report into structured, word-based chunks,
    creating a maximum of 50 chunks.

    Args:
        raw_text (str): The raw text content of the report.
        chunk_size (int): The number of words to include in each chunk.

    Returns:
        dict: A structured dictionary containing the text broken into a
              limited number of chunks (max 50).
    """
    # 1. Normalize whitespace: replace newlines, tabs, and multiple spaces with a single space.
    cleaned_text = re.sub(r'\s+', ' ', raw_text).strip()

    # 2. Split the entire text into a list of words.
    words = cleaned_text.split(' ')

    # 3. Group words into chunks of the specified size, up to a limit.
    content_chunks = []
    CHUNK_LIMIT = 50  # Define the maximum number of chunks to create.

    for i in range(0, len(words), chunk_size):
        # **MODIFICATION: Stop if the chunk limit has been reached.**
        if len(content_chunks) >= CHUNK_LIMIT:
            break  # Exit the loop.

        word_chunk = words[i:i + chunk_size]
        # Join the words in the chunk back into a single string.
        chunk_text = ' '.join(word_chunk)
        
        chunk_data = {
            "chunk_id": len(content_chunks) + 1,
            "word_count": len(word_chunk),
            "text": chunk_text
        }
        content_chunks.append(chunk_data)

    # 4. Assemble the final report data structure.
    report_data: Dict[str, Any] = {
        "parsing_metadata": {
            "parser_type": "Generic Word Chunk Parser",
            "total_words": len(words),
            "chunk_size": chunk_size,
            # The total_chunks will now be the actual number of chunks created (<= 50).
            "total_chunks": len(content_chunks)
        },
        "content_chunks": content_chunks
    }
    
    return report_data

def process_sql_report_file(file_path: str, chunk_size: int = 250) -> Dict[str, Any]:
    """
    Processes any report PDF file and returns structured, chunked data.

    Args:
        file_path (str): Path to the report PDF file.
        chunk_size (int): The number of words for each text chunk.

    Returns:
        dict: Structured report data.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Report file not found: {file_path}")

    print(f"Processing SQL report: {file_path}")

    try:
        # Use the provided function to extract raw text from the PDF
        raw_text = extract_text_from_pdf(file_path)
        if not raw_text.strip():
            raise ValueError("Extracted text is empty or contains only whitespace.")

        # Parse the text into generic chunks
        report_data = parse_sql_report(raw_text, chunk_size)

        # Add file metadata to the final output
        report_data["file_metadata"] = {
            "filename": os.path.basename(file_path),
            "file_size_bytes": os.path.getsize(file_path),
            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }

        return report_data

    except Exception as e:
        print(f"Error processing SQL report {file_path}: {str(e)}")
        raise

if __name__ == "__main__":
    import sys
    
    # Check for correct command-line arguments
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sql_parser.py <path_to_report.pdf> [chunk_size]")
        print("Example: python sql_parser.py my_report.pdf 300")
        sys.exit(1)
        
    file_path = sys.argv[1]
    
    # Use provided chunk size or default to 250
    chunk_size = int(sys.argv[2]) if len(sys.argv) == 3 else 250
    
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    try:
        parsed_data = process_sql_report_file(file_path, chunk_size)
        
        if parsed_data:
            print(f"\n--- Parsed SQL Report (Chunk Size: {chunk_size}) ---")
            print(json.dumps(parsed_data, indent=2))
            print("\nReport processed successfully!")
        else:
            print("Error: Failed to parse the report.")
            
    except Exception as e:
        print(f"\nAn error occurred during processing: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)