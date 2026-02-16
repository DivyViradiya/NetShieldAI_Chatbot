import PyPDF2
import os
import logging

# Initialize module-level logger
logger = logging.getLogger(__name__)

def extract_text_from_pdf(pdf_path: str) -> str:
    """
    Extracts all readable text from a PDF document.

    Args:
        pdf_path (str): The path to the PDF file.

    Returns:
        str: The extracted text from the PDF.

    Raises:
        FileNotFoundError: If the PDF file does not exist.
        PyPDF2.errors.PdfReadError: If the PDF file is corrupted or unreadable.
        Exception: For other unexpected errors during extraction.
    """
    if not os.path.exists(pdf_path):
        logger.error(f"PDF file not found at: {pdf_path}")
        raise FileNotFoundError(f"The PDF file was not found: {pdf_path}")

    extracted_text = ""
    try:
        logger.info(f"Starting text extraction for: {pdf_path}")
        with open(pdf_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            
            # Log the number of pages found
            num_pages = len(reader.pages)
            logger.info(f"PDF loaded. Total pages: {num_pages}")

            # Iterate through its pages 
            for i, page in enumerate(reader.pages):
                try:
                    text = page.extract_text()
                    if text:
                        extracted_text += text + "\n"
                    else:
                        logger.warning(f"No text extracted from page {i+1}. It might be an image-only page.")
                except Exception as page_error:
                    logger.warning(f"Could not extract text from page {i+1}: {page_error}")
                    continue # Skip this page and try the next one

        total_chars = len(extracted_text)
        logger.info(f"Extraction complete. Extracted {total_chars} characters.")
        
        return extracted_text

    except PyPDF2.errors.PdfReadError as e:
        logger.error(f"PyPDF2 Error reading {pdf_path}: {e}")
        raise PyPDF2.errors.PdfReadError(f"Error reading PDF file. It might be corrupted or encrypted.")
    except Exception as e:
        logger.error(f"Unexpected error extracting PDF {pdf_path}: {e}")
        raise Exception(f"An unexpected error occurred during PDF extraction: {e}")

def save_text_to_file(text: str, output_path: str) -> None:
    """
    Saves the extracted text to a .txt file.

    Args:
        text (str): The text content to save.
        output_path (str): The path where the text file should be saved.
    """
    try:
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as file:
            file.write(text)
        logger.info(f"Text successfully saved to: {output_path}")
    except IOError as e:
        logger.error(f"Failed to save text to {output_path}: {e}")
        raise IOError(f"Error saving text to file: {e}")

if __name__ == "__main__":
    # --- Example Usage (for independent testing) ---
    from .config import PROJECT_ROOT
    logging.basicConfig(level=logging.INFO)
    
    # Use raw string for paths to handle backslashes on Windows
    dummy_pdf_path = os.path.join(PROJECT_ROOT, "uploads", "killchain_report.pdf")
    output_txt_path = os.path.join(PROJECT_ROOT, "uploads", "xtracted_text.txt")

    if os.path.exists(dummy_pdf_path):
        print(f"Attempting to extract text from: {dummy_pdf_path}")
        try:
            # Extract text from PDF
            extracted_content = extract_text_from_pdf(dummy_pdf_path)
            
            # Save the extracted text to a file
            save_text_to_file(extracted_content, output_txt_path)
            
            # Print preview
            print("\n--- Extracted Text Preview (first 500 chars) ---")
            print(extracted_content[:500])
            print("\n--- End of Preview ---")
            
        except Exception as e:
            print(f"Test run failed: {e}")
    else:
        print(f"Test skipped: File not found at {dummy_pdf_path}")
        print("To test, update the 'dummy_pdf_path' variable in the __main__ block.")