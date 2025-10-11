import PyPDF2
import os

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
        raise FileNotFoundError(f"The PDF file was not found: {pdf_path}")

    extracted_text = ""
    try:
        with open(pdf_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            # Iterate through its pages 
            for page_num in range(len(reader.pages)):
                page = reader.pages[page_num]
                text = page.extract_text()
                if text:
                    extracted_text += text + "\n" # Add a newline for readability between pages
    except PyPDF2.errors.PdfReadError as e:
        # Include robust error handling for unreadable PDFs or extraction issues 
        raise PyPDF2.errors.PdfReadError(f"Error reading PDF file {pdf_path}: {e}. It might be corrupted or encrypted.")
    except Exception as e:
        # Include robust error handling for unreadable PDFs or extraction issues 
        raise Exception(f"An unexpected error occurred during PDF extraction from {pdf_path}: {e}")

    return extracted_text

def save_text_to_file(text: str, output_path: str) -> None:
    """
    Saves the extracted text to a .txt file.

    Args:
        text (str): The text content to save.
        output_path (str): The path where the text file should be saved.

    Raises:
        IOError: If there's an error writing to the file.
    """
    try:
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as file:
            file.write(text)
        print(f"Text successfully saved to: {output_path}")
    except IOError as e:
        raise IOError(f"Error saving text to file {output_path}: {e}")

if __name__ == "__main__":
    # --- Example Usage (for testing) ---
    # Create a dummy PDF for testing (if you don't have one)
    # You would typically have a PDF file to test with.
    # For demonstration, let's assume 'dummy_report.pdf' exists in a 'documents' folder

    dummy_pdf_path = r"D:\NetShieldAI_Chatbot\chatbot_modules\documents\1_zap_auth_20250419_164709.pdf"
    output_txt_path = r"D:\NetShieldAI_Chatbot\chatbot_modules\documents\extracted_text.txt"

    print(f"Attempting to extract text from: {dummy_pdf_path}")
    try:
        # Create a documents directory for example if it doesn't exist
        if not os.path.exists("documents"):
            os.makedirs("documents")
            print("Created 'documents' directory. Please place a PDF inside it for testing.")

        # Extract text from PDF
        extracted_content = extract_text_from_pdf(dummy_pdf_path)
        
        # Save the extracted text to a file
        save_text_to_file(extracted_content, output_txt_path)
        
        # Print first 500 characters to console for verification
        print("\n--- Extracted Text (first 500 characters) ---")
        print(extracted_content[:500])
        print("\n--- End of Extracted Text ---")
        print(f"Full text has been saved to: {output_txt_path}")
        
    except FileNotFoundError as e:
        print(f"Error: {e}. Please ensure the PDF file exists at the specified path.")
    except PyPDF2.errors.PdfReadError as e:
        print(f"PDF Read Error: {e}")
    except IOError as e:
        print(f"File I/O Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")