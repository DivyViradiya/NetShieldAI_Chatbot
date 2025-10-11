#!/usr/bin/env python3
"""
Script to safely delete all files from the uploads directory.
This helps in cleaning up temporary files and maintaining disk space.
"""

import os
import sys
from pathlib import Path

def clean_uploads_directory(uploads_path):
    """
    Delete all files in the specified uploads directory.
    
    Args:
        uploads_path (str): Path to the uploads directory
    """
    # Convert to Path object for better path handling
    uploads_dir = Path(uploads_path)
    
    # Verify the directory exists
    if not uploads_dir.exists() or not uploads_dir.is_dir():
        print(f"Error: Directory not found: {uploads_path}")
        return False
    
    # Get list of files (not directories) in the uploads folder
    files = [f for f in uploads_dir.iterdir() if f.is_file()]
    
    if not files:
        print("No files found in the uploads directory.")
        return True
    
    print(f"Found {len(files)} files to delete.")
    print("Files to be deleted:")
    for file in files:
        print(f"- {file.name}")
    
    # Ask for confirmation
    confirmation = input("\nAre you sure you want to delete these files? (y/n): ").strip().lower()
    if confirmation != 'y':
        print("Operation cancelled by user.")
        return False
    
    # Delete files
    deleted_count = 0
    for file in files:
        try:
            file.unlink()  # Delete the file
            deleted_count += 1
        except Exception as e:
            print(f"Error deleting {file.name}: {e}")
    
    print(f"\nSuccessfully deleted {deleted_count} out of {len(files)} files.")
    return True

if __name__ == "__main__":
    # Default uploads directory (one level up from the script)
    script_dir = Path(__file__).parent.absolute()
    default_uploads_dir = script_dir / "uploads"
    
    # Use provided path or default
    if len(sys.argv) > 1:
        uploads_path = sys.argv[1]
    else:
        uploads_path = str(default_uploads_dir)
    
    clean_uploads_directory(uploads_path)
