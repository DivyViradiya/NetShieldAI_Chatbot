#!/usr/bin/env python3
"""
Script to clean up Pinecone namespaces that start with 'report-'
"""
import os
import sys
from typing import List
from dotenv import load_dotenv
from pinecone import Pinecone

# Load environment variables from .env file
load_dotenv()

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Import configuration
from chatbot_modules.config import (
    PINECONE_INDEX_NAME,
    PINECONE_ENVIRONMENT,
    PINECONE_API_KEY
)

def delete_report_namespaces():
    """
    Delete all Pinecone namespaces that start with 'report-'
    """
    if not all([PINECONE_API_KEY, PINECONE_ENVIRONMENT, PINECONE_INDEX_NAME]):
        print("Error: Missing required Pinecone configuration")
        print("Please ensure PINECONE_API_KEY, PINECONE_ENVIRONMENT, and PINECONE_INDEX_NAME are set")
        return False

    try:
        # Initialize Pinecone client
        pc = Pinecone(api_key=PINECONE_API_KEY)
        
        # Get the index
        index = pc.Index(PINECONE_INDEX_NAME)
        
        # Get all namespaces
        index_stats = index.describe_index_stats()
        namespaces = index_stats.get('namespaces', {})
        
        # Find namespaces starting with 'report-'
        report_namespaces = [ns for ns in namespaces.keys() if ns.startswith('report-')]
        
        if not report_namespaces:
            print("No namespaces starting with 'report-' found.")
            return True
            
        print(f"Found {len(report_namespaces)} namespaces to delete:")
        for ns in report_namespaces:
            print(f"- {ns}")
            
        # Confirm deletion
        confirm = input("\nDo you want to delete these namespaces? (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("Operation cancelled.")
            return False
            
        # Delete namespaces
        for ns in report_namespaces:
            try:
                index.delete(delete_all=True, namespace=ns)
                print(f"Successfully deleted namespace: {ns}")
            except Exception as e:
                print(f"Error deleting namespace {ns}: {str(e)}")
                
        return True
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return False

if __name__ == "__main__":
    print("Pinecone Namespace Cleanup Tool")
    print("This will delete all namespaces starting with 'report-'")
    print("-" * 50)
    
    if delete_report_namespaces():
        print("\nCleanup completed successfully.")
    else:
        print("\nCleanup failed or was cancelled.")
        sys.exit(1)