#!/usr/bin/env python3
"""
Utility functions for cleaning up Pinecone namespaces and uploads directory.
"""
import os
import shutil
from pathlib import Path
from typing import Optional, Tuple

from pinecone import Pinecone

# Import configuration
from chatbot_modules.config import (
    PINECONE_INDEX_NAME,
    PINECONE_ENVIRONMENT,
    PINECONE_API_KEY,
    UPLOAD_FOLDER
)

def delete_namespace(session_id: str) -> Tuple[bool, str]:
    """
    Delete a specific Pinecone namespace.
    
    Args:
        session_id: The session ID to delete the namespace for
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    if not all([PINECONE_API_KEY, PINECONE_ENVIRONMENT, PINECONE_INDEX_NAME]):
        return False, "Missing Pinecone configuration"

    try:
        # Initialize Pinecone client
        pc = Pinecone(api_key=PINECONE_API_KEY)
        
        # Get the index
        index = pc.Index(PINECONE_INDEX_NAME)
        
        # Delete the specific namespace
        namespace = f"report-{session_id}"
        
        # First check if the namespace exists
        try:
            # Try to get stats for the namespace to check if it exists
            index.describe_index_stats(namespace=namespace)
        except Exception as e:
            if "not found" in str(e).lower():
                return True, f"Namespace {namespace} does not exist, nothing to delete"
            raise  # Re-raise other exceptions
            
        # If we get here, the namespace exists - delete it
        index.delete(delete_all=True, namespace=namespace)
        return True, f"Successfully deleted namespace {namespace}"
        
    except Exception as e:
        if "not found" in str(e).lower():
            return True, f"Namespace {namespace} does not exist, nothing to delete"
        return False, f"Error deleting namespace {namespace}: {str(e)}"

def clear_uploaded_files(session_id: str) -> Tuple[bool, str]:
    """
    Delete uploaded files for a specific session.
    
    Args:
        session_id: The session ID to delete files for
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    try:
        uploads_dir = Path(UPLOAD_FOLDER) / session_id
        
        # Skip if directory doesn't exist
        if not uploads_dir.exists():
            return True, f"No uploads found for session {session_id}"
            
        # Remove the entire session directory
        shutil.rmtree(uploads_dir)
        return True, f"Successfully cleared uploads for session {session_id}"
        
    except Exception as e:
        return False, f"Error clearing uploads: {str(e)}"
