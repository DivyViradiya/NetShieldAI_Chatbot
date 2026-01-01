import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# Path to the database file
DB_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_FOLDER, "sessions.db")

def init_db():
    """Initializes the SQLite database and creates tables with the new multi-session schema."""
    if not os.path.exists(DB_FOLDER):
        os.makedirs(DB_FOLDER)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Table: User Sessions
    # CHANGED: session_id is now the PRIMARY KEY (to allow multiple sessions per user)
    # ADDED: title, is_pinned columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT,
            is_pinned BOOLEAN DEFAULT 0,
            report_type TEXT,
            pinecone_namespace TEXT,
            parsed_report_data TEXT, 
            last_active TIMESTAMP
        )
    ''')

    # Create an index on user_id for faster sidebar loading
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON user_sessions(user_id)')

    # Table: Chat History
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(session_id) REFERENCES user_sessions(session_id)
        )
    ''')

    conn.commit()
    conn.close()

# --- Session Management ---

def get_session_by_id(session_id: str) -> Optional[Dict]:
    """Retrieves a specific session by its ID."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM user_sessions WHERE session_id = ?", (session_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        data = dict(row)
        if data.get('parsed_report_data'):
            try:
                data['parsed_report_data'] = json.loads(data['parsed_report_data'])
            except json.JSONDecodeError:
                data['parsed_report_data'] = None
        return data
    return None

def get_user_session(user_id: str) -> Optional[Dict]:
    """
    Retrieves the most recently active session for a user.
    Used as a fallback if no specific session_id is requested.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM user_sessions 
        WHERE user_id = ? 
        ORDER BY last_active DESC 
        LIMIT 1
    """, (user_id,))
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        data = dict(row)
        if data.get('parsed_report_data'):
            try:
                data['parsed_report_data'] = json.loads(data['parsed_report_data'])
            except:
                data['parsed_report_data'] = None
        return data
    return None

def update_or_create_session(user_id: str, session_id: str, report_type: str = None, pinecone_namespace: str = None, parsed_report_data: Dict = None, title: str = None):
    """Creates a new session or updates an existing one."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    timestamp = datetime.now()
    parsed_data_json = json.dumps(parsed_report_data) if parsed_report_data else None

    # Check if session exists using session_id (not user_id)
    cursor.execute("SELECT session_id FROM user_sessions WHERE session_id = ?", (session_id,))
    existing = cursor.fetchone()
    
    if existing:
        # Update existing session
        query = "UPDATE user_sessions SET last_active = ?"
        params = [timestamp]
        
        if report_type:
            query += ", report_type = ?"
            params.append(report_type)
        if pinecone_namespace:
            query += ", pinecone_namespace = ?"
            params.append(pinecone_namespace)
        if parsed_data_json:
            query += ", parsed_report_data = ?"
            params.append(parsed_data_json)
        # Only update title if explicitly provided
        if title:
            query += ", title = ?"
            params.append(title)
            
        query += " WHERE session_id = ?"
        params.append(session_id)
        
        cursor.execute(query, tuple(params))
    else:
        # Default title if creating new
        final_title = title if title else (f"{report_type.upper()} Analysis" if report_type else "New Chat")
        
        # Insert new session
        cursor.execute('''
            INSERT INTO user_sessions (session_id, user_id, title, report_type, pinecone_namespace, parsed_report_data, last_active, is_pinned)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        ''', (session_id, user_id, final_title, report_type, pinecone_namespace, parsed_data_json, timestamp))
        
    conn.commit()
    conn.close()

# --- New Features: Rename, Pin, Delete ---

def rename_session(session_id: str, new_title: str):
    """Updates the title of a specific session."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE user_sessions SET title = ? WHERE session_id = ?", (new_title, session_id))
    conn.commit()
    conn.close()

def toggle_pin_session(session_id: str, is_pinned: bool):
    """Updates the pinned status of a session."""
    # SQLite stores boolean as 1 or 0
    pin_val = 1 if is_pinned else 0
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE user_sessions SET is_pinned = ? WHERE session_id = ?", (pin_val, session_id))
    conn.commit()
    conn.close()

def delete_session(session_id: str):
    """Permanently deletes a session and its chat history."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Delete history first (Foreign Key logic)
    cursor.execute("DELETE FROM chat_history WHERE session_id = ?", (session_id,))
    # Delete session
    cursor.execute("DELETE FROM user_sessions WHERE session_id = ?", (session_id,))
    conn.commit()
    conn.close()

# --- Message Management ---

def add_message(session_id: str, role: str, content: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO chat_history (session_id, role, content)
        VALUES (?, ?, ?)
    ''', (session_id, role, content))
    conn.commit()
    conn.close()

def get_chat_history(session_id: str, limit: int = 50) -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT role, content FROM (
            SELECT id, role, content FROM chat_history 
            WHERE session_id = ? 
            ORDER BY id DESC
            LIMIT ?
        ) ORDER BY id ASC
    ''', (session_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def clear_user_data(user_id: str):
    """Wipes ALL data for a user (Master Reset)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Find all sessions for user
    cursor.execute("SELECT session_id FROM user_sessions WHERE user_id = ?", (user_id,))
    sessions = cursor.fetchall()
    
    for (sid,) in sessions:
        cursor.execute("DELETE FROM chat_history WHERE session_id = ?", (sid,))
        
    cursor.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def get_all_user_sessions(user_id: str) -> List[Dict]:
    """
    Returns a list of sessions sorted by:
    1. Pinned sessions (Top)
    2. Most recently active (Descending)
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT session_id, title, report_type, last_active, is_pinned
        FROM user_sessions 
        WHERE user_id = ? 
        ORDER BY is_pinned DESC, last_active DESC
    ''', (user_id,))
    
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        # Date formatting
        try:
            date_obj = datetime.strptime(str(row['last_active']).split('.')[0], "%Y-%m-%d %H:%M:%S")
            date_str = date_obj.strftime("%b %d, %H:%M")
        except:
            date_str = ""

        results.append({
            "session_id": row['session_id'],
            "title": row['title'] if row['title'] else "Untitled Analysis",
            "subtitle": date_str,
            "type": row['report_type'],
            "is_pinned": bool(row['is_pinned']) # Return boolean for frontend
        })
    return results