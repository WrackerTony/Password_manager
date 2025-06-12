import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import base64
import os
from typing import Optional, Tuple, List

class Database:
    def __init__(self, db_file: str = 'users.db'):
        """Initialize database connection"""
        self.db_file = db_file
        self.initialize_database()

    def get_connection(self) -> sqlite3.Connection:
        """Create and return a database connection"""
        try:
            conn = sqlite3.connect(self.db_file)
            return conn
        except sqlite3.Error as e:
            raise Exception(f"Database connection error: {e}")

    def initialize_database(self) -> None:
        """Create necessary tables if they don't exist"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create passwords table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    site TEXT NOT NULL,
                    site_username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                )
            ''')

            # Create login_history table for security tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    success BOOLEAN,
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                )
            ''')

            conn.commit()
        except sqlite3.Error as e:
            raise Exception(f"Database initialization error: {e}")
        finally:
            conn.close()

    def add_user(self, username: str, password: str) -> bool:
        """Add a new user to the database"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Check if username already exists
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return False

            # Generate salt and hash password
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

            # Store user credentials
            cursor.execute(
                "INSERT INTO users (username, password, salt) VALUES (?, ?, ?)",
                (username, hashed_password.decode('utf-8'), salt.decode('utf-8'))
            )
            conn.commit()
            return True
        except sqlite3.Error:
            return False
        finally:
            conn.close()

    def verify_user(self, username: str, password: str) -> Tuple[bool, Optional[bytes]]:
        """Verify user credentials and return (success, salt)"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password, salt FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()

            if not result:
                return False, None

            stored_password, salt = result
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                return True, salt.encode('utf-8')
            return False, None
        except sqlite3.Error:
            return False, None
        finally:
            conn.close()

    def add_password(self, username: str, site: str, site_username: str, 
                    encrypted_password: str, notes: str = None) -> bool:
        """Add a new password entry"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO passwords (username, site, site_username, password, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, site, site_username, encrypted_password, notes))
            conn.commit()
            return True
        except sqlite3.Error:
            return False
        finally:
            conn.close()

    def get_passwords(self, username: str) -> List[tuple]:
        """Retrieve all passwords for a user"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, site, site_username, password, notes, created_at, updated_at
                FROM passwords
                WHERE username = ?
                ORDER BY site
            ''', (username,))
            return cursor.fetchall()
        except sqlite3.Error:
            return []
        finally:
            conn.close()

    def update_password(self, password_id: int, username: str, 
                       encrypted_password: str, notes: str = None) -> bool:
        """Update an existing password entry"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE passwords
                SET password = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND username = ?
            ''', (encrypted_password, notes, password_id, username))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error:
            return False
        finally:
            conn.close()

    def delete_password(self, password_id: int, username: str) -> bool:
        """Delete a password entry"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM passwords
                WHERE id = ? AND username = ?
            ''', (password_id, username))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error:
            return False
        finally:
            conn.close()

    def log_login_attempt(self, username: str, success: bool, ip_address: str = None) -> None:
        """Log login attempts for security tracking"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO login_history (username, success, ip_address)
                VALUES (?, ?, ?)
            ''', (username, success, ip_address))
            conn.commit()
        except sqlite3.Error:
            pass
        finally:
            conn.close()

    def get_login_history(self, username: str, limit: int = 10) -> List[tuple]:
        """Retrieve login history for a user"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT login_time, ip_address, success
                FROM login_history
                WHERE username = ?
                ORDER BY login_time DESC
                LIMIT ?
            ''', (username, limit))
            return cursor.fetchall()
        except sqlite3.Error:
            return []
        finally:
            conn.close()

    def change_master_password(self, username: str, new_password: str) -> bool:
        """Change user's master password"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Generate new salt and hash password
            new_salt = bcrypt.gensalt()
            new_hash = bcrypt.hashpw(new_password.encode('utf-8'), new_salt)

            cursor.execute('''
                UPDATE users
                SET password = ?, salt = ?
                WHERE username = ?
            ''', (new_hash.decode('utf-8'), new_salt.decode('utf-8'), username))
            conn.commit()
            return True
        except sqlite3.Error:
            return False
        finally:
            conn.close()

    def delete_user(self, username: str) -> bool:
        """Delete a user and all their data"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error:
            return False
        finally:
            conn.close()