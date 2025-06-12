from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import bcrypt
from typing import Tuple, Optional

class Encryption:
    def __init__(self):
        """Initialize encryption class"""
        self.backend = default_backend()
        self.iterations = 100000  # Number of iterations for PBKDF2

    def generate_key_from_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Generate an encryption key from a password using PBKDF2
        Returns (key, salt)
        """
        if salt is None:
            salt = os.urandom(32)  # Generate new salt if none provided
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def create_cipher_suite(self, key: bytes) -> Fernet:
        """Create a Fernet cipher suite from a key"""
        return Fernet(key)

    def encrypt_password(self, cipher_suite: Fernet, password: str) -> str:
        """Encrypt a password using the provided cipher suite"""
        try:
            encrypted_data = cipher_suite.encrypt(password.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {str(e)}")

    def decrypt_password(self, cipher_suite: Fernet, encrypted_password: str) -> str:
        """Decrypt a password using the provided cipher suite"""
        try:
            decrypted_data = cipher_suite.decrypt(base64.urlsafe_b64decode(encrypted_password.encode()))
            return decrypted_data.decode()
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {str(e)}")

    @staticmethod
    def hash_master_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Hash the master password using bcrypt
        Returns (hashed_password, salt)
        """
        if salt is None:
            salt = bcrypt.gensalt()
        
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed, salt

    @staticmethod
    def verify_master_password(password: str, hashed_password: bytes) -> bool:
        """Verify the master password against its hash"""
        try:
            return bcrypt.checkpw(password.encode(), hashed_password)
        except Exception:
            return False

    def rotate_key(self, old_cipher_suite: Fernet, new_key: bytes, encrypted_data: str) -> str:
        """
        Rotate encryption key for a piece of encrypted data
        Used when changing master password
        """
        try:
            # Decrypt with old key
            decrypted_data = self.decrypt_password(old_cipher_suite, encrypted_data)
            
            # Encrypt with new key
            new_cipher_suite = self.create_cipher_suite(new_key)
            return self.encrypt_password(new_cipher_suite, decrypted_data)
        except Exception as e:
            raise EncryptionError(f"Key rotation failed: {str(e)}")

    @staticmethod
    def generate_random_password(length: int = 16) -> str:
        """Generate a secure random password"""
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
            
        # Character sets for password generation
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each set
        password = [
            os.urandom(1)[0] % len(uppercase),
            os.urandom(1)[0] % len(lowercase),
            os.urandom(1)[0] % len(digits),
            os.urandom(1)[0] % len(special)
        ]
        
        # Fill remaining length with random characters
        all_chars = uppercase + lowercase + digits + special
        for _ in range(length - 4):
            password.append(all_chars[os.urandom(1)[0] % len(all_chars)])
            
        # Shuffle the password
        for i in range(len(password) - 1, 0, -1):
            j = os.urandom(1)[0] % (i + 1)
            password[i], password[j] = password[j], password[i]
            
        return ''.join(password)

    def secure_string_comparison(self, str1: str, str2: str) -> bool:
        """
        Perform constant-time string comparison to prevent timing attacks
        """
        if len(str1) != len(str2):
            return False
        
        result = 0
        for x, y in zip(str1.encode(), str2.encode()):
            result |= x ^ y
        return result == 0

class EncryptionError(Exception):
    """Custom exception for encryption-related errors"""
    pass

class KeyDerivationError(Exception):
    """Custom exception for key derivation errors"""
    pass

class SecurityUtils:
    @staticmethod
    def secure_wipe(string: str) -> None:
        """
        Securely wipe a string from memory
        Note: This is best-effort due to Python's memory management
        """
        length = len(string)
        for i in range(length):
            string = string.replace(string[i], '\x00')
        return None

    @staticmethod
    def is_password_strong(password: str) -> Tuple[bool, str]:
        """
        Check if a password meets security requirements
        Returns (is_strong, message)
        """
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
            
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
            
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
            
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
            
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Password must contain at least one special character"
            
        return True, "Password meets security requirements"

    @staticmethod
    def generate_session_id() -> str:
        """Generate a secure session ID"""
        return base64.urlsafe_b64encode(os.urandom(32)).decode()

    @staticmethod
    def constant_time_compare(val1: bytes, val2: bytes) -> bool:
        """Constant-time comparison of two byte strings"""
        if len(val1) != len(val2):
            return False
        result = 0
        for x, y in zip(val1, val2):
            result |= x ^ y
        return result == 0