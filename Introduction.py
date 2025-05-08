# Introduction: Security Concepts, Challenges, Security architecture, Security attacks, security services, security mechanisms

import hashlib
import os
from cryptography.fernet import Fernet

# Security Concepts: Encryption, Hashing, and Authentication
class Security:
    def __init__(self):
        # Key for symmetric encryption
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    # Hashing function to demonstrate integrity check
    def hash_data(self, data: str):
        return hashlib.sha256(data.encode()).hexdigest()

    # Symmetric encryption for confidentiality
    def encrypt_data(self, data: str):
        return self.cipher_suite.encrypt(data.encode())

    def decrypt_data(self, encrypted_data: bytes):
        return self.cipher_suite.decrypt(encrypted_data).decode()

    # Example of authentication (token-based)
    def authenticate_user(self, username: str, password: str):
        # Hardcoded credentials for demonstration purposes
        stored_username = "admin"
        stored_password_hash = hashlib.sha256("password123".encode()).hexdigest()

        if username == stored_username and self.hash_data(password) == stored_password_hash:
            return "Authentication successful"
        else:
            return "Authentication failed"

# Security Attacks: Basic Brute Force
class SecurityAttack:
    def brute_force_attack(self, password: str, possible_passwords: list):
        print("Starting brute-force attack...")
        for possible in possible_passwords:
            if possible == password:
                return f"Password found: {possible}"
        return "Password not found"

# Security Services: Authentication and Integrity
class SecurityService:
    def __init__(self):
        self.security = Security()

    def authenticate_and_hash(self, username: str, password: str, data: str):
        auth_result = self.security.authenticate_user(username, password)
        if "successful" in auth_result:
            hashed_data = self.security.hash_data(data)
            return f"{auth_result} | Data Hash: {hashed_data}"
        return auth_result

# Main code to demonstrate the system
if __name__ == "__main__":
    # Create security system object
    security_system = SecurityService()

    # Step 1: Demonstrate user authentication and hashing
    username_input = "admin"
    password_input = "password123"
    sensitive_data = "Top Secret Data"

    auth_result = security_system.authenticate_and_hash(username_input, password_input, sensitive_data)
    print(auth_result)

    # Step 2: Encrypt and decrypt data
    encrypted_data = security_system.security.encrypt_data(sensitive_data)
    print(f"Encrypted Data: {encrypted_data}")
    decrypted_data = security_system.security.decrypt_data(encrypted_data)
    print(f"Decrypted Data: {decrypted_data}")

    # Step 3: Brute force attack on password
    possible_passwords = ["12345", "password123", "admin123", "qwerty"]
    attack_system = SecurityAttack()
    attack_result = attack_system.brute_force_attack(password_input, possible_passwords)
    print(attack_result)
