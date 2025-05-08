# Cryptography: Encryption, Decryption, Substitution and Transposition, Confusion and diffusion, Symmetric and Asymmetric encryption, Stream and Block ciphers, DES, cryptanalysis

import numpy as np
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random
import string


# 1. Substitution Cipher (Caesar Cipher)
def caesar_cipher(text, shift):
    """Encrypt or decrypt using Caesar Cipher"""
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char  # Non-alphabetic characters are unchanged
    return result

# 2. Transposition Cipher (Simple Columnar Transposition)
def columnar_transposition_encrypt(text, key):
    """Encrypt using Columnar Transposition Cipher"""
    num_cols = len(key)
    num_rows = len(text) // num_cols + (1 if len(text) % num_cols != 0 else 0)
    grid = ['' for _ in range(num_cols)]
    
    for i, char in enumerate(text):
        grid[i % num_cols] += char

    # Sort grid based on key order
    ordered_grid = ['' for _ in range(num_cols)]
    for i, k in enumerate(sorted(range(num_cols), key=lambda x: key[x])):
        ordered_grid[k] = grid[i]

    return ''.join(ordered_grid)

def columnar_transposition_decrypt(text, key):
    """Decrypt using Columnar Transposition Cipher"""
    num_cols = len(key)
    num_rows = len(text) // num_cols
    grid = ['' for _ in range(num_cols)]

    for i, char in enumerate(text):
        grid[i % num_cols] += char

    # Rebuild the message using the key
    ordered_grid = ['' for _ in range(num_cols)]
    for i, k in enumerate(sorted(range(num_cols), key=lambda x: key[x])):
        ordered_grid[k] = grid[i]

    return ''.join(ordered_grid)

# 3. Symmetric Encryption (AES Example)
def aes_encrypt(plain_text, key):
    """Encrypt a plaintext message using AES (Advanced Encryption Standard)"""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return cipher.iv + ct_bytes  # Return IV + ciphertext

def aes_decrypt(cipher_text, key):
    """Decrypt a ciphertext message using AES"""
    iv = cipher_text[:16]
    ct = cipher_text[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_text = unpad(cipher.decrypt(ct), AES.block_size).decode()
    return decrypted_text

# 4. Asymmetric Encryption (RSA Example)
def rsa_encrypt(public_key, plaintext):
    """Encrypt a message using RSA public key"""
    return public_key.encrypt(plaintext.encode(), 32)[0]

def rsa_decrypt(private_key, ciphertext):
    """Decrypt a message using RSA private key"""
    return private_key.decrypt(ciphertext).decode()

# 5. DES (Data Encryption Standard)
def des_encrypt(plain_text, key):
    """Encrypt using DES (Data Encryption Standard)"""
    from Crypto.Cipher import DES
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(plain_text.encode(), DES.block_size))

def des_decrypt(cipher_text, key):
    """Decrypt using DES (Data Encryption Standard)"""
    from Crypto.Cipher import DES
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(cipher_text), DES.block_size).decode()

# 6. Stream Cipher (XOR based Stream Cipher Example)
def xor_stream_cipher_encrypt_decrypt(text, key):
    """Encrypt or decrypt a text using XOR Stream Cipher"""
    result = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(text, key))
    return result

# 7. Cryptanalysis (Brute-force attack on Caesar Cipher)
def brute_force_caesar_cipher(ciphertext):
    """Brute force attack to decrypt Caesar cipher"""
    possibilities = []
    for shift in range(26):
        possibilities.append((shift, caesar_cipher(ciphertext, -shift)))
    return possibilities

# Main example to demonstrate all the above ciphers
if __name__ == "__main__":

    # 1. Substitution (Caesar Cipher)
    print("=== Caesar Cipher ===")
    original_text = "Hello World!"
    caesar_encrypted = caesar_cipher(original_text, 3)  # Encrypt with a shift of 3
    print(f"Encrypted: {caesar_encrypted}")
    caesar_decrypted = caesar_cipher(caesar_encrypted, -3)  # Decrypt with a shift of -3
    print(f"Decrypted: {caesar_decrypted}\n")

    # 2. Transposition (Columnar Transposition Cipher)
    print("=== Columnar Transposition Cipher ===")
    key = [2, 0, 1]  # Columnar key [2, 0, 1]
    transposition_encrypted = columnar_transposition_encrypt(original_text, key)
    print(f"Encrypted: {transposition_encrypted}")
    transposition_decrypted = columnar_transposition_decrypt(transposition_encrypted, key)
    print(f"Decrypted: {transposition_decrypted}\n")

    # 3. Symmetric Encryption (AES)
    print("=== AES Encryption ===")
    aes_key = get_random_bytes(16)  # 16 bytes for AES-128
    aes_encrypted = aes_encrypt(original_text, aes_key)
    print(f"Encrypted: {aes_encrypted.hex()}")
    aes_decrypted = aes_decrypt(aes_encrypted, aes_key)
    print(f"Decrypted: {aes_decrypted}\n")

    # 4. Asymmetric Encryption (RSA)
    print("=== RSA Encryption ===")
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey()
    private_key = rsa_key
    rsa_encrypted = rsa_encrypt(public_key, original_text)
    print(f"Encrypted: {rsa_encrypted.hex()}")
    rsa_decrypted = rsa_decrypt(private_key, rsa_encrypted)
    print(f"Decrypted: {rsa_decrypted}\n")

    # 5. DES Encryption
    print("=== DES Encryption ===")
    des_key = get_random_bytes(8)  # DES requires 8-byte key
    des_encrypted = des_encrypt(original_text, des_key)
    print(f"Encrypted: {des_encrypted.hex()}")
    des_decrypted = des_decrypt(des_encrypted, des_key)
    print(f"Decrypted: {des_decrypted}\n")

    # 6. Stream Cipher (XOR)
    print("=== XOR Stream Cipher ===")
    xor_key = "mysecretkey"
    xor_encrypted = xor_stream_cipher_encrypt_decrypt(original_text, xor_key)
    print(f"Encrypted: {xor_encrypted}")
    xor_decrypted = xor_stream_cipher_encrypt_decrypt(xor_encrypted, xor_key)
    print(f"Decrypted: {xor_decrypted}\n")

    # 7. Cryptanalysis (Brute-force Caesar Cipher Attack)
    print("=== Cryptanalysis (Brute-force Caesar Cipher) ===")
    brute_force_results = brute_force_caesar_cipher(caesar_encrypted)
    for shift, result in brute_force_results:
        print(f"Shift {shift}: {result}")
