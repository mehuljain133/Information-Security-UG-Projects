# Cryptography: Encryption, Decryption, Substitution and Transposition, Confusion and diffusion, Symmetric and Asymmetric encryption, Stream and Block ciphers, DES, cryptanalysis

import numpy as np
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
import random
import string
from PIL import Image
import io
import base64


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
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(plain_text.encode(), DES.block_size))

def des_decrypt(cipher_text, key):
    """Decrypt using DES (Data Encryption Standard)"""
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

# 8. Public-key Cryptography (RSA Encryption)
def generate_rsa_keys():
    """Generate RSA public and private keys"""
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

# 9. Diffie-Hellman Key Exchange (Simple Example)
def diffie_hellman():
    """Simulate Diffie-Hellman key exchange"""
    p = 23  # Prime number
    g = 5   # Generator
    a_private = random.randint(1, p-1)  # Alice's private key
    b_private = random.randint(1, p-1)  # Bob's private key

    # Alice computes public key
    a_public = pow(g, a_private, p)
    # Bob computes public key
    b_public = pow(g, b_private, p)

    # Alice computes shared secret
    shared_secret_a = pow(b_public, a_private, p)
    # Bob computes shared secret
    shared_secret_b = pow(a_public, b_private, p)

    return shared_secret_a, shared_secret_b

# 10. Man-in-the-Middle Attack (Simple Attack Simulation)
def man_in_the_middle_attack():
    """Simulate a simple Man-in-the-Middle attack"""
    p = 23  # Prime number
    g = 5   # Generator
    a_private = random.randint(1, p-1)
    b_private = random.randint(1, p-1)

    # Alice and Bob exchange keys with Eve (attacker)
    a_public = pow(g, a_private, p)
    b_public = pow(g, b_private, p)
    eves_private = random.randint(1, p-1)  # Eve intercepts and modifies

    # Eve sends different public keys
    eves_public = pow(g, eves_private, p)
    alice_shared = pow(eves_public, a_private, p)
    bob_shared = pow(eves_public, b_private, p)

    return alice_shared, bob_shared

# 11. Digital Signature (RSA-based)
def rsa_sign(private_key, message):
    """Generate a digital signature"""
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def rsa_verify(public_key, message, signature):
    """Verify the digital signature"""
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# 12. Steganography (Hiding text in an image)
def hide_text_in_image(image_path, secret_text):
    """Hide secret text in an image using least significant bit method"""
    image = Image.open(image_path)
    binary_text = ''.join(format(ord(c), '08b') for c in secret_text)
    pixels = image.load()
    width, height = image.size
    data_index = 0

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            if data_index < len(binary_text):
                r = r & 0xFE | int(binary_text[data_index])
                data_index += 1
            if data_index < len(binary_text):
                g = g & 0xFE | int(binary_text[data_index])
                data_index += 1
            if data_index < len(binary_text):
                b = b & 0xFE | int(binary_text[data_index])
                data_index += 1
            pixels[x, y] = (r, g, b)
            if data_index >= len(binary_text):
                break
    image.save("steganography_output.png")

def extract_text_from_image(image_path):
    """Extract hidden text from an image"""
    image = Image.open(image_path)
    binary_text = ""
    pixels = image.load()
    width, height = image.size

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_text += str(r & 1)
            binary_text += str(g & 1)
            binary_text += str(b & 1)

    binary_text = binary_text[:len(binary_text) // 8 * 8]
    extracted_text = ''.join(chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8))
    return extracted_text

# 13. Watermarking (Image-based)
def add_watermark(image_path, watermark_text):
    """Add watermark text to an image"""
    image = Image.open(image_path)
    pixels = image.load()
    width, height = image.size

    for x in range(10, 100, 10):
        for y in range(10, 100, 10):
            r, g, b = pixels[x, y]
            pixels[x, y] = (r, g, b)

    image.save("watermarked_image.png")


# Example usage to demonstrate the functionalities

if __name__ == "__main__":
    original_text = "This is a secret message!"

    # Caesar Cipher
    caesar_encrypted = caesar_cipher(original_text, 3)
    print(f"Caesar Encrypted: {caesar_encrypted}")

    # Columnar Transposition Cipher
    transposition_encrypted = columnar_transposition_encrypt(original_text, [2, 0, 1])
    print(f"Transposition Encrypted: {transposition_encrypted}")

    # AES Encryption
    aes_key = get_random_bytes(16)
    aes_encrypted = aes_encrypt(original_text, aes_key)
    aes_decrypted = aes_decrypt(aes_encrypted, aes_key)
    print(f"AES Decrypted: {aes_decrypted}")

    # RSA Encryption/Decryption
    public_key, private_key = generate_rsa_keys()
    rsa_encrypted = rsa_encrypt(public_key, original_text)
    rsa_decrypted = rsa_decrypt(private_key, rsa_encrypted)
    print(f"RSA Decrypted: {rsa_decrypted}")

    # Diffie-Hellman Key Exchange
    shared_secret_a, shared_secret_b = diffie_hellman()
    print(f"Shared secrets: {shared_secret_a}, {shared_secret_b}")

    # Digital Signature
    signature = rsa_sign(private_key, original_text)
    is_verified = rsa_verify(public_key, original_text, signature)
    print(f"Digital Signature Verified: {is_verified}")
