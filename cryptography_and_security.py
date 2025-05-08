import string
import random
import math
from collections import Counter
from itertools import cycle

# =======================
# 1. Hamming Code (Error Correction)
# =======================
def hamming_encode(data):
    """Encode data using Hamming(7,4) code"""
    assert len(data) == 4, "Data length must be 4"
    
    # Redundant bits: r
    r1 = (int(data[0]) + int(data[1]) + int(data[3])) % 2
    r2 = (int(data[0]) + int(data[2]) + int(data[3])) % 2
    r3 = (int(data[1]) + int(data[2]) + int(data[3])) % 2

    # Encoded data: 7 bits
    encoded_data = [str(r1), str(r2), data[0], str(r3), data[1], data[2], data[3]]
    return ''.join(encoded_data)

def hamming_decode(data):
    """Decode Hamming(7,4) code and correct if necessary"""
    assert len(data) == 7, "Encoded data must be 7 bits"
    
    # Parity checks
    r1_check = (int(data[0]) + int(data[2]) + int(data[4]) + int(data[6])) % 2
    r2_check = (int(data[1]) + int(data[2]) + int(data[5]) + int(data[6])) % 2
    r3_check = (int(data[3]) + int(data[4]) + int(data[5]) + int(data[6])) % 2

    # Error detection
    error_position = r1_check * 1 + r2_check * 2 + r3_check * 4
    if error_position:
        print(f"Error detected at position {error_position}")
        data = list(data)
        data[error_position - 1] = '1' if data[error_position - 1] == '0' else '0'
        data = ''.join(data)
    else:
        print("No error detected")
    
    # Return the original data (excluding parity bits)
    return data[2], data[4], data[5], data[6]

# =======================
# 2. Parity Check (Error Detection)
# =======================
def parity_check(data):
    """Perform even parity check"""
    ones_count = data.count('1')
    return ones_count % 2 == 0  # True if even parity

# =======================
# 3. Caesar Cipher Substitution
# =======================
def caesar_cipher(text, shift):
    """Encrypt text using Caesar Cipher"""
    result = ''
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

# =======================
# 4. Monoalphabetic Cipher Substitution
# =======================
def monoalphabetic_substitution(text, key):
    """Encrypt text using Monoalphabetic Substitution Cipher"""
    alphabet = string.ascii_lowercase
    cipher_dict = {alphabet[i]: key[i] for i in range(26)}
    
    return ''.join([cipher_dict.get(char, char) for char in text.lower()])

# =======================
# 5. Polyalphabetic Cipher Substitution
# =======================
def polyalphabetic_substitution(text, key):
    """Encrypt text using Polyalphabetic Substitution Cipher (Vigenère)"""
    result = []
    key = key.lower()
    key_len = len(key)
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % key_len]) - 97
            result.append(chr(((ord(char.lower()) - 97 + shift) % 26) + 97))
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)

# =======================
# 6. Playfair Cipher
# =======================
def playfair_encrypt(text, key):
    """Encrypt text using Playfair Cipher"""
    key = key.lower().replace("j", "i")
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    table = []
    for char in key + alphabet:
        if char not in table:
            table.append(char)
    
    # Prepare the text (pair the letters)
    text = text.lower().replace("j", "i")
    pairs = []
    i = 0
    while i < len(text):
        if i + 1 < len(text) and text[i] != text[i+1]:
            pairs.append(text[i:i+2])
            i += 2
        else:
            pairs.append(text[i] + "x")
            i += 1

    # Encrypt each pair
    cipher_text = ''
    for pair in pairs:
        row1, col1 = divmod(table.index(pair[0]), 5)
        row2, col2 = divmod(table.index(pair[1]), 5)
        
        if row1 == row2:
            cipher_text += table[row1*5 + (col1 + 1) % 5]
            cipher_text += table[row2*5 + (col2 + 1) % 5]
        elif col1 == col2:
            cipher_text += table[((row1 + 1) % 5)*5 + col1]
            cipher_text += table[((row2 + 1) % 5)*5 + col2]
        else:
            cipher_text += table[row1*5 + col2]
            cipher_text += table[row2*5 + col1]
    
    return cipher_text.upper()

# =======================
# 7. Hill Cipher Substitution
# =======================
def hill_cipher(text, key_matrix):
    """Encrypt text using Hill Cipher"""
    n = len(key_matrix)
    text = text.replace(" ", "").lower()
    text_matrix = [ord(char) - 97 for char in text]
    
    # Pad the text to fit the matrix size
    if len(text_matrix) % n != 0:
        text_matrix += [0] * (n - len(text_matrix) % n)

    cipher_matrix = []
    for i in range(0, len(text_matrix), n):
        block = text_matrix[i:i+n]
        cipher_block = [(sum(block[j] * key_matrix[j][k] for j in range(n)) % 26) for k in range(n)]
        cipher_matrix.extend(cipher_block)

    cipher_text = ''.join([chr(c + 97) for c in cipher_matrix])
    return cipher_text.upper()

# =======================
# 8. Rail Fence Cipher Transposition
# =======================
def rail_fence_cipher(text, rails):
    """Encrypt text using Rail Fence Cipher"""
    fence = [['' for _ in range(len(text))] for _ in range(rails)]
    rail, direction = 0, 1

    for i in range(len(text)):
        fence[rail][i] = text[i]
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction = -direction

    return ''.join([fence[r][i] for r in range(rails) for i in range(len(text)) if fence[r][i] != ''])

# =======================
# 9. Row Transposition Cipher
# =======================
def row_transposition_cipher(text, key):
    """Encrypt text using Row Transposition Cipher"""
    while len(text) % len(key) != 0:
        text += ' '  # Padding with spaces
    
    # Create matrix based on key length
    matrix = [text[i:i + len(key)] for i in range(0, len(text), len(key))]
    transposed = [''.join([row[i] for row in matrix]) for i in sorted(range(len(key)), key=lambda x: key[x])]
    
    return ''.join(transposed)

# =======================
# 10. Ciphertext-only and Known-plaintext Attacks
# =======================
def ciphertext_attack(ciphertext, cipher_type, key_guess=None):
    """Simulate a ciphertext-only or known-plaintext attack"""
    print(f"Attempting {cipher_type} attack on ciphertext: {ciphertext}")
    if cipher_type == 'Ciphertext-only':
        print("Ciphertext-only attack failed: Cannot decrypt without key.")
    elif cipher_type == 'Known-plaintext':
        print(f"Attempting to use known key guess: {key_guess}")
        # Placeholder for real decryption (e.g., Caesar cipher)
        if key_guess:
            return caesar_cipher(ciphertext, key_guess)  # Assume it's Caesar for simplicity
    return None

# =======================
# 11. Stream Cipher
# =======================
def stream_cipher(text, key_stream):
    """Encrypt text using Stream Cipher (XOR operation)"""
    cipher_text = ''.join([chr(ord(t) ^ ord(k)) for t, k in zip(text, key_stream)])
    return cipher_text

# =======================
# 12. RSA Algorithm (Asymmetric Encryption)
# =======================
def generate_rsa_keys():
    """Generate RSA keys (public, private)"""
    p = 61  # prime number
    q = 53  # prime number
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    e = 17  # public exponent
    d = pow(e, -1, phi_n)  # private exponent
    
    public_key = (e, n)
    private_key = (d, n)
    
    return public_key, private_key

def rsa_encrypt(plain_text, public_key):
    """Encrypt plain text using RSA"""
    e, n = public_key
    cipher_text = [pow(ord(char), e, n) for char in plain_text]
    return cipher_text

def rsa_decrypt(cipher_text, private_key):
    """Decrypt cipher text using RSA"""
    d, n = private_key
    plain_text = ''.join([chr(pow(char, d, n)) for char in cipher_text])
    return plain_text

# =======================
# 13. Diffie-Hellman Key Exchange
# =======================
def diffie_hellman_key_exchange():
    """Simulate Diffie-Hellman Key Exchange"""
    p = 23  # Prime number
    g = 5   # Generator
    
    # Alice's private key
    a = random.randint(1, p-1)
    A = pow(g, a, p)  # Alice's public key

    # Bob's private key
    b = random.randint(1, p-1)
    B = pow(g, b, p)  # Bob's public key

    # Compute shared secret
    shared_secret_alice = pow(B, a, p)  # Alice computes the shared secret
    shared_secret_bob = pow(A, b, p)    # Bob computes the shared secret
    
    return shared_secret_alice, shared_secret_bob

# =======================
# 14. Man-in-the-middle Attack (Diffie-Hellman)
# =======================
def man_in_the_middle_attack():
    """Simulate a Man-in-the-middle attack on Diffie-Hellman Key Exchange"""
    p = 23  # Prime number
    g = 5   # Generator
    
    # Attacker intercepts and modifies public keys
    A = 8   # Fake Alice's public key (attacker intercepts)
    B = 15  # Fake Bob's public key (attacker intercepts)
    
    # Attacker's private key
    x = random.randint(1, p-1)
    y = random.randint(1, p-1)
    
    shared_secret_alice = pow(B, x, p)  # Attacker computes Alice's shared secret
    shared_secret_bob = pow(A, y, p)    # Attacker computes Bob's shared secret
    
    return shared_secret_alice, shared_secret_bob

# =======================
# 15. Digital Signature using RSA
# =======================
def digital_signature(message, private_key):
    """Generate a digital signature using RSA"""
    d, n = private_key
    signature = [pow(ord(char), d, n) for char in message]
    return signature

def verify_signature(signature, public_key):
    """Verify the digital signature using RSA public key"""
    e, n = public_key
    return ''.join([chr(pow(char, e, n)) for char in signature])

# Main code entry point for testing the functions:
if __name__ == "__main__":
    # Example of using RSA
    public_key, private_key = generate_rsa_keys()
    encrypted_text = rsa_encrypt("Hello World", public_key)
    decrypted_text = rsa_decrypt(encrypted_text, private_key)
    print("Encrypted text (RSA):", encrypted_text)
    print("Decrypted text (RSA):", decrypted_text)
    
    # Example of using Caesar Cipher
    caesar_encrypted = caesar_cipher("Hello", 3)
    print("Caesar Cipher Encrypted:", caesar_encrypted)
    
    # Example of Diffie-Hellman
    shared_secret_alice, shared_secret_bob = diffie_hellman_key_exchange()
    print("Shared Secret Alice:", shared_secret_alice)
    print("Shared Secret Bob:", shared_secret_bob)
