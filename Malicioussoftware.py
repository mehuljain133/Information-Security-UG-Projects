# Malicious software’s: Types of malwares (viruses, worms, trojan horse, rootkits, bots), Memory exploits - Buffer overflow, Integer overflow

import random
import socket
import threading
import os
import time

# ==========================
# 1. Malicious Software Types
# ==========================

# Virus (Simulated)
def virus_simulation():
    """Simulate a virus by appending a virus to a text file (not harmful)"""
    file_path = "infected_file.txt"
    content = "This is a clean file."
    
    # Simulating infection: Adding a virus (malicious code) to the file.
    with open(file_path, "w") as file:
        file.write(content + "\n")
        file.write("Malicious Code: This file is infected!\n")

    print(f"File '{file_path}' has been infected with a virus!")

# Worm (Simulated)
def worm_simulation():
    """Simulate a worm by self-replicating and sending messages to networked machines"""
    # Simulate a worm by creating a message that replicates itself
    worm_message = "This is a worm message, replicating..."
    
    def send_worm():
        # Send the worm to a different machine in the network
        print(f"Sending worm message: {worm_message}")
    
    print("Worm started replicating...")
    # Simulating worm spreading
    for _ in range(3):  # Simulate 3 replications
        send_worm()
        time.sleep(1)

# Trojan Horse (Simulated)
def trojan_simulation():
    """Simulate a Trojan Horse by pretending to be a useful program but performing malicious actions"""
    print("Trojan Horse is installed, pretending to be a helpful program...")
    
    # Hidden malicious action (pretending to perform a task while secretly deleting files)
    action = input("Do you want to perform a useful task? (y/n): ")
    if action == 'y':
        print("Performing task...")
        time.sleep(2)
        print("Task completed! But the Trojan secretly deleted files.")
        os.remove("clean_file.txt")
    else:
        print("No task performed. Trojan remains inactive for now.")
    
    print("Trojan action is complete!")

# Rootkit (Simulated)
def rootkit_simulation():
    """Simulate rootkit functionality by hiding a file from the system"""
    file_name = "secret_file.txt"
    
    # Simulating the presence of a hidden file
    with open(file_name, "w") as file:
        file.write("This is a secret hidden file.")
    
    print(f"Rootkit hiding file: {file_name}")
    os.system(f"attrib +h {file_name}")  # Hide the file (simulated rootkit behavior)
    
    # Listing files (the hidden file shouldn't show up in the directory listing)
    print("Files in the directory (after rootkit is active):")
    os.system("dir")

# Bot (Simulated)
def bot_simulation():
    """Simulate a bot performing automated tasks or launching a DDoS attack"""
    bot_message = "Bot is executing automated tasks..."
    
    def send_bot_task():
        print(f"Bot sending task: {bot_message}")
    
    print("Bot is performing tasks...")
    for _ in range(5):  # Simulate bot tasks (not harmful)
        send_bot_task()
        time.sleep(1)

# ========================
# 2. Memory Exploits
# ========================

# Buffer Overflow (Simulated)
def buffer_overflow_simulation():
    """Simulate a buffer overflow vulnerability by overloading a small buffer"""
    buffer_size = 10
    user_input = input("Enter a string to overflow the buffer (max 10 chars): ")
    
    if len(user_input) > buffer_size:
        print("Buffer overflow detected! Too many characters!")
    else:
        print(f"Buffer content: {user_input}")

# Integer Overflow (Simulated)
def integer_overflow_simulation():
    """Simulate an integer overflow by adding large values together"""
    max_int_value = 2147483647  # Max for a 32-bit signed integer
    
    print("Simulating integer overflow... Adding large values together.")
    result = max_int_value + 1  # This will overflow the value
    print(f"Result after overflow: {result} (Expected: a wraparound behavior)")

# =========================
# Example of How These Work
# =========================

if __name__ == "__main__":
    # Simulate Virus
    virus_simulation()

    # Simulate Worm
    worm_simulation()

    # Simulate Trojan Horse
    trojan_simulation()

    # Simulate Rootkit
    rootkit_simulation()

    # Simulate Bot
    bot_simulation()

    # Simulate Buffer Overflow
    buffer_overflow_simulation()

    # Simulate Integer Overflow
    integer_overflow_simulation()
