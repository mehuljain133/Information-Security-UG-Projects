# Error detecting/correction: Block Codes, Generator Matrix, Parity Check Matrix, Minimumdistance of a Code, Error detection and correction, Standard Array and syndrome decoding,Hamming Codes

import numpy as np

class ErrorDetectionCorrection:
    def __init__(self, n, k):
        """
        n: Length of codeword (including parity bits)
        k: Length of message (data bits)
        """
        self.n = n
        self.k = k
        self.G = None  # Generator Matrix
        self.H = None  # Parity Check Matrix

    # Step 1: Generate Generator Matrix for Block Code
    def generate_generator_matrix(self):
        """Generate a generator matrix for a systematic linear code"""
        I_k = np.eye(self.k, dtype=int)  # Identity matrix of size k
        P = np.random.randint(0, 2, (self.k, self.n - self.k), dtype=int)  # Random matrix for parity bits
        self.G = np.hstack((I_k, P))  # Combine to form generator matrix
        print(f"Generator Matrix (G):\n{self.G}\n")

    # Step 2: Generate Parity Check Matrix for Block Code
    def generate_parity_check_matrix(self):
        """Generate a parity check matrix based on the generator matrix"""
        P_T = self.G[:, self.k:].T  # Extract the parity part from G and transpose
        I_nk = np.eye(self.n - self.k, dtype=int)  # Identity matrix of size (n-k)
        self.H = np.hstack((P_T, I_nk))  # Combine to form parity check matrix
        print(f"Parity Check Matrix (H):\n{self.H}\n")

    # Step 3: Encode message using Generator Matrix (Block Code)
    def encode_message(self, message):
        """Encode a message using the generator matrix"""
        if len(message) != self.k:
            raise ValueError(f"Message must have length {self.k}")
        message_vector = np.array(list(map(int, message)))  # Convert message to a binary vector
        codeword = np.dot(message_vector, self.G) % 2  # Matrix multiplication and modulo 2
        return ''.join(map(str, codeword.astype(int)))

    # Step 4: Calculate the Syndrome for Error Detection
    def calculate_syndrome(self, received_codeword):
        """Calculate syndrome using parity check matrix H"""
        received_vector = np.array(list(map(int, received_codeword)))  # Convert to binary vector
        syndrome = np.dot(received_vector, self.H.T) % 2  # Matrix multiplication and modulo 2
        return syndrome

    # Step 5: Detect Errors using Syndrome
    def detect_errors(self, syndrome):
        """Detect errors by checking if syndrome is non-zero"""
        return np.any(syndrome)

    # Step 6: Syndrome Decoding (Correct Errors)
    def syndrome_decoding(self, received_codeword):
        """Correct errors using syndrome decoding"""
        syndrome = self.calculate_syndrome(received_codeword)
        if np.any(syndrome):  # If syndrome is non-zero, there is an error
            print(f"Error detected. Syndrome: {syndrome}")
            error_position = self.get_error_position(syndrome)
            print(f"Error in position {error_position}")
            corrected_codeword = list(received_codeword)
            corrected_codeword[error_position] = '0' if corrected_codeword[error_position] == '1' else '1'  # Flip the bit
            return ''.join(corrected_codeword)
        return received_codeword  # No error

    # Step 7: Get Error Position from Syndrome
    def get_error_position(self, syndrome):
        """Find the position of the error based on the syndrome"""
        # Syndrome matches the column index of H to identify the error position
        syndrome_str = ''.join(map(str, syndrome.astype(int)))
        for i in range(self.n):
            if syndrome_str == ''.join(map(str, self.H[:, i].astype(int))):
                return i
        return -1  # No error

    # Step 8: Hamming Code (Specific Case of Error Correction)
    def hamming_code(self, message):
        """Encode and decode using Hamming code for error correction"""
        # Hamming(7,4) code (n=7, k=4), example for a (7,4) Hamming code
        if len(message) != 4:
            raise ValueError("For Hamming code, message length must be 4 bits.")
        # Parity bit positions (for (7,4) Hamming Code)
        parity_positions = [0, 1, 3]
        message_bits = list(map(int, message))
        codeword = [None] * 7

        # Fill in the message bits into the codeword
        codeword[2] = message_bits[0]
        codeword[4] = message_bits[1]
        codeword[5] = message_bits[2]
        codeword[6] = message_bits[3]

        # Calculate parity bits (for (7,4) Hamming Code)
        for i in range(3):
            parity_bit = 0
            for j in range(7):
                if (j + 1) & (2 ** i):  # Check if bit position includes current parity bit position
                    parity_bit ^= codeword[j] if codeword[j] is not None else 0
            codeword[parity_positions[i]] = parity_bit

        print(f"Hamming Codeword: {''.join(map(str, codeword))}")
        return ''.join(map(str, codeword))

# Example Usage

if __name__ == "__main__":
    # Initialize Error Detection and Correction System for a (7,4) Code
    edc = ErrorDetectionCorrection(7, 4)
    edc.generate_generator_matrix()
    edc.generate_parity_check_matrix()

    # Encode a message
    message = "1011"
    encoded_message = edc.encode_message(message)
    print(f"Encoded Message: {encoded_message}\n")

    # Simulate an error in the encoded message (flip one bit)
    received_message = list(encoded_message)
    received_message[3] = '0' if received_message[3] == '1' else '1'  # Flip one bit
    received_message = ''.join(received_message)

    print(f"Received Message with Error: {received_message}")
    
    # Correct the received message
    corrected_message = edc.syndrome_decoding(received_message)
    print(f"Corrected Message: {corrected_message}\n")

    # Demonstrating Hamming Code (7,4)
    hamming_codeword = edc.hamming_code("1011")
