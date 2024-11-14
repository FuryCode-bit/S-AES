from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time

class StandardAES:
    def __init__(self, key):
        self.k = key  # Use only 16 bytes for AES-128

    def encrypt(self, plaintext_bytes):
        """
        Encrypts the plaintext bytes using AES-128 ECB mode, returning the ciphertext and time taken in ns.
        """
        plaintext_padded = pad(plaintext_bytes, AES.block_size)  # Pad to match AES block size
        cipher = AES.new(self.k, AES.MODE_ECB)
        
        start_time = time.time()
        # print("\nstart: ", start_time)
        ciphertext = cipher.encrypt(plaintext_padded)
        enc_time_ns = time.time_ns() - start_time  # Time taken for encryption in ns
        # print("end: ", enc_time_ns)

        # print("enc_time_ns: ", enc_time_ns)

        return ciphertext, int(enc_time_ns/1e10)

    def decrypt(self, ciphertext_bytes):
        """
        Decrypts the ciphertext bytes using AES-128 ECB mode, returning the plaintext and time taken in ns.
        """
        cipher = AES.new(self.k, AES.MODE_ECB)
        
        start_time = time.time()
        # print("start_time: ", start_time)
        plaintext_padded = cipher.decrypt(ciphertext_bytes)
        dec_time_ns = time.time_ns() - start_time
        # print("dec_time_ns: ", dec_time_ns)

        plaintext = unpad(plaintext_padded, AES.block_size)  # Remove padding

        return plaintext, int(dec_time_ns/1e10)