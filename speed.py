from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from AES import AES as Custom_AES
import time
import hashlib

class StandardAES:
    def __init__(self, key):
        self.k = hashlib.sha256(key).digest()[:16]  # Use only 16 bytes for AES-128

    def encrypt(self, raw):
        # Pad plaintext, initialize AES cipher, encrypt, and return hex-encoded ciphertext
        raw = pad(raw.encode('utf8'), AES.block_size)
        cipher = AES.new(self.k, AES.MODE_ECB)
        encrypted_bytes = cipher.encrypt(raw)
        return encrypted_bytes.hex()

    def decrypt(self, enc):
        # Decode hex to bytes, decrypt, unpad, and return plaintext as string
        enc = bytes.fromhex(enc)
        cipher = AES.new(self.k, AES.MODE_ECB)
        decrypted_bytes = unpad(cipher.decrypt(enc), AES.block_size)
        return decrypted_bytes.hex()

def run_aes_implementations(plaintext, key, skey=None, method="aes", timeopt=False):

    # TODO: (Maybe o melhor é adicionar questões da contagem do empo dentro das funcoes em especifico, e não fora)
    
    plaintext_bytes = bytes.fromhex(plaintext)

    if timeopt:
        start_time = time.time()
    
    if method == "aes":
    
        aes_custom = Custom_AES(key)
        ciphertext_custom = aes_custom.aes_encrypt(plaintext_bytes)
        ciphertext_custom = ciphertext_custom.hex()

        decrypted_custom = aes_custom.aes_decrypt(ciphertext_custom)
        decrypted_custom = decrypted_custom.hex()
        
        if timeopt:
            print("Custom AES Encryption Time:")
            # start_time = time.time()

        print("Custom AES Ciphertext:", ciphertext_custom)
        print("Custom AES Decrypted Plaintext:", decrypted_custom)

    elif method == "daes":
        aes_standard = StandardAES(key)
        ciphertext_standard = aes_standard.encrypt(plaintext)
        decrypted_standard = aes_standard.decrypt(ciphertext_standard)

        if timeopt:
            print("Standard AES Encryption Time:")

        print("Standard AES Ciphertext:", ciphertext_standard)
        print("Standard AES Decrypted Plaintext:", decrypted_standard)

    elif method == "saes":
        if skey is None:
            raise ValueError("Shuffle key (skey) is required for Shuffled AES (saes)")

        # TODO: Missing tests for saes

        # saes = Custom_AES(key)
        
        # saes_ciphertext = saes.aes_encrypt(plaintext_bytes)
        # saes_ciphertext = saes_ciphertext.hex()

        # saes_decrypted = saes.aes_decrypt(saes_ciphertext)
        # saes_decrypted = saes_decrypted.hex()

        if timeopt:
            print("Shuffled AES Encryption Time:")
        
        # print("Shuffled AES Ciphertext:", saes_ciphertext)
        # print("Shuffled AES Decrypted Plaintext:", saes_decrypted)