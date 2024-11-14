from binascii import hexlify
from ciphers.custom_aes.aes import AES as Custom_AES
from modules.utils.constants import *
from modules.utils.utils import *
import hashlib
import time

class Decrypt():

    def __init__(self, unprocessed_key, unprocessed_skey, time, debug):

        # Generate 128-bit digests for the keys
        self.key = hashlib.shake_128(unprocessed_key).digest(16)
        
        if unprocessed_skey:
            self.skey = hashlib.shake_128(unprocessed_skey).digest(16)

        self.round_key_offset = 0
        self.mix_columns_offset = 0

        self.shuffle_key_number = 0

        self.shuffle_round = 0

        # Initialization of shuffled sbox and respective inverse
        self.s_box_shuffled = []
        self.inverse_s_box_shuffled = create_inv_s_box_shuffled()

        self.time = time
        self.debug = debug

        self.aes = Custom_AES(self.key, self.skey, self.time, self.debug) if unprocessed_skey else Custom_AES(self.key, None, self.time, self.debug)

    def aes_decrypt(self, ciphertext):
        # Step 1: Ensure ciphertext length is a multiple of 16
        ciphertext = ciphertext[:len(ciphertext) - len(ciphertext) % 16]

        start = time.time_ns()

        # Step 2: Decrypt each 16-byte block of the ciphertext
        plaintext_blocks = []
        j = 0
        for i in range(0, len(ciphertext), 16):
            debug_print(f"\nDEC BLOCO {j}\n", self.debug)
            block = ciphertext[i:i+16]  # Get a 16-byte block
            plain_block = self.aes.decryption_block(block)  # Implement decryption block
            j+=1
            # Check if this is the last block, and if so, remove padding
            if i + 16 == len(ciphertext):
                plain_block = unpad_pkcs7(plain_block)

            plaintext_blocks.append(plain_block)

        elapsed_time = time.time_ns() - start

        # Combine all plaintext blocks into the final plaintext
        plaintext = b''.join(plaintext_blocks)

        return plaintext, elapsed_time

    def saes_decrypt(self, ciphertext):

         # Step 1: Ensure ciphertext length is a multiple of 16
        ciphertext = ciphertext[:len(ciphertext) - len(ciphertext) % 16]

        # Initialize plaintext storage
        plaintext_blocks = []

        start = time.time_ns()

        # Decrypt each 16-byte block of the ciphertext
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            plain_block = self.aes.saes_decryption_block(block)
            plaintext_blocks.append(plain_block)

        elapsed_time = time.time_ns() - start

        debug_print("\n===============================================================\n", self.debug)
        
        for plaintext_block in plaintext_blocks:
            debug_print("saes_decrypt block " + hexlify(plaintext_block).decode("utf-8"), self.debug)
        
        debug_print("\n===============================================================\n", self.debug)
        # Combine all decrypted blocks and remove padding
        padded_plaintext = b''.join(plaintext_blocks)
        plaintext = unpad_pkcs7(padded_plaintext)
        debug_print(f"plaintext: {plaintext}", self.debug)
        return plaintext, elapsed_time
