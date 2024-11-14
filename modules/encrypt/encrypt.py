from binascii import hexlify
from modules.utils.constants import *
from modules.utils.utils import *

from ciphers.custom_aes.aes import AES as Custom_AES
from ciphers.crypto_aes.aes import StandardAES
import hashlib

import time

class Encrypt:

    def __init__(self, plaintext, unprocessed_key, unprocessed_skey, time, debug):

        self.plaintext = plaintext

        # Generate 128-bit digests for the keys
        self.key = hashlib.shake_128(unprocessed_key).digest(16)

        if unprocessed_skey:
            self.skey = hashlib.shake_128(unprocessed_skey).digest(16)

        self.time = time
        self.debug = debug

        self.aes = Custom_AES(self.key, self.skey, self.time, self.debug) if unprocessed_skey else Custom_AES(self.key, None, self.time, self.debug)

        # Initialization of shuffled sbox and respective inverse
        self.s_box_shuffled = []
        self.inverse_s_box_shuffled = create_inv_s_box_shuffled()

    def aes_encrypt(self):
        j = 0
        # Step 1: Pad the plaintext to ensure it's a multiple of 16 bytes
        padded_plaintext = pad_pkcs7(self.plaintext)
        # padded_plaintext = plaintext

        start = time.time_ns()

        # Step 2: Encrypt each 16-byte block of the padded plaintext
        ciphertext_blocks = []
        for i in range(0, len(padded_plaintext), 16):
            # print(f"\nENC BLOCO {j}\n")
            block = padded_plaintext[i:i+16]  # Get a 16-byte block
            cipher_block = self.aes.encryption_block(block)
            ciphertext_blocks.append(cipher_block)
            j+=1

        elapsed_time = time.time_ns() - start

        # Combine all ciphertext blocks into the final ciphertext
        ciphertext = b''.join(ciphertext_blocks)
        return ciphertext, elapsed_time

    def saes_encrypt(self):

        # Step 1: Pad the plaintext to ensure it's a multiple of 16 bytes
        padded_plaintext = pad_pkcs7(self.plaintext)
        # self.skey = text2matrix(self.key)

        # Initialize ciphertext storage
        ciphertext_blocks = []

        if self.skey:
            self.shuffle_key_number = random_shuffle_number(self.skey)

            # Get a random shuffle round and initialize other variables
            self.shuffle_round = int((self.shuffle_key_number % 9) + 1)
            # debug_print(f"self.shuffle_round: {self.shuffle_round}", self.debug)
            ss_box = SUBSTITUTION_BOX.copy()
            self.s_box_shuffled = shuffle_sbox(ss_box, self.shuffle_key_number)
            calculate_inverse_matrix(self.inverse_s_box_shuffled, self.s_box_shuffled)

            
            self.round_key_offset = int(self.shuffle_key_number % 16)
            self.mix_columns_offset = int(self.shuffle_key_number % 4)
            self.skey = text2matrix(self.skey)

            start = time.time_ns()

            # Encrypt each 16-byte block of the padded plaintext
            for i in range(0, len(padded_plaintext), 16):
                block = padded_plaintext[i:i+16]  # Get a 16-byte block
                cipher_block = self.aes.saes_encryption_block(block)
                ciphertext_blocks.append(cipher_block)

            elapsed_time = time.time_ns() - start

        debug_print("\n===============================================================\n", self.debug)
        
        for ct_block in ciphertext_blocks:
            debug_print(f"saes_encrypt block {hexlify(ct_block).decode('utf-8')}", self.debug)
        
        debug_print("\n===============================================================\n", self.debug)

        # Combine all ciphertext blocks into the final ciphertext
        ciphertext = b''.join(ciphertext_blocks)
        return ciphertext, elapsed_time