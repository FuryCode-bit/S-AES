from binascii import hexlify
from modules.utils.constants import *
from modules.utils.utils import *

from ciphers.custom_aes.aes import AES as Custom_AES
from ciphers.crypto_aes.aes import StandardAES

import time

'''
Steps in AES encryption:

Addition of the first round key
9 Rounds:
    Substitute Bytes (S-Box)
    Shift Rows
    Mix Columns
    Adding the Round Key
The final round
    Substitute Bytes  (S-Box)
    Shift Rows
    Adding the Round Key
    
'''

class Encrypt:

    def __init__(self, plaintext, key, skey, time, debug):

        self.plaintext = plaintext
        self.key = key
        self.skey = skey
        self.time = time
        self.debug = debug

        self.aes = Custom_AES(self.key, self.skey, self.time, self.debug) if self.skey else Custom_AES(self.key, self.skey, self.time, self.debug)

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
            self.aes.shuffle_round = int((self.aes.shuffle_key_number % 9) + 1)
            print("self.shuffle_round: ", self.aes.shuffle_round)
            ss_box = SUBSTITUTION_BOX.copy()
            self.aes.s_box_shuffled = shuffle_sbox(ss_box, self.aes.shuffle_key_number)
            calculate_inverse_matrix(self.aes.inverse_s_box_shuffled, self.aes.s_box_shuffled)

            
            self.aes.round_key_offset = int(self.aes.shuffle_key_number % 16)
            self.aes.mix_columns_offset = int(self.aes.shuffle_key_number % 4)
            self.aes.skey = text2matrix(self.aes.skey)

            start = time.time_ns()

            # Encrypt each 16-byte block of the padded plaintext
            for i in range(0, len(padded_plaintext), 16):
                block = padded_plaintext[i:i+16]  # Get a 16-byte block
                cipher_block = self.aes.saes_encryption_block(block)
                ciphertext_blocks.append(cipher_block)

            elapsed_time = time.time_ns() - start

        if self.debug:
            print("\n===============================================================\n")
            
            for ct_block in ciphertext_blocks:
                print("saes_encrypt block ", hexlify(ct_block).decode("utf-8"))
            
            print("\n===============================================================\n")

        # Combine all ciphertext blocks into the final ciphertext
        ciphertext = b''.join(ciphertext_blocks)
        return ciphertext, elapsed_time