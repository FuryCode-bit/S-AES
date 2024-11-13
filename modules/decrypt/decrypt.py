from binascii import hexlify
from ciphers.custom_aes.aes import AES as Custom_AES
from modules.utils.constants import *
from modules.utils.utils import *
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

class Decrypt():

    def __init__(self, key, skey, time, debug):
        self.key = key
        self.skey = skey
        self.round_keys = (self.key, self.skey)
        self.round_key_offset = 0
        self.mix_columns_offset = 0

        self.shuffle_key_number = 0

        self.shuffle_round = 0

        # Initialization of shuffled sbox and respective inverse
        self.s_box_shuffled = []
        self.inverse_s_box_shuffled = create_inv_s_box_shuffled()

        self.time = time
        self.debug = debug

        self.aes = Custom_AES(self.key, self.skey, self.time, self.debug) if self.skey else Custom_AES(self.key, self.skey, self.time, self.debug)

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
        print("plaintext: ", plaintext)
        return plaintext, elapsed_time
