from ciphers.crypto_aes.aes import StandardAES
from modules.encrypt.encrypt import Encrypt
from modules.decrypt.decrypt import Decrypt
from modules.utils.utils import *
from binascii import hexlify
import os

class Speed:
    def __init__(self, plaintext, key, skey = None,time = False, debug = False):
        self.key = bytes.fromhex(key)
        self.skey = bytes.fromhex(skey) if skey else None
        self.plaintext = plaintext
        self.plaintext_bytes = bytes.fromhex(plaintext)
        self.time = time
        self.debug = debug

        self.crypto_aes = StandardAES(self.key)
        self.aes_enc = Encrypt(self.plaintext_bytes, self.key, self.skey, self.time, self.debug)
        self.saes_enc = Encrypt(self.plaintext_bytes, self.key, self.skey, self.time, self.debug) if self.skey else None

        self.aes_dec = Decrypt(self.key, self.skey, self.time, self.debug)
        self.saes_dec = Decrypt(self.key, self.skey, self.time, self.debug) if self.skey else None

        self.min_enc_time_crypto_aes = float('inf')
        self.min_dec_time_crypto_aes = float('inf')
        self.min_enc_time_custom_aes = float('inf')
        self.min_dec_time_custom_aes = float('inf')
        self.min_enc_time_saes = float('inf')
        self.min_dec_time_saes = float('inf')

    def measure_performance(self, plaintext_bytes, key, skey):

        # Measure encryption time
        ciphertext_crypto_aes, enc_time_crypto_aes = StandardAES(key).encrypt(plaintext_bytes)
        self.min_enc_time_crypto_aes = min(self.min_enc_time_crypto_aes, enc_time_crypto_aes)

        # Measure decryption time
        decrypted_text_crypto_aes, dec_time_crypto_aes = StandardAES(key).decrypt(ciphertext_crypto_aes)
        self.min_dec_time_crypto_aes = min(self.min_dec_time_crypto_aes, dec_time_crypto_aes)

        # Measure encryption time
        ciphertext_custom_aes, enc_time_custom_aes = Encrypt(plaintext_bytes, key, None, self.time, self.debug).aes_encrypt()
        self.min_enc_time_custom_aes = min(self.min_enc_time_custom_aes, enc_time_custom_aes)

        # Measure decryption time
        decrypted_text_custom_aes, dec_time_custom_aes = Decrypt(key, None, self.time, self.debug).aes_decrypt(ciphertext_custom_aes)
        self.min_dec_time_custom_aes = min(self.min_dec_time_custom_aes, dec_time_custom_aes)

        # Measure encryption time
        ciphertext_saes, enc_time_saes = Encrypt(plaintext_bytes, key, skey, self.time, self.debug).saes_encrypt()
        self.min_enc_time_saes = min(self.min_enc_time_saes, enc_time_saes)

        # Measure decryption time
        decrypted_text_saes, dec_time_saes = Decrypt(key, skey, self.time, self.debug).saes_decrypt(ciphertext_saes)
        self.min_dec_time_saes = min(self.min_dec_time_saes, dec_time_saes)
        
    def Crypto_AES_speed(self):
        
        print('\n===================================================================')
        print("                           Crypto_AES                                ")
        print('===================================================================\n')

        # Encrypt the plaintext
        print(f'\nPLAINTEXT : {self.plaintext}')
        print(f'KEY       : {hexlify(self.key).decode("utf-8")}')

        ciphertext, std_aes_enc_time = self.crypto_aes.encrypt(self.plaintext_bytes)
        print(f'\nSTANTARD AES CIPHERTEXT: {hexlify(ciphertext).decode("utf-8")}')
        print(f'STANTARD AES Encryption Time in ns: {std_aes_enc_time}')


        # Decrypt the ciphertext
        decrypted_text, std_aes_dec_time = self.crypto_aes.decrypt(ciphertext)
        print(f'\nDECRYPTED : {hexlify(decrypted_text).decode("utf-8")}')
        print(f'STANDARD AES Decryption Time in ns: {str(std_aes_dec_time)}')

    def Custom_AES_speed(self):

        print('\n===================================================================')
        print("                           Custom_AES                                ")
        print('===================================================================\n')

        # Encrypt the plaintext
        print(f'\nPLAINTEXT : {self.plaintext}')
        print(f'KEY       : {hexlify(self.key).decode("utf-8")}')
        
        # Encrypt
        ciphertext, aes_enc_time = self.aes_enc.aes_encrypt()
        print(f'\nCustom AES CIPHERTEXT: {hexlify(ciphertext).decode("utf-8")}')
        print(f'Custom AES Encryption Time in ns: {aes_enc_time}\n')

        # Decrypt
        decrypted_text, aes_dec_time = self.aes_dec.aes_decrypt(ciphertext)
        print(f'\nDECRYPTED Custom AES: {hexlify(decrypted_text).decode("utf-8")}')
        print(f'Custom AES Decryption Time in ns: {aes_dec_time}')


    def Shuffled_AES_speed(self):
            
        print('\n===================================================================')
        print("                         Shuffled-AES                                ")
        print('===================================================================\n')

        # Encrypt the plaintext
        print(f'\nPLAINTEXT : {self.plaintext}')
        print(f'KEY       : {hexlify(self.key).decode("utf-8")}')
        print(f'SKEY      : {hexlify(self.skey).decode("utf-8")}')
        
        # Encrypt
        ciphertext, saes_enc_time = self.saes_enc.saes_encrypt()
        print(f'\nSHUFFLED AES CIPHERTEXT: {hexlify(ciphertext).decode("utf-8")}')
        print(f'Shuffled AES Encryption Time in ns: {saes_enc_time}\n')

        # Decrypt
        decrypted_text, saes_dec_time = self.saes_dec.saes_decrypt(ciphertext)
        print(f'\nDECRYPTED Shuffled AES: {hexlify(decrypted_text).decode("utf-8")}')
        print(f'Shuffled AES Decryption Time in ns: {saes_dec_time}\n')

    def speed(self):

        if self.debug:
            self.Crypto_AES_speed()
            self.Custom_AES_speed()
            if self.skey:
                self.Shuffled_AES_speed()
        else:

            for _ in range(10000):
                # Generate random plaintext and key for each iteration
                buffer_plaintext = os.urandom(4096)
                buffer_key = os.urandom(16)
                buffer_skey = os.urandom(16)

                self.measure_performance(buffer_plaintext, buffer_key, buffer_skey)

            print("\n===================================================\n")
            print("\nMinimum Encryption time\n")
            print(f"Crypto_aes: {self.min_enc_time_crypto_aes} ns")
            print(f"AES: {self.min_enc_time_custom_aes} ns")
            print(f"Shuffle AES: {self.min_enc_time_saes} ns")
            print("\n===================================================\n")
            print("\nMinimum Decryption time\n")
            print(f"Crypto_aes: {self.min_dec_time_crypto_aes} ns")
            print(f"AES: {self.min_dec_time_custom_aes} ns")
            print(f"Shuffle AES: {self.min_dec_time_saes} ns")
            print("\n===================================================\n")