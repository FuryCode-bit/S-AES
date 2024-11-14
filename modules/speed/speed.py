from ciphers.crypto_aes.aes import StandardAES
from modules.encrypt.encrypt import Encrypt
from modules.decrypt.decrypt import Decrypt
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
    
# key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
# skey = bytes.fromhex("10000000000000000000000000000000")

# expected_round_keys = [
#     '2b7e151628aed2a6abf7158809cf4f3c',  # Initial key
#     'a0fafe1788542cb123a339392a6c7605',  # Round 1
#     'f2c295f27a96b9435935807a7359f67f',  # Round 2
#     '3d80477d4716fe3e1e237e446d7a883b',  # Round 3
#     'ef44a541a8525b7fb671253bdb0bad00',  # Round 4
#     'd4d1c6f87c839d87caf2b8bc11f915bc',  # Round 5
#     '6d88a37a110b3efddbf98641ca0093fd',  # Round 6
#     '4e54f70e5f5fc9f384a64fb24ea6dc4f',  # Round 7
#     'ead27321b58dbad2312bf5607f8d292f',  # Round 8
#     'ac7766f319fadc2128d12941575c006e',  # Round 9
#     'd014f9a8c9ee2589e13f0cc8b6630ca6'   # Round 10
# ]

# aes = AES(key)
# round_keys = aes.key_expansion()

# # Compare generated round keys with expected values
# for i, (actual, expected) in enumerate(zip(round_keys, expected_round_keys)):
#     actual_hex = hexlify(bytes(actual)).decode('utf-8')
#     assert actual_hex == expected, f"Round {i} key mismatch"
#     print(f"Round {i} key: {actual_hex}")
#     print(f"Expected     : {expected}")

# # Testing AES Encryption
# key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
# skey = bytes.fromhex("10000000000000000000000000000000")

# plaintext = "00112233445566778899aabbccddeeff"
# plaintext = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
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
        print(f'SANTARD AES Decryption Time in ns: {str(std_aes_dec_time)}')
        # print(f'SAES Decryption Time in ms: {str(saes_dec_time/1000000)}')

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
        # print(f'Custom AES Encryption Time in ns: {aes_enc_time}')

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
        print(f'Shuffled AES Encryption Time in ns: {saes_enc_time}')

        # Decrypt
        decrypted_text, saes_dec_time = self.saes_dec.saes_decrypt(ciphertext)
        print(f'\nDECRYPTED Shuffled AES: {hexlify(decrypted_text).decode("utf-8")}')
        print(f'Shuffled AES Decryption Time in ns: {saes_dec_time}')



        min_enc_time = float('inf')
        min_dec_time = float('inf')


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
                buffer_key = os.urandom(16)  # 128-bit key
                buffer_skey = os.urandom(16)

                self.measure_performance(buffer_plaintext, buffer_key, buffer_skey)
                
                # min_enc_time_crypto_aes = min(min_enc_time_crypto_aes, metcra)
                # min_dec_time_crypto_aes = min(min_dec_time_crypto_aes, mdtcra)
                # min_enc_time_custom_aes = min(min_enc_time_custom_aes, metca)
                # min_dec_time_custom_aes = min(min_dec_time_custom_aes, mdtca)
                # min_enc_time_saes = min(min_enc_time_saes, mets)
                # min_dec_time_saes = min(min_dec_time_saes, mdts)

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