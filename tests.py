from binascii import hexlify
from AES import AES, text2matrix, xor_words, matrix2text


# Example usage of the print_round_keys function
print("\nExample Key Schedules:")
print('2b7e151628aed2a6abf7158809cf4f3c')  # AES-128 example
key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')

expected_round_keys = [
    '2b7e151628aed2a6abf7158809cf4f3c',  # Initial key
    'a0fafe1788542cb123a339392a6c7605',  # Round 1
    'f2c295f27a96b9435935807a7359f67f',  # Round 2
    '3d80477d4716fe3e1e237e446d7a883b',  # Round 3
    'ef44a541a8525b7fb671253bdb0bad00',  # Round 4
    'd4d1c6f87c839d87caf2b8bc11f915bc',  # Round 5
    '6d88a37a110b3efddbf98641ca0093fd',  # Round 6
    '4e54f70e5f5fc9f384a64fb24ea6dc4f',  # Round 7
    'ead27321b58dbad2312bf5607f8d292f',  # Round 8
    'ac7766f319fadc2128d12941575c006e',  # Round 9
    'd014f9a8c9ee2589e13f0cc8b6630ca6'   # Round 10
]

aes = AES(key)
round_keys = aes.key_expansion()

# Compare generated round keys with expected values
for i, (actual, expected) in enumerate(zip(round_keys, expected_round_keys)):
    actual_hex = hexlify(bytes(actual)).decode('utf-8')
    assert actual_hex == expected, f"Round {i} key mismatch"
    print(f"Round {i} key: {actual_hex}")
    print(f"Expected     : {expected}")

# Testing AES Encryption
key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
plaintext = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
# plaintext = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

plaintext_bytes = bytes.fromhex(plaintext)

print('\n-------------------------------------------------------------------\n')


aes = AES(key)
# Encrypt the plaintext
print(f'\nPLAINTEXT : {plaintext}')
print(f'KEY       : {hexlify(key).decode("utf-8")}')

ciphertext = aes.aes_encrypt(plaintext_bytes)
print(f'CIPHERTEXT: {hexlify(ciphertext).decode("utf-8")}')

print('\n-------------------------------------------------------------------\n')

# Decrypt the ciphertext
decrypted_text = aes.aes_decrypt(ciphertext)
print(f'\nDECRYPTED : {hexlify(decrypted_text).decode("utf-8")}')

print('\n-------------------------------------------------------------------\n')
