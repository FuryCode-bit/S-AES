from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from AES128ECB import AES128ECB
from AES import AES as Custom_AES
from SAES import SAES
import hashlib

class StandardAES:
    def __init__(self, key):
        self.k = key

    def encrypt(self, raw):
        
        # Convert string to bytes and pad
        raw = pad(raw.encode('utf8'), AES.block_size)
        cipher = AES.new(self.k.encode("utf8"), AES.MODE_ECB)

        # Encrypt and encode as Base64
        return b64encode(cipher.encrypt(raw))

    def decrypt(self, enc):

        # Decode Base64 and decrypt
        enc = b64decode(enc)
        cipher = AES.new(self.k.encode("utf8"), AES.MODE_ECB)
        
        # Remove padding after decrypting and convert back to string
        return unpad(cipher.decrypt(enc), AES.block_size).decode('utf8')


# TODO: Main function -> Passar tudo para o main.py e deixar apenas o que está relativo a calulo de performance para aqui

def run_aes_implementations(plaintext, key):

    cryptodome_plaintext = None
    cryptodome_ciphertext = None

    custom_aes_plaintext = None
    custom_aes_ciphertext = None

    saes_plaintext = None
    saes_ciphertext = None

    # Generate 128-bit key from password
    aes_custom = AES(plaintext, key)
    
    key_128_bit = aes_custom.generate_key(password.encode("UTF-8"), salt).flatten()

    # Initialize custom AES implementation
    plaintext_padded = pad(plaintext)
    ciphertext_custom = aes_custom.encrypt(plaintext_padded)

    # Initialize StandardAES for comparison
    aes_standard = StandardAES(key_128_bit.tobytes())
    ciphertext_standard = aes_standard.encrypt(plaintext)

    # Verify ciphertexts match
    print("Custom AES Ciphertext:", ciphertext_custom)
    print("Standard AES Ciphertext:", ciphertext_standard)
    assert ciphertext_custom == ciphertext_standard, "Ciphertexts do not match!"

    # Decrypt to verify correctness
    decrypted_custom = aes_custom.decrypt(ciphertext_custom)
    decrypted_standard = aes_standard.decrypt(ciphertext_standard)

    # Remove padding before comparison
    decrypted_custom = unpad(decrypted_custom)
    decrypted_standard = unpad(decrypted_standard)

    print("Custom AES Decryption:", decrypted_custom)
    print("Standard AES Decryption:", decrypted_standard)

    print('\n-------------------------------------------------------------------')

    time_cryptodome_aes_enc, time_cryptodome_aes_dec = StandardAES()
    time_aes_enc, time_aes_dec = Custom_AES()
    time_saes_enc, time_saes_dec = SAES()

    print('\n-------------------------------------------------------------------')
    print("\n")

    print("Results:\n")

    print("Cryptodome AES ciphertext: " + cryptodome_ciphertext)
    print("Cryptodome AES plaintext: " + cryptodome_plaintext)
    print("Cryptodome AES encryption time: " + str(time_aes_enc))
    print("Cryptodome AES decryption time: " + str(time_aes_dec))

    print("\n-------------------------------------------------------------------\n")

    print("custom AES ciphertext: " + custom_aes_ciphertext)
    print("custom AES plaintext: " + custom_aes_plaintext)
    print("custom AES encryption time: " + str(time_aes_enc))
    print("custom AES decryption time: " + str(time_aes_dec))

    print("\n-------------------------------------------------------------------\n")

    print("Shuffled-AES ciphertext: " + saes_ciphertext)
    print("Shuffled-AES plaintext: " + saes_plaintext)
    print("Shuffled-AES encryption time: " + str(time_saes_enc))
    print("Shuffled-AES decryption time: " + str(time_saes_dec))



if __name__ == "__main__":

    key = hashlib.sha256(b"securepassword").digest()[:16]
    plaintext = b"Secret Message!!!"

    run_aes_implementations(plaintext, key)