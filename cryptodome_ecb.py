from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# key and plaintext
key = 'Sixteen byte key'
data = 'Unaligned'

def encrypt(raw):

    # Convert string to bytes and pad
    raw = pad(raw.encode('utf8'), AES.block_size)
    cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)

    # Encrypt and encode as Base64
    return b64encode(cipher.encrypt(raw))

def decrypt(enc):
    
    # Decode Base64 and decrypt
    enc = b64decode(enc)
    cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)
    
    # Remove padding after decrypting and convert back to string
    return unpad(cipher.decrypt(enc), AES.block_size).decode('utf8')

# Encrypt and print encrypted result
encrypted = encrypt(data)
print('encrypted ECB Base64:', encrypted.decode("utf-8", "ignore"))

# Decrypt and print decrypted result
decrypted = decrypt(encrypted)
print('decrypted data:', decrypted)
