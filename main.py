from modules.encrypt.encrypt import Encrypt
from modules.decrypt.decrypt import Decrypt
from modules.speed.speed import Speed
from binascii import hexlify
import argparse

def main():
    parser = argparse.ArgumentParser(description='AES Encryption/Decryption Tool')
    parser.add_argument('mode', choices=['enc', 'dec', 'speed'], help='Mode: enc (encrypt), dec (decrypt), speed (execute all)')
    parser.add_argument('plaintext', type=str, help='Plaintext to be encrypted or decrypted (in hex format)')
    parser.add_argument('-k', '--key', type=str, required=True, help='Encryption/Decryption key (in hex format)')
    parser.add_argument('-sk', '--skey', type=str, nargs='?', help='Shuffle key (only required for saes mode, in hex format)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable Debug Mode')
    parser.add_argument('-t', '--time', action='store_true', help='Measure encryption/decryption time')

    args = parser.parse_args()

    print("Arguments:", args)
    aes_method = "Custom_AES" if not args.skey else "Shuffled_AES"

    if args.mode == 'speed':
        print("Running speed test with all options...")
        speed_test = Speed(args.plaintext, args.key, args.skey, args.time, args.debug)
        speed_test.Crypto_AES_speed()
        speed_test.Custom_AES_speed()
        if args.skey:
            speed_test.Shuffled_AES_speed()

    elif args.mode == 'enc':
        print("Encryption Mode Selected - Method:", aes_method)
        plaintext_bytes = bytes.fromhex(args.plaintext)
        key_bytes = bytes.fromhex(args.key)
        skey_bytes = bytes.fromhex(args.skey) if args.skey else None
        
        # Perform encryption
        encryptor = Encrypt(plaintext_bytes, key_bytes, skey_bytes, time=args.time, debug=args.debug)

        if aes_method == "Custom_AES":
            ciphertext, enc_time = encryptor.aes_encrypt()
        else:
            ciphertext, enc_time = encryptor.saes_encrypt()

        print("Encrypted Text (hex):", hexlify(ciphertext).decode("utf-8"))
        if args.time:
            print("Encryption Time (ns):", enc_time)

    elif args.mode == 'dec':
        print("Decryption Mode Selected - Method:", aes_method)
        ciphertext_bytes = bytes.fromhex(args.plaintext)
        key_bytes = bytes.fromhex(args.key)
        skey_bytes = bytes.fromhex(args.skey) if args.skey else None

        # Perform decryption
        decryptor = Decrypt(key_bytes, skey_bytes, time=args.time, debug=args.debug)
        
        if aes_method == "Custom_AES":
            decrypted_text, dec_time = decryptor.aes_decrypt(ciphertext_bytes)
        else:
            decrypted_text, dec_time = decryptor.saes_decrypt(ciphertext_bytes)

        print("Decrypted Text (hex):", hexlify(decrypted_text).decode("utf-8"))
        if args.time:
            print("Decryption Time (ns):", dec_time)

if __name__ == "__main__":
    main()
