from modules.encrypt.encrypt import Encrypt
from modules.decrypt.decrypt import Decrypt
from modules.speed.speed import Speed
from modules.utils.utils import *
from binascii import hexlify
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description='AES Encryption/Decryption Tool')
    parser.add_argument('mode', choices=['enc', 'dec', 'speed'], help='Mode: enc (encrypt), dec (decrypt), speed (execute all)')
    parser.add_argument('key', type=str, help='Encryption/Decryption key (in hex format)')
    parser.add_argument('skey', type=str, nargs='?', default=None, help='Shuffle key (only required for saes mode, in hex format)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable Debug Mode')
    parser.add_argument('-t', '--time', action='store_true', help='Measure encryption/decryption time')

    args = parser.parse_args()

    # Read plain from stdin
    block = sys.stdin.read()

    debug_print(f"\nArguments: {args}\n", args.debug)
    aes_method = "Custom_AES" if not args.skey else "Shuffled_AES"

    if args.mode == 'speed':
        debug_print("Running speed test with all options...", args.debug)
        speed_test = Speed(block, args.key, args.skey, args.time, args.debug)
        speed_test.Crypto_AES_speed()
        speed_test.Custom_AES_speed()
        if args.skey:
            speed_test.Shuffled_AES_speed()

    elif args.mode == 'enc':
        debug_print(f"Encryption Mode Selected - Method: {aes_method}", args.debug)
        plaintext_bytes = block.encode('utf-8')
        key_bytes = bytes.fromhex(args.key)
        skey_bytes = bytes.fromhex(args.skey) if args.skey else None
        
        # Perform encryption
        encryptor = Encrypt(plaintext_bytes, key_bytes, skey_bytes, time=args.time, debug=args.debug)

        if aes_method == "Custom_AES":
            ciphertext, enc_time = encryptor.aes_encrypt()
        else:
            ciphertext, enc_time = encryptor.saes_encrypt()

        if not args.debug:
            # Stdout
            for hexa in ciphertext:
                print(hexa,end="")

        debug_print(f"Encrypted Text (hex): {hexlify(ciphertext).decode('utf-8')}", args.debug)
        if args.time:
            debug_print(f"Encryption Time (ns): {enc_time}", args.debug)

    elif args.mode == 'dec':
    
        debug_print(f"Decryption Mode Selected - Method: {aes_method}", args.debug)
        ciphertext_bytes = block.encode('utf-8')
        key_bytes = bytes.fromhex(args.key)
        skey_bytes = bytes.fromhex(args.skey) if args.skey else None

        # Perform decryption
        decryptor = Decrypt(key_bytes, skey_bytes, time=args.time, debug=args.debug)
        
        if aes_method == "Custom_AES":
            decrypted_text, dec_time = decryptor.aes_decrypt(ciphertext_bytes)
        else:
            decrypted_text, dec_time = decryptor.saes_decrypt(ciphertext_bytes)

        debug_print(f"Decrypted Text (hex): {hexlify(decrypted_text).decode('utf-8')}", args.debug)
        if args.time:
            debug_print(f"Decryption Time (ns): {dec_time}", args.debug)

        if not args.debug:
            # Stdout
            for hexa in decrypted_text:
                print(hexa,end="")
                
if __name__ == "__main__":
    main()