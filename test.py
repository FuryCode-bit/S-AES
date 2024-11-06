import unittest
from binascii import hexlify

from aes import AES

class TestAES(unittest.TestCase):
    def test_aes(self):
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
        
        round_keys = AES.key_expansion(key)
        print("\nKey Schedule:")
        for i in range(len(round_keys)):
            print(f"Round {i} key: {round_keys[i]}")
        
        for i, (actual, expected) in enumerate(zip(round_keys, expected_round_keys)):
            actual_hex = hexlify(bytes(actual)).decode('utf-8')
            self.assertEqual(actual_hex, expected, f"Round {i} key mismatch")
            print(f"Round {i} key: {actual_hex}")
            print(f"Expected: {expected}")
            
if __name__ == '__main__':
    # Run the unit tests
    unittest.main(argv=[''], exit=False)
    
    # Example usage of the print_round_keys function
    print("\nExample Key Schedules:")
    print('2b7e151628aed2a6abf7158809cf4f3c')  # AES-128 example
    
    