# Custom_AES works! SAES dont either

# N mudei sub bytes nem inv

from binascii import hexlify
from modules.utils.constants import *
from modules.utils.utils import *
import time
from copy import copy
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

class AES:

    def __init__(self, key, skey=None, time=False, debug=False):
        self.key = key
        self.skey = skey
        self.round_keys = self.key_expansion()
        self.round_key_offset = 0
        self.mix_columns_offset = 0

        self.shuffle_key_number = 0

        self.shuffle_round = 0

        # Initialization of shuffled sbox and respective inverse
        self.s_box_shuffled = []
        self.inverse_s_box_shuffled = create_inv_s_box_shuffled()

        self.time = time
        self.debug = debug
        
    def key_expansion(self):
        
        nk = 4  #The key is 128 bits, so 4 words of 32 bits each
        nr = 10 #The number of roundKeys is 10
        
        if self.skey:
            key = self.skey
        else:
            key = self.key
        
        
        #Convert the key to a list of bytes
        key_bytes = list(key)
        
        #Initialize the expanded key
        #The expanded key is a list of 4-word lists
        expanded_key = [0] * (4 * (nr + 1) * 4)

        #Copy the key to the first 4 words of the expanded key
        expanded_key[0:16] = key_bytes
        
        #Generate the rest of the expanded key
        for i in range(nk, (nr + 1)*4):    
            
            temp = expanded_key[(i-1)*4:i*4]
            
            if i % nk == 0:
                temp = xor_words(sub_word(rot_word(temp)), rcon[i // nk - 1])
            
            expanded_key[i*4:(i+1)*4] = xor_words(expanded_key[(i - nk) * 4:i * 4], temp)
        
        #Convert the expanded key to a list of 16-byte round keys
        round_keys = []
        for i in range(nr + 1):
            start = i * 16
            round_key = expanded_key[start:start+16]
            round_keys.append(round_key)
        
        return round_keys
    
    def sub_bytes(self, block, shuffled=False):
        """Sub Bytes using inverse S-box."""
        for i in range(4):
            for j in range(4):
                if not shuffled:
                    block[i][j] = SUBSTITUTION_BOX[block[i][j]]
                else:
                    block[i][j] = self.s_box_shuffled[block[i][j]]
        return block

    def shift_rows(self, matrix, shuffled=False):
        if not shuffled:
            for i in range(4):
                matrix[i] = matrix[i][i:] + matrix[i][:i]
        else:
            # Shuffled Shift Rows
            index = int(self.shuffle_key_number % len(PERMUTATIONS))
            perm = PERMUTATIONS[index]
            
            matrix[0][0], matrix[1][0], matrix[2][0], matrix[3][0] = matrix[(perm[0]) % 4][0], matrix[(perm[0] + 1) % 4][0], matrix[(perm[0] + 2) % 4][0], matrix[(perm[0] + 3) % 4][0]
            matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1] = matrix[(perm[1]) % 4][1], matrix[(perm[1] + 1) % 4][1], matrix[(perm[1] + 2) % 4][1], matrix[(perm[1] + 3) % 4][1]
            matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2] = matrix[(perm[2]) % 4][2], matrix[(perm[2] + 1) % 4][2], matrix[(perm[2] + 2) % 4][2], matrix[(perm[2] + 3) % 4][2]
            matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3] = matrix[(perm[3]) % 4][3], matrix[(perm[3] + 1) % 4][3], matrix[(perm[3] + 2) % 4][3], matrix[(perm[3] + 3) % 4][3]

        return matrix

    
    def gmul(self, a, b):
        """Galois Field (2^8) Multiplication of two bytes"""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1b  # x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return p & 0xff

    def mix_columns(self, state, shuffled=False):
        """
        Performs Mix Columns operation on a 4x4 matrix.
        Uses shuffled column permutation if `shuffled` is True.
        """
        if not shuffled:
            for j in range(4):
                
                # Store original values
                a = state[j][0]
                b = state[j][1]
                c = state[j][2]
                d = state[j][3]
                
                # Mix column operation
                state[j][0] = self.gmul(2, a) ^ self.gmul(3, b) ^ c ^ d
                state[j][1] = a ^ self.gmul(2, b) ^ self.gmul(3, c) ^ d
                state[j][2] = a ^ b ^ self.gmul(2, c) ^ self.gmul(3, d)
                state[j][3] = self.gmul(3, a) ^ b ^ c ^ self.gmul(2, d)
            return state
        else:
            columns = []
            for i in range(4):
                # Extract column
                column = state[i]
                # print("columns mix_col: ", i, column)
                temp = copy(column)
                # Store original values
                v0, v1, v2, v3 = (temp[0], temp[1], temp[2],temp[3])
                
                # Mix column operation
                column[0] = self.gmul(2, v0) ^ v3 ^ v2 ^ self.gmul(3, v1)
                column[1] = self.gmul(2, v1) ^ v0 ^ v3 ^ self.gmul(3, v2)
                column[2] = self.gmul(2, v2) ^ v1 ^ v0 ^ self.gmul(3, v3)
                column[3] = self.gmul(3, v3) ^ v2 ^ v1 ^ self.gmul(2, v0)

            for index, column in enumerate(columns):
                state[(index + self.mix_columns_offset) % 4] = column
            return state
        
    def add_round_key(self, matrix, key, shuffled=False):
    # params: block | all_round_keys | Boolean
        # offset = self.round_key_offset if shuffled else 0
        if shuffled:
            offset = self.round_key_offset
        else:
            offset = 0

        for i in range(4):
            for j in range(4):
                matrix[j][i] ^= key[i*4 + (j + offset)]
        return matrix

    def inv_sub_bytes(self, block, shuffled=False):
        """Inverse Sub Bytes using inverse S-box."""
        for i in range(4):
            for j in range(4):
                if not shuffled:
                    block[i][j] = SUBSTITUTION_BOX_INV[block[i][j]]
                else:
                    block[i][j] = self.inverse_s_box_shuffled[block[i][j]]  # Use shuffled S-box
        return block

    def inv_shift_rows(self, matrix, shuffled=False):
        """Inverse Shift Rows operation."""
        if not shuffled:
            for i in range(4):
                # Perform the normal inverse shift (circular right shift)
                matrix[i] = matrix[i][-i:] + matrix[i][:-i]
        else:
            # Shuffled inverse shift rows using permutation
            index = int(self.shuffle_key_number % len(PERMUTATIONS))
            perm = PERMUTATIONS[index]            

            matrix[(perm[0]) % 4][0], matrix[(perm[0] + 1) % 4][0], matrix[(perm[0] + 2) % 4][0], matrix[(perm[0] + 3) % 4][0] = matrix[0][0], matrix[1][0], matrix[2][0], matrix[3][0]
            matrix[(perm[1]) % 4][1], matrix[(perm[1] + 1) % 4][1], matrix[(perm[1] + 2) % 4][1], matrix[(perm[1] + 3) % 4][1] = matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1]
            matrix[(perm[2]) % 4][2], matrix[(perm[2] + 1) % 4][2], matrix[(perm[2] + 2) % 4][2], matrix[(perm[2] + 3) % 4][2] = matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2]
            matrix[(perm[3]) % 4][3], matrix[(perm[3] + 1) % 4][3], matrix[(perm[3] + 2) % 4][3], matrix[(perm[3] + 3) % 4][3] = matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3]

        return matrix

    def inv_mix_columns(self, state, shuffled = False):
        """Inverse Mix Columns transformation."""
        # Apply the inverse MixColumns operation
        if not shuffled:
            for j in range(4):

                a = state[j][0]
                b = state[j][1]
                c = state[j][2]
                d = state[j][3]

                state[j][0] = self.gmul(14, a) ^ self.gmul(9, d) ^ self.gmul(13, c) ^ self.gmul(11, b)
                state[j][1] = self.gmul(14, b) ^ self.gmul(9, a) ^ self.gmul(13, d) ^ self.gmul(11, c)
                state[j][2] = self.gmul(14, c) ^ self.gmul(9, b) ^ self.gmul(13, a) ^ self.gmul(11, d)
                state[j][3] = self.gmul(14, d) ^ self.gmul(9, c) ^ self.gmul(13, b) ^ self.gmul(11, a)
            
            return state
        else:
            columns = []
            for i in range(4):
                column = state[i]
                # print("coluns inv_mix_col: ", i, column)
                temp = copy(column)
                a = temp[0]
                b = temp[1]
                c = temp[2]
                d = temp[3]

                column[0] = self.gmul(14, a) ^ self.gmul(9, d) ^ self.gmul(13, c) ^ self.gmul(11, b)
                column[1] = self.gmul(14, b) ^ self.gmul(9, a) ^ self.gmul(13, d) ^ self.gmul(11, c)
                column[2] = self.gmul(14, c) ^ self.gmul(9, b) ^ self.gmul(13, a) ^ self.gmul(11, d)
                column[3] = self.gmul(14, d) ^ self.gmul(9, c) ^ self.gmul(13, b) ^ self.gmul(11, a)
                columns.append(column)

            # Apply inverse column offset if shuffled
            offset = self.mix_columns_offset
            for index, column in enumerate(columns):
                # Shift column by the negative offset to undo the previous shuffle
                state[(index + self.mix_columns_offset) % 4] = column
            return state
    def encryption_block(self, text):
        
        #Convert the text to a 4x4 matrix
        block = text2matrix(text)
        debug_print(f"round[ 0].input  {hexlify(bytes(matrix2text(block))).decode('utf-8')}", self.debug)
        debug_print(f"round[ 0].k_sch  {hexlify(bytes(self.round_keys[0])).decode('utf-8')}", self.debug)  # Round key

        # print("block: ", block)
        # print("self.round_keys[0]: ", self.round_keys[0])

        #Step 1: Add the first round key
        state = self.add_round_key(block, self.round_keys[0])
        
        debug_print(f"round[ 0].start  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
        #Step 2: Perform 9 rounds
        for i in range(1, 10):
            state = self.sub_bytes(state)
            debug_print(f"round[ {i}].s_box  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
            state = self.shift_rows(state)
            debug_print(f"round[ {i}].s_row  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

            state = self.mix_columns(state)
            debug_print(f"round[ {i}].m_col  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
            debug_print(f"round[ {i}].k_sch  {hexlify(bytes(self.round_keys[i])).decode('utf-8')}", self.debug)
            
            state = self.add_round_key(state, self.round_keys[i])
            debug_print(f"round[ {i +1}].start  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

        #Step 3: Perform the final round
        state = self.sub_bytes(state)
        debug_print(f"round[ 10].s_box  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
        
        state = self.shift_rows(state)
        debug_print(f"round[ 10].s_row  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
        debug_print(f"round[ 10].k_sch  {hexlify(bytes(self.round_keys[10])).decode('utf-8')}", self.debug)
        
        state = self.add_round_key(state, self.round_keys[10])
        
        debug_print(f"round[ 10].output  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

        #Convert the state to a list of bytes
        ciphertext = bytes(matrix2text(state))
        return ciphertext

    def decryption_block(self, text):
        
        # Step 1: Convert the text to a 4x4 matrix
        block = text2matrix(text)
        debug_print(f"round[10].input {hexlify(bytes(matrix2text(block))).decode('utf-8')}", self.debug)

        # Step 2: Add the last round key first
        state = self.add_round_key(block, self.round_keys[10])
        debug_print(f"round[10].k_sch {hexlify(bytes(self.round_keys[10])).decode('utf-8')}", self.debug)

        # Step 3: Perform the last round without MixColumns
        state = self.inv_shift_rows(state)
        debug_print(f"round[ 10].is_row  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
        state = self.inv_sub_bytes(state)
        debug_print(f"round[ 10].is_box  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

        # Step 4: Perform the remaining 9 rounds in reverse order
        for i in range(9, 0, -1):
            j = 9-i
            state = self.add_round_key(state, self.round_keys[i])
            debug_print(f"round[{j}].k_sch {hexlify(bytes(self.round_keys[i])).decode('utf-8')}", self.debug)

            state = self.inv_mix_columns(state)
            debug_print(f"round[{j}].m_col {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

            state = self.inv_shift_rows(state)
            debug_print(f"round[{j}].s_row {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

            state = self.inv_sub_bytes(state)
            debug_print(f"round[{j}].s_box {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

        # Step 5: Add the first round key at the end
        debug_print(f"round[ 10].ik_sch  {hexlify(bytes(self.round_keys[0])).decode('utf-8')}", self.debug)
        state = self.add_round_key(state, self.round_keys[0])
        debug_print(f"round[ 10].ioutput  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

        # Convert the state back to plaintext
        plaintext = bytes(matrix2text(state))
        debug_print(f"round[10].output {hexlify(plaintext).decode('utf-8')}", self.debug)
    
        return plaintext

    def saes_encryption_block(self, text):
        """
        SAES Block Encryption.
        Recieves a 16 byte block of plain, encrypts it using 176 byte key and returns
        a 16 byte block of cipher.
        Performs shuffled operations in one of the 9 complete rounds.
        """

        #Convert the text to a 4x4 matrix
        block = text2matrix(text)

        debug_print(f"round[ 0].input  {hexlify(bytes(matrix2text(block))).decode('utf-8')}", self.debug)
        debug_print(f"round[ 0].k_sch  {hexlify(bytes(self.round_keys[0])).decode('utf-8')}", self.debug)  

        #Step 1: Add the first round key
        state = self.add_round_key(block, self.round_keys[0], True)

        debug_print(f"round[ 0].start  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

        #Step 2: Perform 9 rounds
        for i in range(1, 10):
            if i == self.shuffle_round:
                state = self.sub_bytes(state, True)
                debug_print(f"round[ {i}].s_box  {hexlify(bytes(matrix2text(state))).decode('utf-8')}, {self.shuffle_round}", self.debug)
                state = self.shift_rows(state, True)
                debug_print(f"round[ {i}].s_row  {hexlify(bytes(matrix2text(state))).decode('utf-8')}, {self.shuffle_round}", self.debug)

                state = self.mix_columns(state, True)
                debug_print(f"round[ {i}].m_col  {hexlify(bytes(matrix2text(state))).decode('utf-8')}, {self.shuffle_round}", self.debug)
                debug_print(f"round[ {i}].k_sch  {hexlify(bytes(self.round_keys[i])).decode('utf-8')}, {self.shuffle_round}", self.debug)
                
                state = self.add_round_key(state, self.round_keys[i], True)
                debug_print(f"round[ {i +1}].start  {hexlify(bytes(matrix2text(state))).decode('utf-8')}, {self.shuffle_round}", self.debug)
            else:
                state = self.sub_bytes(state)
                debug_print(f"round[ {i}].s_box  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
                state = self.shift_rows(state)
                debug_print(f"round[ {i}].s_row  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

                state = self.mix_columns(state)
                debug_print(f"round[ {i}].m_col  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
                debug_print(f"round[ {i}].k_sch  {hexlify(bytes(self.round_keys[i])).decode('utf-8')}", self.debug)

                state = self.add_round_key(state, self.round_keys[i])
                debug_print(f"round[ {i +1}].start  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)


        #Step 3: Perform the final round
        state = self.sub_bytes(state)
        debug_print(f"round[ 10].s_box  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
        
        state = self.shift_rows(state)
        debug_print(f"round[ 10].s_row  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
        debug_print(f"round[ 10].k_sch  {hexlify(bytes(self.round_keys[10])).decode('utf-8')}", self.debug)
        
        state = self.add_round_key(state, self.round_keys[10])
        
        debug_print(f"round[ 10].output  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

        #Convert the state to a list of bytes
        ciphertext = bytes(matrix2text(state))
        return ciphertext

    def saes_decryption_block(self, text):
                
        # Step 1: Convert the text to a 4x4 matrix
        block = text2matrix(text)
        debug_print(f"round[0].input {hexlify(bytes(matrix2text(block))).decode('utf-8')}", self.debug)

        # Step 2: Add the last round key first
        state = self.add_round_key(block, self.round_keys[10])
        debug_print(f"round[0].k_sch {hexlify(bytes(self.round_keys[10])).decode('utf-8')}", self.debug)

        # Step 3: Perform the last round without MixColumns
        state = self.inv_shift_rows(state)
        debug_print(f"round[ 0].is_row  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
        state = self.inv_sub_bytes(state)
        debug_print(f"round[ 0].is_box  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
        

        # Step 4: Perform 9 rounds in reverse order
        for i in range(9, 0, -1):
            j = 10 - i
            
            # Shuffle round
            if i == self.shuffle_round:

                state = self.add_round_key(state, self.round_keys[i], True)
                debug_print(f"round[{j}].k_sch {hexlify(bytes(self.round_keys[i])).decode('utf-8')}, {self.shuffle_round}", self.debug)

                state = self.inv_mix_columns(state, True)
                debug_print(f"round[{j}].m_col {hexlify(bytes(matrix2text(state))).decode('utf-8')}, {self.shuffle_round}", self.debug)
                
                # Problema
                state = self.inv_shift_rows(state, True)
                debug_print(f"round[{j}].s_row {hexlify(bytes(matrix2text(state))).decode('utf-8')}, {self.shuffle_round}", self.debug)

                state = self.inv_sub_bytes(state, True)
                debug_print(f"round[{j}].s_box {hexlify(bytes(matrix2text(state))).decode('utf-8')}, {self.shuffle_round}", self.debug)
                
            # Normal round
            else:
                state = self.add_round_key(state, self.round_keys[i])
                debug_print(f"round[{j}].k_sch {hexlify(bytes(self.round_keys[i])).decode('utf-8')}", self.debug)

                state = self.inv_mix_columns(state)
                debug_print(f"round[{j}].m_col {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

                state = self.inv_shift_rows(state)
                debug_print(f"round[{j}].s_row {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

                state = self.inv_sub_bytes(state)
                debug_print(f"round[{j}].s_box {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)

        debug_print(f"round[ 10].ik_sch  {hexlify(bytes(self.round_keys[0])).decode('utf-8')}", self.debug)
        state = self.add_round_key(state, self.round_keys[0])
        debug_print(f"round[ 10].ioutput  {hexlify(bytes(matrix2text(state))).decode('utf-8')}", self.debug)
        
        # Convert the state back to plaintext
        plaintext = bytes(matrix2text(state))
        debug_print(f"round[10].output {hexlify(plaintext).decode('utf-8')}", self.debug)
    
        return plaintext

    def aes_encrypt(self, plaintext):
        j = 0
        # Step 1: Pad the plaintext to ensure it's a multiple of 16 bytes
        padded_plaintext = pad_pkcs7(plaintext)
        # padded_plaintext = plaintext

        start = time.time_ns()

        # Step 2: Encrypt each 16-byte block of the padded plaintext
        ciphertext_blocks = []
        for i in range(0, len(padded_plaintext), 16):
            # print(f"\nENC BLOCO {j}\n")
            block = padded_plaintext[i:i+16]  # Get a 16-byte block
            cipher_block = self.encryption_block(block)
            ciphertext_blocks.append(cipher_block)
            j+=1

        elapsed_time = time.time_ns() - start

        # Combine all ciphertext blocks into the final ciphertext
        ciphertext = b''.join(ciphertext_blocks)
        return ciphertext

    def saes_encrypt(self, plaintext):

        # Step 1: Pad the plaintext to ensure it's a multiple of 16 bytes
        padded_plaintext = pad_pkcs7(plaintext)
        # self.skey = text2matrix(self.key)

        # Initialize ciphertext storage
        ciphertext_blocks = []

        if self.skey:
            self.shuffle_key_number = random_shuffle_number(self.skey)

            # Get a random shuffle round and initialize other variables
            self.shuffle_round = int((self.shuffle_key_number % 9) + 1)
            # debug_print(f"self.shuffle_round: {self.shuffle_round}", self.debug)
            ss_box = SUBSTITUTION_BOX.copy()
            self.s_box_shuffled = shuffle_sbox(ss_box, self.shuffle_key_number)
            calculate_inverse_matrix(self.inverse_s_box_shuffled, self.s_box_shuffled)

            
            self.round_key_offset = int(self.shuffle_key_number % 16)
            self.mix_columns_offset = int(self.shuffle_key_number % 4)
            self.skey = text2matrix(self.skey)

            start = time.time_ns()

            # Encrypt each 16-byte block of the padded plaintext
            for i in range(0, len(padded_plaintext), 16):
                block = padded_plaintext[i:i+16]  # Get a 16-byte block
                cipher_block = self.saes_encryption_block(block)
                ciphertext_blocks.append(cipher_block)

            elapsed_time = time.time_ns() - start

        debug_print("\n===============================================================\n", self.debug)
        
        for ct_block in ciphertext_blocks:
            debug_print(f"saes_encrypt block {hexlify(ct_block).decode('utf-8')}", self.debug)
        
        debug_print("\n===============================================================\n", self.debug)

        # Combine all ciphertext blocks into the final ciphertext
        ciphertext = b''.join(ciphertext_blocks)
        return ciphertext
    
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
            plain_block = self.decryption_block(block)  # Implement decryption block
            j+=1
            # Check if this is the last block, and if so, remove padding
            if i + 16 == len(ciphertext):
                plain_block = unpad_pkcs7(plain_block)

            plaintext_blocks.append(plain_block)

        elapsed_time = time.time_ns() - start

        # Combine all plaintext blocks into the final plaintext
        plaintext = b''.join(plaintext_blocks)

        return plaintext

    def saes_decrypt(self, ciphertext):
        # Initialize plaintext storage
        plaintext_blocks = []

        start = time.time_ns()

        # Decrypt each 16-byte block of the ciphertext
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            plain_block = self.saes_decryption_block(block)
            plaintext_blocks.append(plain_block)

        elapsed_time = time.time_ns() - start

        debug_print("\n===============================================================\n", self.debug)
        
        for plaintext_block in plaintext_blocks:
            debug_print("saes_decrypt block " + hexlify(plaintext_block).decode("utf-8"), self.debug)
        
        debug_print("\n===============================================================\n", self.debug)
        # Combine all decrypted blocks and remove padding
        padded_plaintext = b''.join(plaintext_blocks)
        plaintext = unpad_pkcs7(padded_plaintext)
        debug_print(f"plaintext: {plaintext}", self.debug)
        return plaintext