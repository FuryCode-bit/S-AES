from binascii import hexlify
from modules.utils.constants import *
from modules.utils.utils import *
from copy import copy
import time

'''
This class implements the Advanced Encryption Standard (AES) algorithm 
for encryption and decryption and their respective shuffled versions.
'''

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
        '''
        Initialize AES with encryption parameters and round keys schedule.

        Parameters:
        - key: Main - encryption key (128 bits) used for the AES algorithm.
        - skey: Optional - shuffle key (128 bits) to use in shuffled AES.
        - time: Boolean - flag to measure encryption time.
        - debug: Boolean - flag for debugging output.

        Initializes round keys and key expansion.
        '''
                
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

        '''
        Expand the cipher key into an array of round keys for encryption.

        Returns:
        - List of round keys, each consisting of 16 bytes (128 bits).
        '''
        
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
    
    def sub_bytes(self, state, shuffled=False):
        '''
        Apply the SubBytes transformation using the Substitution-box.

        Parameters:
        - state: 4x4 state matrix to be transformed.
        - shuffled: Boolean flag to use shuffled S-box.

        Returns:
        - The transformed 4x4 matrix.
        '''

        for i in range(4):
            for j in range(4):
                if not shuffled:
                    state[i][j] = SUBSTITUTION_BOX[state[i][j]]
                else:
                    state[i][j] = self.s_box_shuffled[state[i][j]]
        return state

    def shift_rows(self, state, shuffled=False):
        '''
        Perform the ShiftRows operation, either in standard or shuffled mode.

        Parameters:
        - state: 4x4 state matrix to be transformed.
        - shuffled: Boolean flag to use shuffled row shift.

        Returns:
        - The transformed 4x4 matrix.
        '''

        if not shuffled:
            for i in range(4):
                state[i] = state[i][i:] + state[i][:i]
        else:
            # Shuffled ShiftRows: row shifts are based on predefined permutations
            index = int(self.shuffle_key_number % len(PERMUTATIONS))
            permutations = PERMUTATIONS[index]
            
            # Apply the permutation to shift rows in a shuffled manner
            shuffled_state = [[0] * 4 for _ in range(4)]
            for col in range(4):
                for row in range(4):
                    shuffled_state[row][col] = state[(permutations[row] + col) % 4][col]
                    
            # Update the original state matrix with the shuffled values
            state = [list(row) for row in shuffled_state]
            
        return state

    
    def gmul(self, a, b):
        '''
        Perform Galois Field (2^8) multiplication of two bytes. Based from [2]

        Parameters:
        - a, b: Byte values to be multiplied in GF(2^8).

        Returns:
        - Product of a and b within GF(2^8).
        '''

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
        '''
        Perform the MixColumns transformation on a 4x4 matrix. Code adapted from [1]
        """

        Parameters:
        - state: The 4x4 state matrix.
        - shuffled: Boolean flag to apply a shuffled column mix.

        Returns:
        - The transformed state matrix.
        '''

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
        '''
        XOR the round key with the state matrix.

        Parameters:
        - matrix: The 4x4 state matrix.
        - key: The current round key.
        - shuffled: Boolean flag for shuffled operation.

        Returns:
        - The state matrix after round key addition.
        '''

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

    def inv_shift_rows(self, state, shuffled=False):
        '''
        Perform inverse Shift_Rows transformation on the state.

        Parameters:
        - state: The 4x4 state matrix.
        - shuffled: Boolean flag for shuffled inverse rows.

        Returns:
        - The state matrix after inverse row shifts.
        '''

        if not shuffled:
            for i in range(4):
                # Perform the normal inverse shift (circular right shift)
                state[i] = state[i][-i:] + state[i][:-i]
        else:
            # Shuffled Inverse Shift_Rows: row shifts are based on predefined permutations
            index = int(self.shuffle_key_number % len(PERMUTATIONS))
            permutation = PERMUTATIONS[index]
            
            # Apply the permutation to shift rows in a shuffled manner
            shuffled_state = [[0] * 4 for _ in range(4)]
            for col in range(4):
                for row in range(4):
                    shuffled_state[(permutation[row] + col) % 4][col] = state[row][col]
                    
            # Update the original state matrix with the inverse shuffled values
            state = [list(row) for row in shuffled_state]
            
        return state

    def inv_mix_columns(self, state, shuffled = False):
        '''
        Perform inverse MixColumns transformation on the state matrix. Code adapted from [1]

        Parameters:
        - state: The 4x4 state matrix.
        - shuffled: Boolean flag for shuffled inverse column mixing.

        Returns:
        - The state matrix after inverse column mixing.
        '''
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

            for index, column in enumerate(columns):
                state[(index + self.mix_columns_offset) % 4] = column
            return state
        
    def encryption_block(self, text):
        
        #Convert the text to a 4x4 matrix
        block = text2matrix(text)
        debug_print(f"round[ 0].input  {hexlify(bytes(matrix2text(block))).decode('utf-8')}", self.debug)
        debug_print(f"round[ 0].k_sch  {hexlify(bytes(self.round_keys[0])).decode('utf-8')}", self.debug)

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