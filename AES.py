from constants import *
from binascii import hexlify
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
def rot_word(word):
    """Rotate a word one byte to the left"""
    return word[1:] + word[:1]

def xor_words(word1, word2):
    """XOR two words byte by byte"""
    return [w1 ^ w2 for w1, w2 in zip(word1, word2)]

def sub_word(word):
    return [SUBSTITUTION_BOX[b] for b in word]

def text2matrix(text):
    # Convert the bytes to a 4x4 matrix
    matrix = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(16):
        matrix[i % 4][i // 4] = text[i]
    return matrix

def matrix2text(matrix):
    text = []
    for i in range(4):
        for j in range(4):
            text.append(matrix[j][i])
    return text

class AES:
    
    def __init__(self, key):
        self.key = key
        self.round_keys = self
    
    def key_expansion(self):
        #Step 0: Key Expansion
        nk = 4  #The key is 128 bits, so 4 words of 32 bits each
        nr = 10 #The number of roundKeys is 10
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
        
        self.round_keys = round_keys
        return round_keys
    
    def sub_box(self,block):
        for i in range(4):
            for j in range(4):
                block[i][j] = SUBSTITUTION_BOX[block[i][j]]
        return block    
    
    def shift_rows(self, block):
        for i in range(4):
            block[i] = block[i][i:] + block[i][:i]
        return block
    
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

    def mix_columns(self,state):
        """
        Mix columns transformation for a 4x4 state matrix stored in row-major order
        state[i][j] represents row i, column j
        """
        # Process each column
        for j in range(4):
            # Extract column
            column = [state[i][j] for i in range(4)]
            
            # Store original values
            a, b, c, d = column
            
            # Mix column operation
            state[0][j] = self.gmul(2, a) ^ self.gmul(3, b) ^ c ^ d
            state[1][j] = a ^ self.gmul(2, b) ^ self.gmul(3, c) ^ d
            state[2][j] = a ^ b ^ self.gmul(2, c) ^ self.gmul(3, d)
            state[3][j] = self.gmul(3, a) ^ b ^ c ^ self.gmul(2, d)
        
        return state

        
    def add_round_key(self, block, round_key):
        #Block is a 4x4 matrix
        #Round key is a 4-word list
        for i in range(4):
            for j in range(4):
                block[j][i] ^= round_key[i*4 + j]
        return block
    
    def encryption_block(self, text):
        
        #Convert the text to a 4x4 matrix
        block = text2matrix(text)
        print(f"round[ 0].input  {hexlify(bytes(matrix2text(block))).decode('utf-8')}")
        print(f"round[ 0].k_sch  {hexlify(bytes(self.round_keys[0])).decode('utf-8')}")  # Round key

        #Step 1: Add the first round key
        state = self.add_round_key(block, self.round_keys[0])
        
        print(f"round[ 0].start  {hexlify(bytes(matrix2text(state))).decode('utf-8')}")
        #Step 2: Perform 9 rounds
        for i in range(1, 10):
            state = self.sub_box(state)
            print(f"round[ {i}].s_box  {hexlify(bytes(matrix2text(state))).decode('utf-8')}")
            state = self.shift_rows(state)
            print(f"round[ {i}].s_row  {hexlify(bytes(matrix2text(state))).decode('utf-8')}")

            state = self.mix_columns(state)
            print(f"round[ {i}].m_col  {hexlify(bytes(matrix2text(state))).decode('utf-8')}")
            print(f"round[ {i}].k_sch  {hexlify(bytes(self.round_keys[i])).decode('utf-8')}")
            
            state = self.add_round_key(state, self.round_keys[i])
            print(f"round[ {i +1}].start  {hexlify(bytes(matrix2text(state))).decode('utf-8')}")

        #Step 3: Perform the final round
        state = self.sub_box(state)
        print(f"round[ 10].s_box  {hexlify(bytes(matrix2text(state))).decode('utf-8')}")
        
        state = self.shift_rows(state)
        print(f"round[ 10].s_row  {hexlify(bytes(matrix2text(state))).decode('utf-8')}")
        print(f"round[ 10].k_sch  {hexlify(bytes(self.round_keys[10])).decode('utf-8')}")
        
        state = self.add_round_key(state, self.round_keys[10])
        
        print(f"round[ 10].output  {hexlify(bytes(matrix2text(state))).decode('utf-8')}")

        #Convert the state to a list of bytes
        ciphertext = matrix2text(state)
        return ciphertext
