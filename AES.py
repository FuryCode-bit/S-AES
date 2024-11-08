from constants import *
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

## Ao rodar a key, não 

def rot_word(word):
    """Rotate a word one byte to the left"""
    return word[1:] + word[:1]

def xor_words(word1, word2):
    """XOR two words byte by byte"""
    return [w1 ^ w2 for w1, w2 in zip(word1, word2)]

def sub_word(word):
    return [SBOX[b] for b in word]

class AES:
    
    def key_expansion(key):
        #Step 0: Key Expansion
        nk = 4  #The key is 128 bits, so 4 words of 32 bits each
        nr = 10 #The number of roundKeys is 10
        
        # Round constant words
        # https://en.wikipedia.org/wiki/AES_key_schedule
        
        rcon = [
            [0x01, 0x00, 0x00, 0x00],
            [0x02, 0x00, 0x00, 0x00],
            [0x04, 0x00, 0x00, 0x00],
            [0x08, 0x00, 0x00, 0x00],
            [0x10, 0x00, 0x00, 0x00],
            [0x20, 0x00, 0x00, 0x00],
            [0x40, 0x00, 0x00, 0x00],
            [0x80, 0x00, 0x00, 0x00],
            [0x1b, 0x00, 0x00, 0x00],
            [0x36, 0x00, 0x00, 0x00]
        ]
        
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
            
            elif i % nk == 4:
                temp = AES.s_box(temp)
            
            expanded_key[i*4:(i+1)*4] = xor_words(expanded_key[(i - nk) * 4:i * 4], temp)
        
        #Convert the expanded key to a list of 16-byte round keys
        round_keys = []
        for i in range(nr):
            start = i * 16
            round_key = expanded_key[start:start+16]
            round_keys.append(round_key)
            
        return round_keys
        
