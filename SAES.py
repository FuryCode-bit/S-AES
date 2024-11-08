from constants import SUBSTITUTION_BOX, SUBSTITUTION_BOX_INV, RCON
from utils import *
class SAES:
        
    def __init__(self, plaintext, key, skey):
        self.block_size = 16  # AES block size is 16 bytes (128 bits)
        self.key_len = 128
        self.plaintext = plaintext
        self.key = key
        self.skey = skey

    def key_expansion(self):
        index = 0

        matrix = transform_key(self.key)

        for i in range(44):
            col = []
            if i % 4 == 0:
                sub_bytes(matrix)

        return None
    
    def byte_sub(self):
        
        return None

    def shift_rows(self):
        
        return None
    
    def mix_column(self):
        
        return None
    
    def add_round_key(self):
        
        return None
    
    def aes_round(self):
        
        return None
    
    def shuffled_aes_round(self):
        
        return None
    
    def shuffled_aes_round(self):
        
        return None
    
    def shuffled_aes_enc(self):
        
        return None

    def shuffled_aes_dec(self):
        
        return None
    
