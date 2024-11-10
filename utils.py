import math
import string
import random
import hashlib
from constants import *
from array import array

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

def xor_blocks(array1, array2):

    result = []
    for i in range(4):
        xor_result = array1[i] ^ array2[i]
        result.append(xor_result)
    
    return result

def transform_key(key):
    matrix = []
    for i in range(0, len(key), 4):
        row = bytes([key[i], key[i + 1], key[i + 2], key[i + 3]])
        matrix.append(row)
    return matrix

def sub_bytes(column):

    transformed_column = []

    for byte in column:
        # Apply SubBytes transformation to each byte in the column
        transformed_byte = sub_bytes_4(byte)
        # Append the transformed byte to the new column
        transformed_column.append(transformed_byte)
        
    return transformed_column

def sub_bytes_4(column):

    transformed_column = []

    for i in range(4):
        # Apply the S-Box substitution
        substituted_byte = SUBSTITUTION_BOX[column[i]]
        
        # Append the transformed byte to the new list
        transformed_column.append(substituted_byte)
        
    return transformed_column

def sub_bytes_matrix(matrix):
    for i in range(4):
        for j in range(4):
            matrix[i][j] = SUBSTITUTION_BOX[matrix[i][j]]

def galois_multiplication(x, y):

    p = 0
    hiBitSet = 0

    for i in range(8):
        if y & 1 == 1:
            p ^= x
        hiBitSet = x & 0x80
        x <<= 1
        if hiBitSet == 0x80:
            x ^= 0x1b
        y >>= 1
    return p % 256

def calculate_inverse_matrix(matrix_inverse, matrix):
    for i in range(256):
        matrix_inverse[matrix[i]] = i

def convert_matrix(matrix):
    return bytes([byte for row in matrix for byte in row])

def pad_pkcs7(m):
    padding = 16 - (len(m) % 16)
    bytes_fill = bytes([padding] * padding)
    return m + bytes_fill

def unpad_pkcs7(m_padded):
    padding_length = m_padded[-1]
    return m_padded[:-padding_length]

def create_inv_s_box_shuffled():

    shuffle_matrix = []

    for _ in range(256):
        shuffle_matrix.append(-1)

    return shuffle_matrix

def random_shuffle_number(key):
    random_number = 0
    for n, byte in enumerate(key):
        converted_byte = int(byte)
        random_number += math.pow(converted_byte, math.sqrt(n+1))
    return random_number

def shuffle_sbox(arr, num):
    # Initialize a random generator with the seed `num`
    number_generator = random.Random(num)
    
    # Perform the Fisher-Yates shuffle
    for i in range(len(arr) - 1, 0, -1):
        # Get a random index from 0 to i
        j = number_generator.randint(0, i)
        
        # Swap arr[i] with arr[j]
        arr[i], arr[j] = arr[j], arr[i]
    
    return arr