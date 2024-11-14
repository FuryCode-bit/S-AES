import math
import random
from modules.utils.constants import *
from array import array

def rot_word(word):
    """Rotate a word one byte to the left"""

    return word[1:] + word[:1]

def xor_words(word1, word2):
    """XOR two words byte by byte"""

    return [w1 ^ w2 for w1, w2 in zip(word1, word2)]

def sub_word(word):
    """Substitute each byte in a word using a substitution box (S-box)."""

    return [SUBSTITUTION_BOX[b] for b in word]
    
def text2matrix(text):
    """Convert a 16-byte list into a 4x4 matrix."""

    matrix = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(16):
        matrix[i % 4][i // 4] = text[i]
    return matrix

def matrix2text(matrix):
    """Convert a 4x4 matrix back into a 16-byte list."""

    text = []
    for i in range(4):
        for j in range(4):
            text.append(matrix[j][i])
    return text

def calculate_inverse_matrix(matrix_inverse, matrix):
    """Calculate the inverse of each value in a substitution matrix."""

    for i in range(256):
        matrix_inverse[matrix[i]] = i

def pad_pkcs7(m):
    """Pad the message to make its length a multiple of 16 using PKCS#7 padding."""

    padding = 16 - (len(m) % 16)
    bytes_fill = bytes([padding] * padding)
    return m + bytes_fill

def unpad_pkcs7(m_padded):
    """Remove PKCS#7 padding from a padded message."""

    padding_length = m_padded[-1]
    return m_padded[:-padding_length]

def create_inv_s_box_shuffled():
    """Create an inverse S-box initialized with placeholder values."""

    shuffle_matrix = []

    for _ in range(256):
        shuffle_matrix.append(-1)

    return shuffle_matrix

def random_shuffle_number(key):
    """Generate a pseudorandom number based on key bytes and positions."""

    random_number = 0
    for n, byte in enumerate(key):
        converted_byte = int(byte)
        random_number += math.pow(converted_byte, math.sqrt(n+1))
    return random_number

def shuffle_sbox(arr, num):
    """Shuffle elements in an array based on a seeded pseudorandom generator."""

    number_generator = random.Random(num)
    
    # Perform the Fisher-Yates shuffle
    for i in range(len(arr) - 1, 0, -1):
        # Get a random index from 0 to i
        j = number_generator.randint(0, i)
        
        # Swap arr[i] with arr[j]
        arr[i], arr[j] = arr[j], arr[i]
    
    return arr

def debug_print(message, debug):
    """Print a message if debugging is enabled."""

    if debug:
        print(message)

def print_time(message, time):
    """Print a message if timing is enabled."""

    if time:
        print(message)