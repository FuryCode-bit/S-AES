from constants import *


def transform_key(key):
    matrix = []
    for i in range(0, len(key), 4):
        row = [key[i], key[i + 1], key[i + 2], key[i + 3]]
        matrix.append(row)
        print(matrix)

    return matrix

def sub_bytes(matrix):
    for col in range(4):
        matrix[col] = SUBSTITUTION_BOX[matrix[col]]

def pad_pkcs7(plain):
    return None

def unpad_pkcs7(plain):
    return None

