from copy import copy
from constants import SBOX, SBOX_INV

# Based from https://gist.github.com/raullenchai/2920069 and 
# https://femionewin.medium.com/aes-encryption-with-python-step-by-step-3e3ab0b0fd6c

def subBytes(state):
    for i in range(len(state)):
        state[i] = SBOX[state[i]]
        
def subBytesInv(state):
    for i in range(len(state)):
        state[i] = SBOX_INV[state[i]]

def rotate(word, n):
    return word[n:]+word[0:n]

def shiftRows(state):
    for i in range(4):
        state[i*4:i*4+4] = rotate(state[i*4:i*4+4],i)
def shiftRowsInv(state):
    for i in range(4):
        state[i*4:i*4+4] = rotate(state[i*4:i*4+4],-i)

#Example of the original data
state=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]

# subBytes(state)
# print("s-box: ", state)

# subBytesInv(state)
# print("inverse of s-box: ", state)

def galoisMult(a, b):
    p = 0
    hiBitSet = 0
    for i in range(8):
        if b & 1 == 1:
            p ^= a
        hiBitSet = a & 0x80
        a <<= 1
        if hiBitSet == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256

def mixColumn(column):
    temp = copy(column)
    column[0] = galoisMult(temp[0],2) ^ galoisMult(temp[3],1) ^ \
                galoisMult(temp[2],1) ^ galoisMult(temp[1],3)
    column[1] = galoisMult(temp[1],2) ^ galoisMult(temp[0],1) ^ \
                galoisMult(temp[3],1) ^ galoisMult(temp[2],3)
    column[2] = galoisMult(temp[2],2) ^ galoisMult(temp[1],1) ^ \
                galoisMult(temp[0],1) ^ galoisMult(temp[3],3)
    column[3] = galoisMult(temp[3],2) ^ galoisMult(temp[2],1) ^ \
      galoisMult(temp[1],1) ^ galoisMult(temp[0],3)
    
def mixColumnInv(column):
    temp = copy(column)
    column[0] = galoisMult(temp[0],14) ^ galoisMult(temp[3],9) ^ \
                galoisMult(temp[2],13) ^ galoisMult(temp[1],11)
    column[1] = galoisMult(temp[1],14) ^ galoisMult(temp[0],9) ^ \
                galoisMult(temp[3],13) ^ galoisMult(temp[2],11)
    column[2] = galoisMult(temp[2],14) ^ galoisMult(temp[1],9) ^ \
                galoisMult(temp[0],13) ^ galoisMult(temp[3],11)
    column[3] = galoisMult(temp[3],14) ^ galoisMult(temp[2],9) ^ \
      galoisMult(temp[1],13) ^ galoisMult(temp[0],11)
    
# g = [1,2,3,4]
# mixColumn(g)
# print ('Mixed: ',g)
# mixColumnInv(g)
# print ('Inverse mixed', g)

def addRoundKey(state, roundKey):
    for i in range(len(state)):
     state[i] = state[i] ^ roundKey[i]

# state=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
# roundkey=[2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1]
# addRoundKey(state,roundkey)
# print(state)
# addRoundKey(state,roundkey)
# print(state)