#include "saes.h"
#include <string.h>
#include <stdio.h>

// Helper functions for key manipulation
static inline __m128i key_expand_step(__m128i key, __m128i keygen) {
    __m128i tmp;
    keygen = _mm_shuffle_epi32(keygen, 0xff);
    tmp = _mm_slli_si128(key, 0x4);
    key = _mm_xor_si128(key, tmp);
    tmp = _mm_slli_si128(tmp, 0x4);
    key = _mm_xor_si128(key, tmp);
    tmp = _mm_slli_si128(tmp, 0x4);
    key = _mm_xor_si128(key, tmp);
    return _mm_xor_si128(key, keygen);
}

// Function to create a permutation based on SK
static void create_key_permutation(const uint64_t sk_half, int* perm, int size) {
    // Initialize the perm array with sequential values
    for (int i = 0; i < size; i++) {
        perm[i] = i;
    }

    // Seed the random number generator using sk_half
    srand(sk_half);

    // Shuffle the array using the Fisher-Yates algorithm
    for (int i = size - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int temp = perm[i];
        perm[i] = perm[j];
        perm[j] = temp;
    }

    // Debugging
    printf("Permutation: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", perm[i]);
    }
    printf("\n");
}
   


// Function to shuffle S-box based on SK
static void create_modified_sbox(const uint64_t sk_half, 
                               uint8_t* modified_sbox, 
                               uint8_t* inv_modified_sbox) {
    // Initialize the modified S-box with the sbox standart values
    // Default AES S-Box
    const uint8_t aes_sbox[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };
    memcpy(modified_sbox, aes_sbox, 256);
    // Seed the random number generator using sk_half
    srand(sk_half);

    // Shuffle the array using the Fisher-Yates algorithm
    for (int i = 256 - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int temp = modified_sbox[i];
        modified_sbox[i] = modified_sbox[j];
        modified_sbox[j] = temp;
    }

    int changes = 0;
    for (int i = 0; i < 256; i++) {
        if (modified_sbox[i] != aes_sbox[i]) {
            changes++;
        }
    }
    //DEBUG
    printf("Modified S-box changes: %d\n", changes);
    
    if (changes < 128){
        // Shuffle the array using the Fisher-Yates algorithm
        for (int i = 256 - 1; i > 0 && changes > 128; i--) {
            int j = rand() % (i + 1);
            int temp = modified_sbox[i];
            modified_sbox[i] = modified_sbox[j];
            modified_sbox[j] = temp;
            if (modified_sbox[i] != aes_sbox[i]) {
                changes++;
            }
        }    
    }   
    
    for (int i = 0; i < 256; i++) {
        inv_modified_sbox[modified_sbox[i]] = i;
    }

}

int saes_init(SAES_KEY* keys, const uint8_t* aes_key, const uint8_t* shuffle_key) {
    __m128i key;
    uint64_t sk_first_half, sk_second_half;
    
    if (!keys || !aes_key) return -1;

    // Load the initial AES key
    key = _mm_loadu_si128((__m128i*)aes_key);
    
    // Generate regular AES round keys
    keys->round_keys[0] = key;
    for(int i = 1; i <= 10; i++) {
        key = key_expand_step(key, _mm_aeskeygenassist_si128(key, i));
        keys->round_keys[i] = key;
    }
    
    if (shuffle_key) {  // If we're doing S-AES
        // Split shuffle key into two halves
        memcpy(&sk_first_half, shuffle_key, 8);
        memcpy(&sk_second_half, shuffle_key + 8, 8);
        //Debugging
        printf("sk_first_half: %lu\n", sk_first_half);
        printf("sk_second_half: %lu\n", sk_second_half);

        // Create key permutation using first half of SK
        int perm[11];
        create_key_permutation(sk_first_half, perm, 11);
        
        // Shuffle the round keys
        for(int i = 0; i < 11; i++) {
            keys->shuffled_keys[i] = keys->round_keys[perm[i]];
            // For decryption, we need to transform the middle round keys
            if (i > 0 && i < 10) {
                keys->inv_shuffled_keys[i] = _mm_aesimc_si128(keys->shuffled_keys[i]);
            } else {
                keys->inv_shuffled_keys[i] = keys->shuffled_keys[i];
            }
        }
        //DEBUGGING
        for (int i = 0; i < 11; i++) {
            printf("Shuffled key %d: ", i);
            for (int j = 0; j < 16; j++) {
                printf("%02x ", ((uint8_t*)&keys->shuffled_keys[i])[j]);
            }
            printf("\n");
        }
  
        // Select modified round (1-9) using some bits from SK
        keys->modified_round = 1 + (sk_first_half % 9);
        
        printf("Modified round: %d\n", keys->modified_round);

        // Create modified S-box using second half of SK
        create_modified_sbox(sk_second_half, 
                           keys->modified_sbox, 
                           keys->inv_modified_sbox);
        printf("Modified S-box: ");
        for (int i = 0; i < 256; i++) {
            printf("%02x ", keys->modified_sbox[i]);
        }
        printf("\n");

        printf("Modified Inv S-box: ");
        for (int i = 0; i < 256; i++) {
            printf("%02x ", keys->inv_modified_sbox[i]);
        }
        printf("\n");
        

        // Create modified round key with SK XOR
        __m128i sk_mask = _mm_set_epi64x(sk_second_half, sk_second_half);
        keys->modified_key = _mm_xor_si128(keys->shuffled_keys[keys->modified_round], 
                                         sk_mask);
    } else {
        // If no shuffle key, just copy regular round keys
        memcpy(keys->shuffled_keys, keys->round_keys, sizeof(keys->round_keys));
        memcpy(keys->inv_shuffled_keys, keys->round_keys, sizeof(keys->round_keys));
        keys->modified_round = -1;  // No modified round
    }
    
    return 0;
}

void saes_encrypt_block(const SAES_KEY* keys, const uint8_t* in, uint8_t* out) {
    __m128i m = _mm_loadu_si128((__m128i*)in);
    
    // Initial round
    m = _mm_xor_si128(m, keys->shuffled_keys[0]);
    
    // Main rounds
    for(int i = 1; i < 10; i++) {
        if(i == keys->modified_round) {
            // TODO: Implement modified round with custom S-box
            // For now, just do regular round
            // AddRoundKey ( MixColumns ( ShiftRows ( SubBytes ( x ) ) ) , RK )
            m = _mm_aesenc_si128(m, keys->modified_key);
        } else {
            m = _mm_aesenc_si128(m, keys->shuffled_keys[i]);
        }
    }
    
    // Final round
    m = _mm_aesenclast_si128(m, keys->shuffled_keys[10]);
    
    _mm_storeu_si128((__m128i*)out, m);
}

void saes_decrypt_block(const SAES_KEY* keys, const uint8_t* in, uint8_t* out) {
    __m128i m = _mm_loadu_si128((__m128i*)in);
    
    // Initial round
    m = _mm_xor_si128(m, keys->inv_shuffled_keys[10]);
    
    // Main rounds
    for(int i = 9; i > 0; i--) {
        if(i == keys->modified_round) {
            // TODO: Implement modified round with custom S-box
            // For now, just do regular round
            m = _mm_aesdec_si128(m, _mm_aesimc_si128(keys->modified_key));
        } else {
            m = _mm_aesdec_si128(m, keys->inv_shuffled_keys[i]);
        }
    }
    
    // Final round
    m = _mm_aesdeclast_si128(m, keys->inv_shuffled_keys[0]);
    
    _mm_storeu_si128((__m128i*)out, m);
}