#ifndef SAES_H
#define SAES_H

#include <stdint.h>
#include <wmmintrin.h>

// Structure definition needs to be visible to users
typedef struct {
    __m128i round_keys[11];    // Original AES round keys
    __m128i shuffled_keys[11]; // Shuffled version of round keys
    __m128i inv_shuffled_keys[11]; // Inverse shuffled keys for decryption
    uint8_t sbox[256];         // Original S-box
    uint8_t modified_sbox[256]; // Modified S-box for the special round
    uint8_t inv_modified_sbox[256]; // Inverse modified S-box
    int modified_round;        // Which round is modified (1-9)
    __m128i modified_key;      // Modified round key with SK XOR
    __m128i inv_modified_key;  // Inverse modified round key
} SAES_KEY;

// Initialize S-AES keys and modifications
int saes_init(SAES_KEY* keys, const uint8_t* aes_key, const uint8_t* shuffle_key);

// Encrypt a single block
void saes_encrypt_block(const SAES_KEY* keys, const uint8_t* in, uint8_t* out);

// Decrypt a single block
void saes_decrypt_block(const SAES_KEY* keys, const uint8_t* in, uint8_t* out);

uint8_t* saes_encrypt(const SAES_KEY *keys, const uint8_t *plaintext, size_t plaintext_length, size_t *ciphertext_length); 

uint8_t* saes_decrypt(const SAES_KEY *keys, const uint8_t *ciphertext, size_t ciphertext_length, size_t *plaintext_length);

#endif /* SAES_H */
