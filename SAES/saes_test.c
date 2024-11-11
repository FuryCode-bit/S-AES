#include <stdio.h>
#include <string.h>
#include "saes.h"

int main() {
    SAES_KEY keys;
    uint8_t aes_key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; 
    uint8_t shuffle_key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; 
    uint8_t plaintext[16] = "aaaaa, World!"; // Test data
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    // Initialize keys
    if (saes_init(&keys, aes_key, shuffle_key) != 0) {
        printf("Key initialization failed\n");
        return 1;
    }

    // Encrypt
    saes_encrypt_block(&keys, plaintext, ciphertext);
    
    printf("Ciphertext: %s\n", ciphertext);

    // Decrypt
    saes_decrypt_block(&keys, ciphertext, decrypted);
    printf("Decrypted: %s\n", decrypted);

    // Compare
    if (memcmp(plaintext, decrypted, 16) == 0) {
        printf("Test passed!\n");
    } else {
        printf("Test failed!\n");
    }

    return 0;
}