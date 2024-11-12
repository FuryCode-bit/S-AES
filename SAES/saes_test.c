#include <stdio.h>
#include <string.h>
#include "saes.h"

int main() {
    SAES_KEY keys;
    uint8_t aes_key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t shuffle_key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    
    const char* message = "Hello, world! This is a longer message that needs multiple blocks.";
    size_t message_length = strlen(message);
    
    // Initialize keys
    if (saes_init(&keys, aes_key, shuffle_key) != 0) {
        printf("Key initialization failed\n");
        return 1;
    }
    
    // Encrypt
    size_t ciphertext_length;
    uint8_t* ciphertext = saes_encrypt(&keys, (uint8_t*)message, message_length, &ciphertext_length);
    if (!ciphertext) {
        printf("Encryption failed\n");
        return 1;
    }
    
    // Decrypt
    size_t plaintext_length;
    uint8_t* decrypted = saes_decrypt(&keys, ciphertext, ciphertext_length, &plaintext_length);
    if (!decrypted) {
        free(ciphertext);
        printf("Decryption failed\n");
        return 1;
    }
    printf("Original message: %s\n", message);
    printf("Decrypted message: %s\n", decrypted);
    // Compare
    if (plaintext_length == message_length && 
        memcmp(message, decrypted, message_length) == 0) {
        printf("Test passed!\n");
    } else {
        printf("Test failed!\n");
    }
    
    free(ciphertext);
    free(decrypted);
    return 0;
}