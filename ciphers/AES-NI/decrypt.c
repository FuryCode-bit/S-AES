// decrypt.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "saes.h"

#define MAX_INPUT_SIZE 1024

uint8_t hex2byte(const char* hex) {
    uint8_t byte = 0;
    for (int i = 0; i < 2; i++) {
        byte <<= 4;
        if (hex[i] >= '0' && hex[i] <= '9')
            byte |= hex[i] - '0';
        else if (hex[i] >= 'a' && hex[i] <= 'f')
            byte |= hex[i] - 'a' + 10;
        else if (hex[i] >= 'A' && hex[i] <= 'F')
            byte |= hex[i] - 'A' + 10;
    }
    return byte;
}

void hex2bytes(const char *hex, uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) {
        bytes[i] = hex2byte(hex + (i * 2));
    }
}

int validate_key(const char* key) {
    // Check length
    if (strlen(key) != 32) {
        fprintf(stderr, "Key must be exactly 32 hex characters\n");
        return 0;
    }
    
    // Check if all characters are valid hex
    for (int i = 0; i < 32; i++) {
        if (!((key[i] >= '0' && key[i] <= '9') ||
              (key[i] >= 'a' && key[i] <= 'f') ||
              (key[i] >= 'A' && key[i] <= 'F'))) {
            fprintf(stderr, "Invalid hex character in key: %c\n", key[i]);
            return 0;
        }
    }
    return 1;
}


int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <aes_key> <shuffle_key>\n", argv[0]);
        fprintf(stderr, "Keys should be 32 characters hex strings (16 bytes)\n");
        fprintf(stderr, "Example: %s 2b7e151628aed2a6abf7158809cf4f3c 2b7e151628aed2a6abf7158809cf4f3c\n", argv[0]);
        return 1;
    }

    if (!validate_key(argv[1]) || !validate_key(argv[2])) {
        return 1;
    }

    

    SAES_KEY keys;
    uint8_t aes_key[16];
    uint8_t shuffle_key[16];
    hex2bytes(argv[1], aes_key, 16);
    hex2bytes(argv[2], shuffle_key, 16);

    // Initialize keys first
    if (saes_init(&keys, aes_key, shuffle_key) != 0) {
        fprintf(stderr, "Key initialization failed\n");
        return 1;
    }

    // First read the length
    size_t ciphertext_length;
    if (fread(&ciphertext_length, sizeof(size_t), 1, stdin) != 1) {
        fprintf(stderr, "Error reading ciphertext length\n");
        return 1;
    }

    // Allocate buffer and read ciphertext
    uint8_t* ciphertext = malloc(ciphertext_length);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    if (fread(ciphertext, 1, ciphertext_length, stdin) != ciphertext_length) {
        fprintf(stderr, "Error reading ciphertext\n");
        free(ciphertext);
        return 1;
    }
    
    // Decrypt
    size_t message_length;
    uint8_t* message = saes_decrypt(&keys, ciphertext, ciphertext_length, &message_length);
    free(ciphertext);  // Free ciphertext buffer as it's no longer needed

    if (!message) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }

    // Write decrypted message and add a newline
    fwrite(message, 1, message_length, stdout);
    printf("\n");
    
    free(message);
    return 0;
}