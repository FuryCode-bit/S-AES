#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "saes.h"

#define BUFFER_SIZE 4096  // 4KB buffer
#define NUM_MEASUREMENTS 100000
#define BILLION 1000000000L

// Function to generate random bytes
void generate_random_bytes(uint8_t *buffer, size_t size) {
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL) {
        fprintf(stderr, "Failed to open /dev/urandom\n");
        exit(1);
    }
    if (fread(buffer, 1, size, urandom) != size) {
        fprintf(stderr, "Failed to read random data\n");
        exit(1);
    }
    fclose(urandom);
}

// Get time difference in nanoseconds
uint64_t time_diff(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * BILLION + (end.tv_nsec - start.tv_nsec);
}

int main() {
    // Allocate buffer
    uint8_t *input_buffer = malloc(BUFFER_SIZE);
    if (!input_buffer) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    
    // Variables for minimum times
    uint64_t min_saes_encrypt = UINT64_MAX;
    uint64_t min_saes_decrypt = UINT64_MAX;
    
    struct timespec start, end;
    
    // Perform measurements
    for (int i = 0; i < NUM_MEASUREMENTS; i++) {
        // Generate random data and keys
        generate_random_bytes(input_buffer, BUFFER_SIZE);
        uint8_t aes_key[16], shuffle_key[16];
        generate_random_bytes(aes_key, 16);
        generate_random_bytes(shuffle_key, 16);
        
        // S-AES Setup
        SAES_KEY saes_keys;
        if (saes_init(&saes_keys, aes_key, shuffle_key) != 0) {
            fprintf(stderr, "S-AES key initialization failed\n");
            free(input_buffer);
            return 1;
        }

        // Measure S-AES encryption
        size_t output_len;
        clock_gettime(CLOCK_MONOTONIC, &start);
        uint8_t *encrypted = saes_encrypt(&saes_keys, input_buffer, BUFFER_SIZE, &output_len);
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        if (!encrypted) {
            fprintf(stderr, "Encryption failed\n");
            continue;
        }
        
        uint64_t saes_encrypt_time = time_diff(start, end);
        if (saes_encrypt_time < min_saes_encrypt) min_saes_encrypt = saes_encrypt_time;
        
        // Measure S-AES decryption
        size_t decrypted_len;
        clock_gettime(CLOCK_MONOTONIC, &start);
        uint8_t *decrypted = saes_decrypt(&saes_keys, encrypted, output_len, &decrypted_len);
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        if (!decrypted) {
            fprintf(stderr, "Decryption failed\n");
            free(encrypted);
            continue;
        }
        
        uint64_t saes_decrypt_time = time_diff(start, end);
        if (saes_decrypt_time < min_saes_decrypt) min_saes_decrypt = saes_decrypt_time;
        
        free(encrypted);
        free(decrypted);
        
        // Progress indicator
        if (i % 1000 == 0) {
            fprintf(stderr, "Progress: %d/%d measurements\r", i, NUM_MEASUREMENTS);
        }
    }
    
    // Print results
    printf("\nResults (best times out of %d measurements):\n", NUM_MEASUREMENTS);
    printf("S-AES Encryption: %lu ns\n", 
           min_saes_encrypt);
    printf("S-AES Decryption: %lu ns\n",min_saes_decrypt);
    
    // Cleanup
    free(input_buffer);
    
    return 0;
}