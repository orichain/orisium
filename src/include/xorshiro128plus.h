#ifndef XOROSHIRO128PLUS_H
#define XOROSHIRO128PLUS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <randombytes.h>

static uint64_t s[2];
static bool is_seeded = false;
static uint64_t current_rand_64bit = 0;
static uint8_t byte_counter = 8; 

static inline uint64_t rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static void _xoroshiro128plus(void) {
    uint8_t output[8];
    uint64_t output_be;
    randombytes(output, 8);
    memcpy(&output_be, output, 8);
    s[0] = be64toh(output_be);
    randombytes(output, 8);
    memcpy(&output_be, output, 8);
    s[1] = be64toh(output_be);
    is_seeded = true;
}

static inline uint64_t _next_xoroshiro128plus(void) {
    if (!is_seeded) {
        _xoroshiro128plus();
    }
    const uint64_t s0 = s[0];
    uint64_t s1 = s[1];
    const uint64_t result = s0 + s1;    
    s1 ^= s0;
    s[0] = rotl(s0, 24) ^ s1 ^ (s1 << 16);
    s[1] = rotl(s1, 37);
    return result;
}

static inline uint8_t _next_xoroshiro128plus_uint8(void) {
    if (byte_counter >= 8) {
        current_rand_64bit = _next_xoroshiro128plus(); 
        byte_counter = 0;
    }
    uint8_t result_byte = (uint8_t)(current_rand_64bit >> (byte_counter * 8)) & 0xFF;
    byte_counter++;
    return result_byte;
}

void generate_fast_salt(uint8_t *buffer, size_t len);

#endif
