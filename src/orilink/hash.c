#include <stddef.h>
#include <stdint.h>

#include <blake3.h>

uint32_t orilink_hash32(const void* data, size_t len) {
    uint8_t out[32]; // full BLAKE3 hash
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data, len);
    blake3_hasher_finalize(&hasher, out, 32);
    // Ambil 4 byte pertama jadi uint32_t
    return (uint32_t)out[0] << 24 | (uint32_t)out[1] << 16 |
           (uint32_t)out[2] << 8  | (uint32_t)out[3];
}
