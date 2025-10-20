#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "xorshiro128plus.h"

void generate_fast_salt(uint8_t *buffer, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint64_t random_val = _next_xoroshiro128plus();
        size_t bytes_to_copy = (len - i > 8) ? 8 : (len - i);
        memcpy(&buffer[i], &random_val, bytes_to_copy);
        i += bytes_to_copy;
    }
}
