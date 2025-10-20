#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <endian.h>
#include <aes.h>

#include "log.h"
#include "types.h"
#include "constants.h"
#include "poly1305-donna.h"

void increment_ctr(uint32_t *ctr, uint8_t *nonce) {
    if (*ctr == 0xFFFFFFFFUL) {
        *ctr = 0;
        uint8_t carry = 1;
        for (int i = ((int)AES_NONCE_BYTES-(int)1); i >= 0; i--) {
            uint16_t temp_sum = nonce[i] + carry;
            if (temp_sum > 255) {
                nonce[i] = 0;
                carry = 1;
            } else {
                nonce[i] = (uint8_t)temp_sum;
                carry = 0;
                break;
            }
        }
    } else {
        (*ctr)++;
    }
}

status_t CHECK_BUFFER_BOUNDS(size_t current_offset, size_t bytes_to_write, size_t total_buffer_size) {
    if (current_offset + bytes_to_write > total_buffer_size) {
        LOG_ERROR("[SER Error]: Buffer overflow check failed. Offset: %zu, Bytes to write: %zu, Total buffer size: %zu",
                current_offset, bytes_to_write, total_buffer_size);
        return FAILURE_OOBUF;
    }
    return SUCCESS;
}

void calculate_mac(
    uint8_t* key_mac, 
    uint8_t *data_4mac, 
    uint8_t *mac, 
    const size_t data_4mac_len
)
{
    poly1305_context ctx;
    poly1305_init(&ctx, key_mac);
    poly1305_update(&ctx, data_4mac, data_4mac_len);
    poly1305_finish(&ctx, mac);
}

status_t encrypt_decrypt_256(
    const char* label, 
    uint8_t* key_aes, 
    uint8_t* nonce, 
    uint32_t *ctr, 
    uint8_t *data, 
    uint8_t *encrypted_decrypted_data, 
    const size_t data_len
)
{
    uint8_t *keystream_buffer = (uint8_t *)calloc(1, data_len);
    if (!keystream_buffer) {
        LOG_ERROR("%sError calloc keystream_buffer for encryption/decryption: %s", label, strerror(errno));
        return FAILURE;
    }
    aes256ctx aes_ctx;
    aes256_ctr_keyexp(&aes_ctx, key_aes);
    uint8_t iv[AES_IV_BYTES];
    memcpy(iv, nonce, AES_NONCE_BYTES);
/*
 * CRITICAL: Convert the 4-byte Counter to Little-Endian (LE).
 * The underlying PQClean/BearSSL implementation relies on the LE convention
 * (using internal functions like 'br_dec32le') to correctly interpret the
 * 4-byte counter field within the 12-byte IV prefix.
 *  
 * This use of htole32 ensures cryptographic portability and guarantees that 
 * the counter is processed logically (1, 2, 3, etc.), preventing byte-ordering 
 * confusion regardless of the Host system's native endianness (e.g., big-endian systems).
*/
    uint32_t ctr_le = htole32(*(uint32_t *)ctr);
    memcpy(iv + AES_NONCE_BYTES, &ctr_le, sizeof(uint32_t));
    aes256_ctr(keystream_buffer, data_len, iv, &aes_ctx);
    for (size_t i = 0; i < data_len; i++) {
        encrypted_decrypted_data[i] = data[i] ^ keystream_buffer[i];
    }
    free(keystream_buffer);
    aes256_ctx_release(&aes_ctx);
    return SUCCESS;
}

status_t encrypt_decrypt_128(
    const char* label, 
    uint8_t* key_aes, 
    uint8_t* nonce, 
    uint32_t *ctr, 
    uint8_t *data, 
    uint8_t *encrypted_decrypted_data, 
    const size_t data_len
)
{
    uint8_t *keystream_buffer = (uint8_t *)calloc(1, data_len);
    if (!keystream_buffer) {
        LOG_ERROR("%sError calloc keystream_buffer for encryption/decryption: %s", label, strerror(errno));
        return FAILURE;
    }
    aes128ctx aes_ctx;
    aes128_ctr_keyexp(&aes_ctx, key_aes);
    uint8_t iv[AES_IV_BYTES];
    memcpy(iv, nonce, AES_NONCE_BYTES);
/*
 * CRITICAL: Convert the 4-byte Counter to Little-Endian (LE).
 * The underlying PQClean/BearSSL implementation relies on the LE convention
 * (using internal functions like 'br_dec32le') to correctly interpret the
 * 4-byte counter field within the 12-byte IV prefix.
 *  
 * This use of htole32 ensures cryptographic portability and guarantees that 
 * the counter is processed logically (1, 2, 3, etc.), preventing byte-ordering 
 * confusion regardless of the Host system's native endianness (e.g., big-endian systems).
*/
    uint32_t ctr_le = htole32(*(uint32_t *)ctr);
    memcpy(iv + AES_NONCE_BYTES, &ctr_le, sizeof(uint32_t));
    aes128_ctr(keystream_buffer, data_len, iv, &aes_ctx);
    for (size_t i = 0; i < data_len; i++) {
        encrypted_decrypted_data[i] = data[i] ^ keystream_buffer[i];
    }
    free(keystream_buffer);
    aes128_ctx_release(&aes_ctx);
    return SUCCESS;
}
