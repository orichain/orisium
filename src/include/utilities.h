#ifndef UTILITIES_H
#define UTILITIES_H

#include <aes.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <fips202.h>
#include <math.h>
#include <netdb.h>

#if defined(__NetBSD__)
    #ifndef AI_V4MAPPED
        #define AI_V4MAPPED 0
    #endif
    #include <sys/signal.h>
    #include <sys/errno.h>
    #include <sys/time.h>
    #include <sys/endian.h>
    #include <sys/common_int_limits.h>
#elif defined(__OpenBSD__)
    #ifndef AI_V4MAPPED
        #define AI_V4MAPPED 0
    #endif
    #include <sys/_time.h>
    #include <sys/signal.h>
    #include <sys/errno.h>
    #include <sys/endian.h>
#elif defined(__FreeBSD__)
    #include <sys/signal.h>
    #include <sys/_clock_id.h>
    #include <x86/endian.h>
    #include <strings.h>
    #include <x86/_stdint.h>
#else
    #include <endian.h>
    #include <stddef.h>
#endif

#include <netinet/in.h>
#include <randombytes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "constants.h"
#include "log.h"
#include "poly1305-donna.h"
#include "types.h"
#include "oritlsf.h"
#include "xorshiro128plus.h"

static inline void insertion_sort_uint64(uint64_t *arr, size_t n) {
    for (size_t i = 1; i < n; ++i) {
        uint64_t key = arr[i];
        size_t j = i;
        while (j > 0 && arr[j - 1] > key) {
            arr[j] = arr[j - 1];
            --j;
        }
        arr[j] = key;
    }
}

static inline void shell_sort_uint64(uint64_t *arr, size_t n) {
    size_t h = 1;
    while (h < n / 3) {
        h = h * 3 + 1;
    }
    while (h >= 1) {
        for (size_t i = h; i < n; i++) {
            uint64_t temp = arr[i];
            size_t j;
            for (j = i; j >= h && arr[j - h] > temp; j -= h) {
                arr[j] = arr[j - h];
            }
            arr[j] = temp;
        }
        h /= 3;
    }
}

static inline size_t quick_sort_partition(uint64_t *arr, size_t low, size_t high) {
    uint64_t pivot = arr[high];
    size_t i = low;
    uint64_t tmp;    
    for (size_t j = low; j < high; ++j) {
        if (arr[j] < pivot) {
            tmp = arr[i];
            arr[i] = arr[j];
            arr[j] = tmp;
            i++;
        }
    }
    tmp = arr[i];
    arr[i] = arr[high];
    arr[high] = tmp;
    return i;
}

static inline void quick_sort_uint64_recursive(uint64_t *arr, size_t low, size_t high) {
    if (high - low < ORISORT_THRESHOLD_INSERTION) {
        insertion_sort_uint64(arr + low, high - low + 1);
        return;
    }
    if (low < high) {
        size_t pi = quick_sort_partition(arr, low, high);
        if (pi > 0) quick_sort_uint64_recursive(arr, low, pi - 1);
        quick_sort_uint64_recursive(arr, pi + 1, high);
    }
}

static inline void oritw_sort_uint64(uint64_t *arr, size_t n) {
    if (n <= 1) {
        return;
    }
    #if ORITW_MAX_CANDIDATES <= ORISORT_THRESHOLD_INSERTION
    insertion_sort_uint64(arr, n);
    #elif ORITW_MAX_CANDIDATES <= ORISORT_THRESHOLD_SHELL
    shell_sort_uint64(arr, n);
    #else
    quick_sort_uint64_recursive(arr, 0, n - 1);
    #endif
}

static inline int hexchr2bin(char c, uint8_t *out) {
    if (__builtin_expect(out == NULL, 0)) return 0;
    uint8_t v = (uint8_t)c;
    uint8_t d = (uint8_t)(v - '0');
    uint8_t u = (uint8_t)(v - 'A');
    uint8_t l = (uint8_t)(v - 'a');
    uint8_t is_d = (uint8_t)(d <= 9);
    uint8_t is_u = (uint8_t)(u <= 5);
    uint8_t is_l = (uint8_t)(l <= 5);
    *out = (uint8_t)((is_d * d) |
                     (is_u * (u + 10)) |
                     (is_l * (l + 10)));
    return (is_d | is_u | is_l);
}

static inline int hexs2bin(const char *hex, size_t hexlen, uint8_t *out, size_t outlen) {
    if (__builtin_expect(!hex || !out, 0)) return -1;
    if (__builtin_expect(hexlen / 2 < outlen, 0)) return -1;
    for (size_t i = 0; i < outlen; i++) {
        uint8_t hi, lo;
        if (!hexchr2bin(hex[2*i], &hi) ||
            !hexchr2bin(hex[2*i + 1], &lo)) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static inline void bin2hexs(const uint8_t *bin, size_t binlen, char *out) {
    if (__builtin_expect(!bin || !out, 0)) return;
    for (size_t i = 0; i < binlen; i++) {
        uint8_t nibbles[2];
        nibbles[0] = bin[i] >> 4; 
        nibbles[1] = bin[i] & 0x0F;

        for (int j = 0; j < 2; j++) {
            uint8_t v = nibbles[j];
            uint8_t is_digit = (uint8_t)(v <= 9);
            uint8_t is_letter = (uint8_t)(v >= 10);
            out[i * 2 + j] = (char)((is_digit * ('0' + v)) | 
                                    (is_letter * ('a' + (v - 10))));
        }
    }
    out[binlen * 2] = '\0';
}

static inline void get_time_str(char *buf, size_t len) {
    time_t t = time(NULL);
    struct tm tm_info;
    localtime_r(&t, &tm_info);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm_info);
}

static inline void print_hex(const char* label, const uint8_t* data, size_t len, int uppercase) {
    if (label)
        printf("%s", label);

    const char* fmt = uppercase ? "%02X" : "%02x";

    for (size_t i = 0; i < len; ++i) {
        printf(fmt, data[i]);
    }
    printf("\n");
}

static void increment_ctr(uint32_t *ctr, uint8_t *nonce) {
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

static inline void calculate_mac(
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

static inline status_t encrypt_decrypt_256(
    const char* label, 
    oritlsf_pool_t *pool, 
    uint8_t* key_aes, 
    uint8_t* nonce, 
    uint32_t *ctr, 
    uint8_t *data, 
    uint8_t *encrypted_decrypted_data, 
    const size_t data_len
)
{
    uint8_t *keystream_buffer = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, data_len);
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
    uint32_t ctr_le = htole32(*ctr);
    memcpy(iv + AES_NONCE_BYTES, &ctr_le, sizeof(uint32_t));
    aes256_ctr(keystream_buffer, data_len, iv, &aes_ctx);
    for (size_t i = 0; i < data_len; i++) {
        encrypted_decrypted_data[i] = data[i] ^ keystream_buffer[i];
    }
    oritlsf_free(pool, (void **)&keystream_buffer);
    aes256_ctx_release(&aes_ctx);
    return SUCCESS;
}

static status_t encrypt_decrypt_128(
    const char* label, 
    oritlsf_pool_t *pool, 
    uint8_t* key_aes, 
    uint8_t* nonce, 
    uint32_t *ctr, 
    uint8_t *data, 
    uint8_t *encrypted_decrypted_data, 
    const size_t data_len
)
{
    uint8_t *keystream_buffer = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, data_len);
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
    uint32_t ctr_le = htole32(*ctr);
    memcpy(iv + AES_NONCE_BYTES, &ctr_le, sizeof(uint32_t));
    aes128_ctr(keystream_buffer, data_len, iv, &aes_ctx);
    for (size_t i = 0; i < data_len; i++) {
        encrypted_decrypted_data[i] = data[i] ^ keystream_buffer[i];
    }
    oritlsf_free(pool, (void **)&keystream_buffer);
    aes128_ctx_release(&aes_ctx);
    return SUCCESS;
}

static inline status_t compare_mac(
    uint8_t *key_mac, 
    uint8_t *data, 
    const size_t data_len,
    uint8_t *data_4mac
)
{
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context ctx;
    poly1305_init(&ctx, key_mac);
    poly1305_update(&ctx, data, data_len);
    poly1305_finish(&ctx, mac);
    if (!poly1305_verify(mac, data_4mac)) {       
        return FAILURE_MACMSMTCH;
    }
    return SUCCESS;
}

static inline void decrement_ctr(uint32_t *ctr, uint8_t *nonce) {
    if (*ctr == 0) {
        *ctr = 0xFFFFFFFFUL;
        uint8_t borrow = 1;
        for (int i = ((int)AES_NONCE_BYTES-(int)1); i >= 0; i--) {
            int16_t temp_diff = nonce[i] - borrow;
            if (temp_diff < 0) {
                nonce[i] = 255;
                borrow = 1; 
            } else {
                nonce[i] = (uint8_t)temp_diff;
                borrow = 0;
                break;
            }
        }
    } else {
        (*ctr)--;
    }
}

static inline bool is_1greater_ctr(const char* label, oritlsf_pool_t *pool, uint8_t *data, uint8_t* key_mac, uint8_t *nonce, uint32_t *ctr) {
    uint8_t tmp_nonce[AES_NONCE_BYTES];
    memcpy(tmp_nonce, nonce, AES_NONCE_BYTES);
    uint32_t tmp_ctr = *ctr;
//----------------------------------------------------------------------
    increment_ctr(&tmp_ctr, tmp_nonce);
    const size_t header_offset = AES_TAG_BYTES;
    const size_t header_len = sizeof(uint32_t) +
                              ORILINK_VERSION_BYTES +
                              sizeof(uint8_t) +
                              sizeof(uint8_t) +
                              sizeof(uint8_t);
    uint8_t *header = data + header_offset;
    uint8_t decripted_header[header_len];
    #if defined(ORILINK_DECRYPT_HEADER)
        if (encrypt_decrypt_128(
                label,
                pool,
                key_mac,
                tmp_nonce,
                &tmp_ctr,
                header,
                decripted_header,
                header_len
            ) != SUCCESS
        )
        {
            memset(tmp_nonce, 0, AES_NONCE_BYTES);
            return false;
        }
    #else
        memcpy(decripted_header, header, header_len);
    #endif
    uint32_t data_ctr_be;
    memcpy(&data_ctr_be, decripted_header, sizeof(uint32_t));
    uint32_t data_ctr = be32toh(data_ctr_be);
    bool islwr = (data_ctr == tmp_ctr);
//----------------------------------------------------------------------    
    memset(tmp_nonce, 0, AES_NONCE_BYTES);
    return islwr;
}

static inline bool is_1lower_equal_ctr(const char* label, oritlsf_pool_t *pool, uint8_t *data, uint8_t* key_mac, uint8_t *nonce, uint32_t *ctr) {
    uint8_t tmp_nonce[AES_NONCE_BYTES];
    memcpy(tmp_nonce, nonce, AES_NONCE_BYTES);
    uint32_t tmp_ctr = *ctr;
//----------------------------------------------------------------------
    const size_t header_offset = AES_TAG_BYTES;
    const size_t header_len = sizeof(uint32_t) +
                              ORILINK_VERSION_BYTES +
                              sizeof(uint8_t) +
                              sizeof(uint8_t) +
                              sizeof(uint8_t);
    uint8_t *header = data + header_offset;
    uint8_t decripted_header[header_len];
    #if defined(ORILINK_DECRYPT_HEADER)
        if (encrypt_decrypt_128(
                label,
                pool,
                key_mac,
                tmp_nonce,
                &tmp_ctr,
                header,
                decripted_header,
                header_len
            ) != SUCCESS
        )
        {
            memset(tmp_nonce, 0, AES_NONCE_BYTES);
            return false;
        }
    #else
        memcpy(decripted_header, header, header_len);
    #endif
    uint32_t data_ctr_be;
    memcpy(&data_ctr_be, decripted_header, sizeof(uint32_t));
    uint32_t data_ctr = be32toh(data_ctr_be);
    bool issme = (data_ctr == tmp_ctr);
    if (issme) {
        memset(tmp_nonce, 0, AES_NONCE_BYTES);
        return issme;
    }
    decrement_ctr(&tmp_ctr, tmp_nonce);
    #if defined(ORILINK_DECRYPT_HEADER)
        if (encrypt_decrypt_128(
                label,
                pool,
                key_mac,
                tmp_nonce,
                &tmp_ctr,
                header,
                decripted_header,
                header_len
            ) != SUCCESS
        )
        {
            memset(tmp_nonce, 0, AES_NONCE_BYTES);
            return false;
        }
    #else
        memcpy(decripted_header, header, header_len);
    #endif
    memcpy(&data_ctr_be, decripted_header, sizeof(uint32_t));
    data_ctr = be32toh(data_ctr_be);
    bool islwr = (data_ctr == tmp_ctr);
//----------------------------------------------------------------------    
    memset(tmp_nonce, 0, AES_NONCE_BYTES);
    return islwr;
}

static inline bool is_equal_ctr(const char* label, oritlsf_pool_t *pool, uint8_t *data, uint8_t* key_mac, uint8_t *nonce, uint32_t *ctr) {
    uint8_t tmp_nonce[AES_NONCE_BYTES];
    memcpy(tmp_nonce, nonce, AES_NONCE_BYTES);
    uint32_t tmp_ctr = *ctr;
//----------------------------------------------------------------------
    const size_t header_offset = AES_TAG_BYTES;
    const size_t header_len = sizeof(uint32_t) +
                              ORILINK_VERSION_BYTES +
                              sizeof(uint8_t) +
                              sizeof(uint8_t) +
                              sizeof(uint8_t);
    uint8_t *header = data + header_offset;
    uint8_t decripted_header[header_len];
    #if defined(ORILINK_DECRYPT_HEADER)
        if (encrypt_decrypt_128(
                label,
                pool,
                key_mac,
                tmp_nonce,
                &tmp_ctr,
                header,
                decripted_header,
                header_len
            ) != SUCCESS
        )
        {
            memset(tmp_nonce, 0, AES_NONCE_BYTES);
            return false;
        }
    #else
        memcpy(decripted_header, header, header_len);
    #endif
    uint32_t data_ctr_be;
    memcpy(&data_ctr_be, decripted_header, sizeof(uint32_t));
    uint32_t data_ctr = be32toh(data_ctr_be);
    bool issme = (data_ctr == tmp_ctr);
//----------------------------------------------------------------------    
    memset(tmp_nonce, 0, AES_NONCE_BYTES);
    return issme;
}

static inline bool is_gc_ctr(const char* label, oritlsf_pool_t *pool, uint8_t *data, uint8_t* key_mac, uint8_t *nonce) {
    uint8_t tmp_nonce[AES_NONCE_BYTES];
    memcpy(tmp_nonce, nonce, AES_NONCE_BYTES);
    uint32_t tmp_ctr = 0xffffffff;
//----------------------------------------------------------------------
    const size_t header_offset = AES_TAG_BYTES;
    const size_t header_len = sizeof(uint32_t) +
                              ORILINK_VERSION_BYTES +
                              sizeof(uint8_t) +
                              sizeof(uint8_t) +
                              sizeof(uint8_t);
    uint8_t *header = data + header_offset;
    uint8_t decripted_header[header_len];
    #if defined(ORILINK_DECRYPT_HEADER)
        if (encrypt_decrypt_128(
                label,
                pool,
                key_mac,
                tmp_nonce,
                &tmp_ctr,
                header,
                decripted_header,
                header_len
            ) != SUCCESS
        )
        {
            memset(tmp_nonce, 0, AES_NONCE_BYTES);
            return false;
        }
    #else
        memcpy(decripted_header, header, header_len);
    #endif
    uint32_t data_ctr_be;
    memcpy(&data_ctr_be, decripted_header, sizeof(uint32_t));
    uint32_t data_ctr = be32toh(data_ctr_be);
    bool issme = (data_ctr == tmp_ctr);
//----------------------------------------------------------------------    
    memset(tmp_nonce, 0, AES_NONCE_BYTES);
    return issme;
}

static inline double add_jitter(double value) {
    uint64_t r;
    arc4random_buf(&r, sizeof(r));
    double jitter_amount = (((double)r * 0x1p-64) / RAND_MAX_DOUBLE * JITTER_PERCENTAGE * 2) - JITTER_PERCENTAGE;
    value *= (1.0 + jitter_amount);
    return value;
}

static inline double retry_interval_with_jitter_us(double retry_value_prediction) {
    double retry_interval = retry_value_prediction;
    retry_interval = pow((double)2, retry_interval);
    if (retry_interval < (double)MIN_RETRY_SEC) retry_interval = (double)MIN_RETRY_SEC;
    retry_interval *= (double)1e6;
    retry_interval = add_jitter(retry_interval);
    if (retry_interval < (double)MIN_GAP_US) {
        retry_interval = (double)MIN_GAP_US;
    }
    return retry_interval;
}

static inline double retry_interval_us(double retry_value_prediction) {
    double retry_interval = retry_value_prediction;
    retry_interval = pow((double)2, retry_interval);
    if (retry_interval < (double)MIN_RETRY_SEC) retry_interval = (double)MIN_RETRY_SEC;
    retry_interval *= (double)1e6;
    if (retry_interval < (double)MIN_GAP_US) {
        retry_interval = (double)MIN_GAP_US;
    }
    return retry_interval;
}

static inline double node_hb_interval_with_jitter_us(double rtt_value_prediction, double retry_value_prediction) {
    double hb_interval = (double)NODE_HEARTBEAT_INTERVAL * pow((double)2, retry_value_prediction);
    hb_interval *= (double)1e6;
    hb_interval = add_jitter(hb_interval);
    hb_interval += rtt_value_prediction / (double)1e3;
    if (hb_interval < (double)MIN_GAP_US) {
        hb_interval = (double)MIN_GAP_US;
    }
    return hb_interval;
}

static inline double worker_hb_interval_with_jitter_us() {
    double hb_interval = (double)WORKER_HEARTBEAT_INTERVAL;
    hb_interval *= (double)1e6;
    hb_interval = add_jitter(hb_interval);
    if (hb_interval < (double)MIN_GAP_US) {
        hb_interval = (double)MIN_GAP_US;
    }
    return hb_interval;
}

static inline double worker_hb_interval_us() {
    double hb_interval = (double)WORKER_HEARTBEAT_INTERVAL;
    hb_interval *= (double)1e6;
    if (hb_interval < (double)MIN_GAP_US) {
        hb_interval = (double)MIN_GAP_US;
    }
    return hb_interval;
}

static inline double worker_check_healthy_us() {
    double hb_interval = (double)WORKER_CHECK_HEALTHY;
    hb_interval *= (double)1e6;
    if (hb_interval < (double)MIN_GAP_US) {
        hb_interval = (double)MIN_GAP_US;
    }
    return hb_interval;
}

static inline bool is_1lower_ctr(const char* label, oritlsf_pool_t *pool, uint8_t *data, uint8_t* key_mac, uint8_t *nonce, uint32_t *ctr) {
    uint8_t tmp_nonce[AES_NONCE_BYTES];
    memcpy(tmp_nonce, nonce, AES_NONCE_BYTES);
    uint32_t tmp_ctr = *ctr;
//----------------------------------------------------------------------
    decrement_ctr(&tmp_ctr, tmp_nonce);
    const size_t header_offset = AES_TAG_BYTES;
    const size_t header_len = sizeof(uint32_t) +
                              ORILINK_VERSION_BYTES +
                              sizeof(uint8_t) +
                              sizeof(uint8_t) +
                              sizeof(uint8_t);
    uint8_t *header = data + header_offset;
    uint8_t decripted_header[header_len];
    #if defined(ORILINK_DECRYPT_HEADER)
        if (encrypt_decrypt_128(
                label,
                pool,
                key_mac,
                tmp_nonce,
                &tmp_ctr,
                header,
                decripted_header,
                header_len
            ) != SUCCESS
        )
        {
            memset(tmp_nonce, 0, AES_NONCE_BYTES);
            return false;
        }
    #else
        memcpy(decripted_header, header, header_len);
    #endif
    uint32_t data_ctr_be;
    memcpy(&data_ctr_be, decripted_header, sizeof(uint32_t));
    uint32_t data_ctr = be32toh(data_ctr_be);
    bool islwr = (data_ctr == tmp_ctr);
//----------------------------------------------------------------------    
    memset(tmp_nonce, 0, AES_NONCE_BYTES);
    return islwr;
}

static inline int kdf(uint8_t *out, size_t outlen,
    const uint8_t *key, size_t key_len,
    const uint8_t *info, size_t info_len)
{
    if ((key_len > UINT32_MAX) ||
        (info_len > UINT32_MAX))
        return -1;
    if (!out && outlen)
        return -1;
    shake256incctx st;
    uint8_t buffer[4];
    shake256_inc_init(&st);
    const uint8_t tag = 0xFF;
    shake256_inc_absorb(&st, &tag, 1);
    const uint8_t key_header = 0x01;
    shake256_inc_absorb(&st, &key_header, 1);
    buffer[0] = (uint8_t)(key_len >> 24);
    buffer[1] = (uint8_t)(key_len >> 16);
    buffer[2] = (uint8_t)(key_len >> 8);
    buffer[3] = (uint8_t)(key_len);
    shake256_inc_absorb(&st, buffer, 4);
    if (key && key_len)
        shake256_inc_absorb(&st, key, key_len);
    const uint8_t info_header = 0x02;
    shake256_inc_absorb(&st, &info_header, 1);
    buffer[0] = (uint8_t)(info_len >> 24);
    buffer[1] = (uint8_t)(info_len >> 16);
    buffer[2] = (uint8_t)(info_len >> 8);
    buffer[3] = (uint8_t)(info_len);
    shake256_inc_absorb(&st, buffer, 4);
    if (info && info_len)
        shake256_inc_absorb(&st, info, info_len);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(out, outlen, &st);
    shake256_inc_ctx_release(&st);
#if defined(__NetBSD__)
    explicit_memset(buffer, 0, sizeof(buffer));
#else
    explicit_bzero(buffer, sizeof(buffer));
#endif
    return 0;
}

static inline status_t generate_nonce(const char* label, uint8_t *out_nonce) {
    if (out_nonce == NULL) {
        LOG_ERROR("%sError: out_nonce cannot be NULL.", label);
        return FAILURE;
    }
    if (randombytes(out_nonce, AES_NONCE_BYTES) != 0) {
        LOG_ERROR("%sError: randombytes.", label);
        return FAILURE;
    }
    return SUCCESS;
}

static inline status_t generate_uint64_t_id(const char* label, uint64_t *out_id) {
    if (out_id == NULL) {
        LOG_ERROR("%sError: out_id cannot be NULL.", label);
        return FAILURE;
    }
    uint8_t output[8];
    uint64_t output_be;
    if (randombytes(output, 8) != 0) {
        LOG_ERROR("%sError: randombytes.", label);
        return FAILURE;
    }
    memcpy(&output_be, output, 8);
    *out_id = be64toh(output_be);
    return SUCCESS;
}

static inline status_t generate_si_id(const char* label, uint8_t session_index, uint64_t *out_id) {
    if (out_id == NULL) {
        LOG_ERROR("%sError: out_id cannot be NULL.", label);
        return FAILURE;
    }
    uint8_t output[8];
    uint64_t output_be;
    uint8_t output_rand[7];
    if (randombytes(output_rand, 7) != 0) {
        LOG_ERROR("%sError: randombytes.", label);
        return FAILURE;
    }
    output[0] = session_index;
    memcpy(output + 1, output_rand, 7);
    memcpy(&output_be, output, 8);
    *out_id = be64toh(output_be);
    return SUCCESS;
}

static inline status_t read_id_si(const char* label, uint64_t id, uint8_t *session_index) {
    if (session_index == NULL) {
        LOG_ERROR("%sError: si cannot be NULL.", label);
        return FAILURE;
    }
    uint8_t output[8];
    uint64_t output_be = htobe64(id);
    memcpy(output, &output_be, sizeof(uint64_t));
    *session_index = output[0];
    return SUCCESS;
}

static inline status_t set_nonblocking(const char* label, int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        LOG_ERROR("%sfcntl F_GETFL: %s", label, strerror(errno));
        return FAILURE;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_ERROR("%sfcntl F_SETFL O_NONBLOCK: %s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

static inline status_t convert_str_to_sockaddr_in6(const char *ip_str, uint16_t port, struct sockaddr_in6 *addr) {
    struct in_addr ipv4;
    struct in6_addr ipv6;
    uint8_t out_ipv6[IPV6_ADDRESS_LEN];
    
    memset(addr, 0, sizeof(struct sockaddr_in6));
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htobe16(port);
    addr->sin6_flowinfo = 0;
    addr->sin6_scope_id = 0;
    if (inet_pton(AF_INET6, ip_str, &ipv6) == 1) {
        memcpy(out_ipv6, &ipv6, IPV6_ADDRESS_LEN);
        memcpy(&(addr->sin6_addr), out_ipv6, IPV6_ADDRESS_LEN);
        return SUCCESS;
    }
    if (inet_pton(AF_INET, ip_str, &ipv4) == 1) {
        memset(out_ipv6, 0, 10);
        out_ipv6[10] = 0xff;
        out_ipv6[11] = 0xff;
        memcpy(&out_ipv6[12], &ipv4, IPV4_ADDRESS_LEN);
        memcpy(&(addr->sin6_addr), out_ipv6, IPV6_ADDRESS_LEN);
        return SUCCESS;
    }
    struct addrinfo hints, *res, *p;
    int status_gai;
    char port_str[6];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
    snprintf(port_str, sizeof(port_str), "%u", port);
    status_gai = getaddrinfo(ip_str, port_str, &hints, &res);
    if (status_gai != 0) {
        LOG_ERROR("getaddrinfo for '%s': %s", ip_str, gai_strerror(status_gai));
        return FAILURE;
    }
    for (p = res; p != NULL; p = p->ai_next) {
        if (p->ai_family == AF_INET6) {
            memcpy(addr, p->ai_addr, p->ai_addrlen);
            freeaddrinfo(res);
            return SUCCESS;
        }
    }
    LOG_ERROR("getaddrinfo untuk '%s' tidak menemukan alamat IPv6 atau IPv4-mapped yang sesuai.", ip_str);
    freeaddrinfo(res);
    return FAILURE;
}

static inline bool is_ipv4_mapped_in6(const struct sockaddr_in6 *addr) {
    if (!addr) return false;
    return IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr);
}

static inline bool extract_ipv4_from_in6(
    const struct sockaddr_in6 *addr,
    struct in_addr *out)
{
    if (!addr || !out) return false;
    if (!IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr)) return false;

    memcpy(&out->s_addr, &addr->sin6_addr.s6_addr[12], sizeof(out->s_addr));
    return true;
}

static inline bool convert_ipv4_to_v4mapped_v6(
    const struct sockaddr_in *src,
    struct sockaddr_in6 *dst)
{
    if (!src || !dst) return false;
    memset(dst, 0, sizeof(*dst));
    dst->sin6_family = AF_INET6;
    dst->sin6_port   = src->sin_port;
    dst->sin6_addr.s6_addr[10] = 0xff;
    dst->sin6_addr.s6_addr[11] = 0xff;
    memcpy(&dst->sin6_addr.s6_addr[12], &src->sin_addr.s_addr, 4);
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
    dst->sin6_len = sizeof(*dst);
#endif
    return true;
}

static inline void serialize_sockaddr_in6(const struct sockaddr_in6 *addr, uint8_t *buffer) {
    uint16_t family_be = htobe16(addr->sin6_family);
    uint16_t port_be = htobe16(addr->sin6_port);
    uint32_t flowinfo_be = htobe32(addr->sin6_flowinfo);
    uint32_t scopeid_be = htobe32(addr->sin6_scope_id);
    size_t offset = 0;
    memcpy(buffer + offset, &family_be, sizeof(family_be)); offset += sizeof(family_be);
    memcpy(buffer + offset, &port_be, sizeof(port_be)); offset += sizeof(port_be);
    memcpy(buffer + offset, &flowinfo_be, sizeof(flowinfo_be)); offset += sizeof(flowinfo_be);
    memcpy(buffer + offset, &(addr->sin6_addr), IPV6_ADDRESS_LEN); offset += IPV6_ADDRESS_LEN;
    memcpy(buffer + offset, &scopeid_be, sizeof(scopeid_be)); offset += sizeof(scopeid_be);
}

static inline void deserialize_sockaddr_in6(const uint8_t *buffer, struct sockaddr_in6 *addr) {
    memset(addr, 0, sizeof(struct sockaddr_in6));
    size_t offset = 0;
    uint16_t family_be;
    uint16_t port_be;
    uint32_t flowinfo_be;
    uint32_t scopeid_be;
    memcpy(&family_be, buffer + offset, sizeof(uint16_t)); offset += sizeof(uint16_t);
    memcpy(&port_be, buffer + offset, sizeof(uint16_t)); offset += sizeof(uint16_t);
    memcpy(&flowinfo_be, buffer + offset, sizeof(uint32_t)); offset += sizeof(uint32_t);
    memcpy(&(addr->sin6_addr), buffer + offset, IPV6_ADDRESS_LEN); offset += IPV6_ADDRESS_LEN;
    memcpy(&scopeid_be, buffer + offset, sizeof(uint32_t)); offset += sizeof(uint32_t);
    addr->sin6_family = be16toh(family_be);
    addr->sin6_port = be16toh(port_be);
    addr->sin6_flowinfo = be32toh(flowinfo_be);
    addr->sin6_scope_id = be32toh(scopeid_be);
}

static inline float calculate_average(const float* data, int num_elements) {
    if (num_elements == 0) return 0.0f;
    float sum = 0.0f;
    for (int i = 0; i < num_elements; ++i) {
        sum += data[i];
    }
    return sum / (float)num_elements;
}

static inline double calculate_double_average(const double* data, int num_elements) {
    if (num_elements == 0) return (double)0;
    double sum = (double)0;
    for (int i = 0; i < num_elements; ++i) {
        sum += data[i];
    }
    return sum / (double)num_elements;
}

static inline long double calculate_long_double_average(const long double* data, int num_elements) {
    if (num_elements == 0) return (long double)0;
    long double sum = (long double)0;
    for (int i = 0; i < num_elements; ++i) {
        sum += data[i];
    }
    return sum / (long double)num_elements;
}

static inline float calculate_variance(const float* data, int num_elements, float mean) {
    if (num_elements <= 1) return 0.0f;
    float sum_squared_diff = 0.0f;
    for (int i = 0; i < num_elements; ++i) {
        float diff = data[i] - mean;
        sum_squared_diff += diff * diff;
    }
    return sum_squared_diff / (float)(num_elements - 1);
}

static inline double calculate_double_variance(const double* data, int num_elements, double mean) {
    if (num_elements <= 1) return (double)0;
    double sum_squared_diff = (double)0;
    for (int i = 0; i < num_elements; ++i) {
        double diff = data[i] - mean;
        sum_squared_diff += diff * diff;
    }
    return sum_squared_diff / (double)(num_elements - 1);
}

static inline long double calculate_long_double_variance(const long double* data, int num_elements, long double mean) {
    if (num_elements <= 1) return (long double)0;
    long double sum_squared_diff = (long double)0;
    for (int i = 0; i < num_elements; ++i) {
        long double diff = data[i] - mean;
        sum_squared_diff += diff * diff;
    }
    return sum_squared_diff / (long double)(num_elements - 1);
}

static inline status_t sleep_ns(long nanoseconds) {
	if (nanoseconds < 0) {
		return FAILURE;
	}
    struct timespec ts;
    ts.tv_sec = nanoseconds / 1000000000L;
    ts.tv_nsec = nanoseconds % 1000000000L;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
        // Retry if interrupted
    }
    return SUCCESS;
}

static inline status_t sleep_us(long microseconds) {
    return sleep_ns(microseconds * 1000L);
}

static inline status_t sleep_ms(long milliseconds) {
    return sleep_ns(milliseconds * 1000000L);
}

static inline status_t sleep_s(double seconds) {
    long ns = (long)(fmin(seconds, 60 * 60 * 24) * 1e9);
    return sleep_ns(ns);
}

static inline uint64_t_status_t get_monotonic_time_ns(const char *label) {
	uint64_t_status_t result;
	result.status = FAILURE;
	result.r_uint64_t = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return result;
    }
    result.r_uint64_t = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    result.status = SUCCESS;
    return result;
}

static inline status_t ensure_directory_exists(const char *label, const char *path) {
	if (!path) {
        LOG_ERROR("%sNULL path provided to ensure_directory_exists.", label);
        return FAILURE;
    }
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            LOG_DEBUG("%sDirectory already exists: %s", label, path);
            return SUCCESS;
        } else {
            LOG_ERROR("%sPath exists but is not a directory: %s", label, path);
            return FAILURE;
        }
    }
    if (mkdir(path, 0755) == 0) {
        LOG_DEBUG("%sDirectory created: %s", label, path);
        return 0;
    } else {
        LOG_ERROR("%smkdir failed for path '%s': %s", label, path, strerror(errno));
        return FAILURE;
    }
}

static inline void double_to_uint8_be(double value, uint8_t out[8]) {
    uint64_t temp_u64;

    memcpy(&temp_u64, &value, sizeof(double));
    uint64_t big_endian_u64 = htobe64(temp_u64);
    memcpy(out, &big_endian_u64, sizeof(uint64_t));
}

static inline double uint8_be_to_double(const uint8_t in[8]) {
    uint64_t big_endian_u64;
    double value;

    memcpy(&big_endian_u64, in, sizeof(uint64_t));
    uint64_t host_u64 = be64toh(big_endian_u64);
    memcpy(&value, &host_u64, sizeof(double));
    return value;
}

static inline bool sockaddr_equal(const struct sockaddr *a, const struct sockaddr *b) {
    if (a == NULL || b == NULL) {
        return false;
    }
    if (a->sa_family != b->sa_family) {
        return false;
    }
    if (a->sa_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
        const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
        //if (a4->sin_port != b4->sin_port) {
        //    return false;
        //}
        if (memcmp(&a4->sin_addr, &b4->sin_addr, sizeof(struct in_addr)) != 0) {
            return false;
        }
        return true;
    } else if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
        //if (a6->sin6_port != b6->sin6_port) {
        //    return false;
        //}
        if (memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(struct in6_addr)) != 0) {
            return false;
        }
        //if (a6->sin6_flowinfo != b6->sin6_flowinfo) {
        //    return false;
        //}
        //if (a6->sin6_scope_id != b6->sin6_scope_id) {
        //    return false;
        //}
        return true;
    }
    return false;
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline status_t CHECK_BUFFER_BOUNDS(size_t current_offset, size_t bytes_to_write, size_t total_buffer_size) {
    if (current_offset + bytes_to_write > total_buffer_size) {
        LOG_ERROR("[SER Error]: Buffer overflow check failed. Offset: %zu, Bytes to write: %zu, Total buffer size: %zu",
                current_offset, bytes_to_write, total_buffer_size);
        return FAILURE_OOBUF;
    }
    return SUCCESS;
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline status_t SER_CHECK_SPACE(size_t bytes_needed, size_t buffer_size) {
    if (bytes_needed > buffer_size) {
        return FAILURE_OOBUF;
    }
    return SUCCESS;
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline status_t DESER_CHECK_SPACE(size_t bytes_needed, size_t current_len) {
    if (current_len < bytes_needed) {
        return FAILURE_OOBUF;
    }
    return SUCCESS;
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_FD(int *fd) {
    if (*fd != -1) {
        close(*fd);
        *fd = -1;
    }
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_ET_BUFFER(oritlsf_pool_t *pool, et_buffer_t **eb) {
    et_buffer_t *buffer = *eb;
    if (buffer == NULL) return;
    if (buffer->buffer_in != NULL) {
        oritlsf_free(pool, (void **)&buffer->buffer_in);
    }
    if (buffer->buffer_out != NULL) {
        oritlsf_free(pool, (void **)&buffer->buffer_out);
    }
    oritlsf_free(pool, (void **)eb);
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline int GENERATE_EVENT_ID() {
    int new_id;
    do {
        generate_fast_salt((uint8_t *)&new_id, 4);
    } while (new_id == -1); 
    return new_id;
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_EVENT_ID(oritlsf_pool_t *pool, et_buffered_event_id_t **eb_event_id) {
    et_buffered_event_id_t *ee_id = *eb_event_id;
    if (ee_id == NULL) return;
    if (ee_id->event_id != -1) {
        if (ee_id->event_type == EIT_FD) {
            close(ee_id->event_id);
        }
        ee_id->event_id = -1;
    }
    CLOSE_ET_BUFFER(pool, &ee_id->buffer);
    oritlsf_free(pool, (void **)eb_event_id);
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_UDS(int *uds_fd) {
    if (*uds_fd != 0) {
        close(*uds_fd);
        *uds_fd = 0;
    }
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_PID(pid_t *pid) {
    if (*pid > 0) {
        kill(*pid, SIGTERM);
        waitpid(*pid, NULL, 0);
        *pid = 0;
    }
}

#endif
