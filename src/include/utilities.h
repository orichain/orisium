#ifndef UTILITIES_H
#define UTILITIES_H

#include <aes.h>
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <fips202.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <randombytes.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
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

#include "async.h"
#include "constants.h"
#include "log.h"
#include "poly1305-donna.h"
#include "pqc.h"
#include "types.h"
#include "oritlsf.h"

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

static inline status_t create_timer_oneshot(const char* label, async_type_t *async , int *file_descriptor, double timer_interval) {
    bool closed = (*file_descriptor == -1);
    if (closed) {
        if (async_create_timerfd(label, file_descriptor) != SUCCESS) {
            return FAILURE;
        }
    }
    if (async_set_timerfd_time(label, file_descriptor,
        (time_t)timer_interval,
        (long)((timer_interval - (time_t)timer_interval) * 1e9),
        (time_t)0,
        (long)0) != SUCCESS)
    {
        return FAILURE;
    }
    if (closed) {
        if (async_create_incoming_event(label, async, file_descriptor) != SUCCESS) {
            return FAILURE;
        }
    }
    return SUCCESS;
}

static inline status_t update_timer_oneshot(const char* label, int *file_descriptor, double timer_interval) {
    if (async_set_timerfd_time(label, file_descriptor,
        (time_t)timer_interval,
        (long)((timer_interval - (time_t)timer_interval) * 1e9),
        (time_t)0,
        (long)0) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
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
    uint8_t *keystream_buffer = (uint8_t *)oritlsf_calloc(pool, 1, data_len);
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
    uint8_t *keystream_buffer = (uint8_t *)oritlsf_calloc(pool, 1, data_len);
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
    double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * JITTER_PERCENTAGE * 2) - JITTER_PERCENTAGE;
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

static inline void kdf1(uint8_t *key, uint8_t *key_deriv) {
    shake256(key_deriv, HASHES_BYTES, key, KEM_SHAREDSECRET_BYTES);
}

static inline void kdf2(uint8_t *key, uint8_t *key_deriv) {
    shake256(key_deriv, HASHES_BYTES, key, HASHES_BYTES);
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
