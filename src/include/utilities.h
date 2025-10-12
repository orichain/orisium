#ifndef UTILITIES_H
#define UTILITIES_H

#include <unistd.h>
#include <sys/wait.h>
#include <stddef.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <endian.h>
#include <common/randombytes.h>
#include <common/fips202.h>
#include "log.h"
#include "types.h"
#include "constants.h"
#include "pqc.h"

static inline bool is_same_ctr(uint32_t *ctr1, uint8_t *nonce1, uint32_t *ctr2, uint8_t *nonce2) {
    if (*ctr1 != *ctr2) {
        return false;
    }
    if (memcmp(nonce1, nonce2, AES_NONCE_BYTES) != 0) {
        return false;
    }
    return true;
}

static inline void increment_ctr(uint32_t *ctr, uint8_t *nonce) {
    if (*ctr == 0xFFFFFFFFUL) {
        *ctr = 0;
        uint8_t carry = 1;
        for (int i = 11; i >= 0; i--) {
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

static inline void decrement_ctr(uint32_t *ctr, uint8_t *nonce) {
    if (*ctr == 0) {
        *ctr = 0xFFFFFFFFUL;
        uint8_t borrow = 1;
        for (int i = 11; i >= 0; i--) {
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

static inline bool is_1greater_ctr(uint32_t *ctr1, uint32_t *ctr2, uint8_t *nonce2) {
    uint8_t *tmp_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    if (!tmp_nonce) {
        false;
        return FAILURE_NOMEM;
    }
    memcpy(tmp_nonce, nonce2, AES_NONCE_BYTES);
    uint32_t tmp_ctr = *ctr2;
    increment_ctr(&tmp_ctr, tmp_nonce);
    bool isgtr = (*ctr1 == tmp_ctr);
    memset(tmp_nonce, 0, AES_NONCE_BYTES);
    free(tmp_nonce);
    return isgtr;
}

static inline bool is_1lower_equal_ctr(uint32_t *ctr1, uint32_t *ctr2, uint8_t *nonce2) {
    if (*ctr1 == *ctr2) {
        return true;
    }
    uint8_t *tmp_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    if (!tmp_nonce) {
        false;
        return FAILURE_NOMEM;
    }
    memcpy(tmp_nonce, nonce2, AES_NONCE_BYTES);
    uint32_t tmp_ctr = *ctr2;
    decrement_ctr(&tmp_ctr, tmp_nonce);
    bool islwr = (*ctr1 == tmp_ctr);
    memset(tmp_nonce, 0, AES_NONCE_BYTES);
    free(tmp_nonce);
    return islwr;
}

static inline bool is_1lower_ctr(uint32_t *ctr1, uint32_t *ctr2, uint8_t *nonce2) {
    uint8_t *tmp_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    if (!tmp_nonce) {
        false;
        return FAILURE_NOMEM;
    }
    memcpy(tmp_nonce, nonce2, AES_NONCE_BYTES);
    uint32_t tmp_ctr = *ctr2;
    decrement_ctr(&tmp_ctr, tmp_nonce);
    bool islwr = (*ctr1 == tmp_ctr);
    memset(tmp_nonce, 0, AES_NONCE_BYTES);
    free(tmp_nonce);
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
    if (randombytes(out_nonce, 12) != 0) {
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

static inline void print_hexx(const char* label, const uint8_t* data, size_t len, int uppercase) {
    if (label)
        printf("%s", label);

    const char* fmt = uppercase ? "%02X" : "%02x";

    for (size_t i = 0; i < len; ++i) {
        printf(fmt, data[i]);
    }
    printf("\n");
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
/*
static inline uint64_t_status_t get_realtime_time_ns(const char *label) {
	uint64_t_status_t result;
	result.status = FAILURE;
	result.r_uint64_t = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return result;
    }
    result.r_uint64_t = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    result.status = SUCCESS;
    return result;
}
*/
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
