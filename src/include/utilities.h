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

#include "log.h"
#include "types.h"
#include "constants.h"

static inline void print_hex(const char* label, const uint8_t* data, size_t len, int uppercase) {
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

static inline status_t convert_str_to_ipv6_bin(const char *ip_str, uint8_t out_ipv6[IP_ADDRESS_LEN]) {
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (inet_pton(AF_INET6, ip_str, &ipv6) == 1) {
        memcpy(out_ipv6, &ipv6, IP_ADDRESS_LEN);
        return SUCCESS;
    }
    if (inet_pton(AF_INET, ip_str, &ipv4) == 1) {
        memset(out_ipv6, 0, 10);
        out_ipv6[10] = 0xff;
        out_ipv6[11] = 0xff;
        memcpy(&out_ipv6[12], &ipv4, 4);
        return SUCCESS;
    }
    return FAILURE;
}

static inline status_t convert_ipv6_bin_to_str(const uint8_t in_ipv6[IP_ADDRESS_LEN], char out_ip_str[INET6_ADDRSTRLEN]) {
    static const uint8_t prefix_ipv4_mapped[12] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0xff, 0xff
    };
    
    if (memcmp(in_ipv6, prefix_ipv4_mapped, 12) == 0) {
        struct in_addr ipv4_part;
        memcpy(&ipv4_part, &in_ipv6[12], 4);
        if (inet_ntop(AF_INET, &ipv4_part, out_ip_str, INET6_ADDRSTRLEN) != NULL) {
			return SUCCESS;
		} else {
			return FAILURE;
		}
    } else {
        struct in6_addr ipv6;
        memcpy(&ipv6, in_ipv6, 16);
        if (inet_ntop(AF_INET6, &ipv6, out_ip_str, INET6_ADDRSTRLEN) != NULL) {
			return SUCCESS;
		} else {
			return FAILURE;
		}
    }
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
