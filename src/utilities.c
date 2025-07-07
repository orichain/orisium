#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <string.h>      // for memset, strncpy
#include <fcntl.h>       // for fcntl, F_GETFL, F_SETFL, O_NONBLOCK
#include <stdint.h>    // for uint64_t
#include <time.h>     // for timespec
#include <math.h>
#include <stdio.h>

#include "log.h"
#include "types.h"

void print_hex(const char* label, const uint8_t* data, size_t len, int uppercase) {
    if (label)
        printf("%s", label);

    const char* fmt = uppercase ? "%02X" : "%02x";

    for (size_t i = 0; i < len; ++i) {
        printf(fmt, data[i]);
    }
    printf("\n");
}

status_t set_nonblocking(const char* label, int fd) {
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

status_t sleep_ns(long nanoseconds) {
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

status_t sleep_us(long microseconds) {
    return sleep_ns(microseconds * 1000L);
}

status_t sleep_ms(long milliseconds) {
    return sleep_ns(milliseconds * 1000000L);
}

status_t sleep_s(double seconds) {
    long ns = (long)(fmin(seconds, 60 * 60 * 24) * 1e9);
    return sleep_ns(ns);
}

uint64_t_status_t get_realtime_time_ns(const char *label) {
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
