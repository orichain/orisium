#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <string.h>      // for memset, strncpy
#include <fcntl.h>       // for fcntl, F_GETFL, F_SETFL, O_NONBLOCK
#include <stdint.h>    // for uint64_t
#include <time.h>     // for timespec

#include "log.h"
#include "types.h"

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

void sleep_ns(long nanoseconds) {
    struct timespec ts;
    ts.tv_sec = nanoseconds / 1000000000L;
    ts.tv_nsec = nanoseconds % 1000000000L;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
        // Retry if interrupted
    }
}

void sleep_us(long microseconds) {
    sleep_ns(microseconds * 1000L);
}

void sleep_ms(long milliseconds) {
    sleep_ns(milliseconds * 1000000L);
}

void sleep_s(double seconds) {
    long ns = (long)(seconds * 1000000000.0);
    sleep_ns(ns);
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
