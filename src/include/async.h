#ifndef ASYNC_H
#define ASYNC_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <time.h>

#include "async.h"
#include "constants.h"
#include "log.h"
#include "types.h"

typedef struct {
    int async_fd;
    struct epoll_event event;
    struct epoll_event events[MAX_EVENTS];
} async_type_t;

static inline bool async_event_is_EPOLLHUP(uint32_t events) {
	return events & EPOLLHUP;
}

static inline bool async_event_is_EPOLLERR(uint32_t events) {
	return events & EPOLLERR;
}

static inline bool async_event_is_EPOLLRDHUP(uint32_t events) {
	return events & EPOLLRDHUP;
}

static inline bool async_event_is_EPOLLIN(uint32_t events) {
	return events & EPOLLIN;
}

static inline bool async_event_is_EPOLLOUT(uint32_t events) {
	return events & EPOLLOUT;
}

static inline bool async_event_is_EPOLLET(uint32_t events) {
	return events & EPOLLET;
}

static inline int_status_t async_getfd(const char* label, async_type_t *async, int n) {
	int_status_t result;
	result.r_int = -1;
	if (n < 0 || n > MAX_EVENTS) {
		LOG_ERROR("%sOOIDX", label);
		result.status = FAILURE_OOIDX;
		return result;
	}
	result.r_int = async->events[n].data.fd;
	if (result.r_int == -1) {
		LOG_ERROR("%sfd sudah tidak valid, mungkin sudah diubah dari tempat lain. (Mis. oprasi pointer).", label);
		result.status = FAILURE;
		return result;
	}
	result.status = SUCCESS;
	return result;
}

static inline uint32_t_status_t async_getevents(const char* label, async_type_t *async, int n) {
	uint32_t_status_t result;
	result.r_uint32_t = 0;
	if (n < 0 || n > MAX_EVENTS) {
		LOG_ERROR("%sOOIDX", label);
		result.status = FAILURE_OOIDX;
		return result;
	}
	result.r_uint32_t = async->events[n].events;
	result.status = SUCCESS;
	return result;
}

static inline int_status_t async_wait(const char* label, async_type_t *async) {
    int_status_t result;
    result.r_int = epoll_wait(async->async_fd, async->events, MAX_EVENTS, -1);
    if (result.r_int == -1) {
        if (errno == EINTR) {
            result.status = FAILURE_EINTR;
            return result;
        } else if (errno == EBADF) {
            result.status = FAILURE_EBADF;
            LOG_ERROR("%sEBADF %s", label, strerror(errno));
            return result;
        }
        LOG_ERROR("%s%s", label, strerror(errno));
        result.status = FAILURE;
        return result;
    }
    result.status = SUCCESS;
    return result;
}

static inline status_t async_create(const char* label, async_type_t *async) {
    async->async_fd = epoll_create1(0);
    if (async->async_fd == -1) {
        LOG_ERROR("%sGagal membuat epoll fd: %s", label, strerror(errno));
        return FAILURE;
    }
    LOG_DEBUG("%sBerhasil membuat epoll fd %d", label, async->async_fd);
    return SUCCESS;
}

static inline status_t async_create_event(const char* label, int *event_fd) {
    *event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (*event_fd == -1) {
        LOG_ERROR("%sGagal membuat eventfd: %s", label, strerror(errno));
        return FAILURE;
    }
    LOG_DEBUG("%sBerhasil membuat event fd %d", label, *event_fd);
    return SUCCESS;
}

static inline status_t async_create_timerfd(const char* label, int *timer_fd) {
    *timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (*timer_fd == -1) {
        LOG_ERROR("%sGagal membuat timerfd: %s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

static inline status_t async_set_timerfd_time(const char* label, int *timer_fd,
	time_t initial_sec, long initial_nsec,
	time_t interval_sec, long interval_nsec)
{
    struct itimerspec new_value;
    new_value.it_value.tv_sec = initial_sec;
    new_value.it_value.tv_nsec = initial_nsec;
    new_value.it_interval.tv_sec = interval_sec;
    new_value.it_interval.tv_nsec = interval_nsec;
    if (timerfd_settime(*timer_fd, 0, &new_value, NULL) == -1) {
        LOG_ERROR("%sGagal set time timerfd (FD %d): %s", label, *timer_fd, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

static inline status_t async_create_incoming_event(const char* label, async_type_t *async, int *fd_to_add) {
    async->event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    async->event.data.fd = *fd_to_add;
    if (epoll_ctl(async->async_fd, EPOLL_CTL_ADD, *fd_to_add, &async->event) == -1) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

static inline status_t async_delete_event(const char* label, async_type_t *async, int *fd_to_delete) {
	if (*fd_to_delete != -1) {
		if (epoll_ctl(async->async_fd, EPOLL_CTL_DEL, *fd_to_delete, NULL) == -1) {
			LOG_ERROR("%s%s", label, strerror(errno));
			return FAILURE;
		}
	}
	return SUCCESS;
}

#endif
