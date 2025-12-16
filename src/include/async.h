#ifndef ASYNC_H
#define ASYNC_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef __NetBSD__
    #include <sys/types.h>
    #include <sys/event.h>
    #include <sys/time.h>
    #include <sys/eventfd.h>
    #include <sys/timerfd.h>
    #include <time.h>
    #include <fcntl.h>
#else
    #include <sys/epoll.h>
    #include <sys/eventfd.h>
    #include <sys/timerfd.h>
    #include <time.h>
#endif

#include "constants.h"
#include "log.h"
#include "types.h"

#ifdef __NetBSD__
    typedef struct {
        int async_fd;
        struct kevent event_change[2];
        struct kevent events[MAX_EVENTS];
    } async_type_t;
    
    #define ASYNC_EPOLLIN_FLAG  (1 << 0)
    #define ASYNC_EPOLLOUT_FLAG (1 << 1)
    #define ASYNC_EPOLLHUP_FLAG (1 << 2)
    #define ASYNC_EPOLLERR_FLAG (1 << 3)
    #define ASYNC_EPOLLRDHUP_FLAG (1 << 4)
#else
    typedef struct {
        int async_fd;
        struct epoll_event event;
        struct epoll_event events[MAX_EVENTS];
    } async_type_t;
#endif

#ifdef __NetBSD__
    static inline bool async_event_is_EPOLLHUP(uint32_t events_flags) {
        return events_flags & ASYNC_EPOLLHUP_FLAG;
    }
    static inline bool async_event_is_EPOLLERR(uint32_t events_flags) {
        return events_flags & ASYNC_EPOLLERR_FLAG;
    }
    static inline bool async_event_is_EPOLLRDHUP(uint32_t events_flags) {
        return events_flags & ASYNC_EPOLLRDHUP_FLAG;
    }
    static inline bool async_event_is_EPOLLIN(uint32_t events_flags) {
        return events_flags & ASYNC_EPOLLIN_FLAG;
    }
    static inline bool async_event_is_EPOLLOUT(uint32_t events_flags) {
        return events_flags & ASYNC_EPOLLOUT_FLAG;
    }
#else
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
#endif

static inline int_status_t async_getfd(const char* label, async_type_t *async, int n) {
    int_status_t result;
    result.r_int = -1;
    if (n < 0 || n >= MAX_EVENTS) {
        LOG_ERROR("%sOOIDX", label);
        result.status = FAILURE_OOIDX;
        return result;
    }
#ifdef __NetBSD__
    result.r_int = (int)async->events[n].ident;
#else
    result.r_int = async->events[n].data.fd;
#endif
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
    if (n < 0 || n >= MAX_EVENTS) {
        LOG_ERROR("%sOOIDX", label);
        result.status = FAILURE_OOIDX;
        return result;
    }
#ifdef __NetBSD__
    if (async->events[n].filter == EVFILT_READ) {
        result.r_uint32_t |= ASYNC_EPOLLIN_FLAG;
    }
    if (async->events[n].filter == EVFILT_WRITE) {
        result.r_uint32_t |= ASYNC_EPOLLOUT_FLAG;
    }
    if (async->events[n].flags & EV_EOF) {
        result.r_uint32_t |= ASYNC_EPOLLHUP_FLAG | ASYNC_EPOLLRDHUP_FLAG;
    }
    if (async->events[n].flags & EV_ERROR) {
        result.r_uint32_t |= ASYNC_EPOLLERR_FLAG;
    }
#else
    result.r_uint32_t = async->events[n].events;
#endif
    result.status = SUCCESS;
    return result;
}

static inline int_status_t async_wait(const char* label, async_type_t *async) {
    int_status_t result;
    result.r_int = -1;
#ifdef __NetBSD__
    struct timespec *timeout = NULL;
    result.r_int = kevent(async->async_fd, NULL, 0, async->events, MAX_EVENTS, timeout);
#else
    result.r_int = epoll_wait(async->async_fd, async->events, MAX_EVENTS, -1);
#endif
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
#ifdef __NetBSD__
    async->async_fd = kqueue();
    if (async->async_fd == -1) {
        LOG_ERROR("%sGagal membuat kqueue fd: %s", label, strerror(errno));
        return FAILURE;
    }
#else
    async->async_fd = epoll_create1(0);
    if (async->async_fd == -1) {
        LOG_ERROR("%sGagal membuat epoll fd: %s", label, strerror(errno));
        return FAILURE;
    }
#endif
    LOG_DEBUG("%sBerhasil membuat async fd %d", label, async->async_fd);
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
#ifdef __NetBSD__
    *timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (*timer_fd == -1) {
        LOG_ERROR("%sGagal membuat timerfd: %s", label, strerror(errno));
        return FAILURE;
    }
    if (fcntl(*timer_fd, F_SETFL, fcntl(*timer_fd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        LOG_WARN("%sGagal set timerfd ke non-blocking: %s", label, strerror(errno));
    }
#else
    *timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (*timer_fd == -1) {
        LOG_ERROR("%sGagal membuat timerfd: %s", label, strerror(errno));
        return FAILURE;
    }
#endif
    return SUCCESS;
}

static inline status_t async_set_timerfd_time(const char* label, int *timer_fd,
    time_t initial_sec, long initial_nsec,
    time_t interval_sec, long interval_nsec
)
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

static inline status_t
async_create_incoming_event(const char* label,
                            async_type_t *async,
                            int *fd)
{
#ifdef __NetBSD__
    EV_SET(&async->event_change[0], *fd,
           EVFILT_READ,
           EV_ADD | EV_ENABLE | EV_CLEAR,
           0, 0, NULL);
    if (kevent(async->async_fd,
               &async->event_change[0], 1,
               NULL, 0, NULL) == -1) {
        LOG_ERROR("%skqueue READ add failed: %s",
                  label, strerror(errno));
        return FAILURE;
    }
#else
    async->event.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
    async->event.data.fd = *fd;

    if (epoll_ctl(async->async_fd,
                   EPOLL_CTL_ADD,
                   *fd,
                   &async->event) == -1) {
        LOG_ERROR("%sepoll add failed: %s",
                  label, strerror(errno));
        return FAILURE;
    }
#endif
    return SUCCESS;
}

static inline status_t async_delete_event(const char* label, async_type_t *async, int *fd_to_delete) {
    if (*fd_to_delete != -1) {
#ifdef __NetBSD__
        struct kevent *ch = async->event_change;
        EV_SET(&ch[0], *fd_to_delete, EVFILT_READ,  EV_DELETE, 0, 0, NULL);
        EV_SET(&ch[1], *fd_to_delete, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        if (kevent(async->async_fd, ch, 2, NULL, 0, NULL) == -1) {
            LOG_DEBUG("%sGagal menghapus event (mungkin sudah ditutup): %s",
                      label, strerror(errno));
        }
#else
        if (epoll_ctl(async->async_fd, EPOLL_CTL_DEL, *fd_to_delete, NULL) == -1) {
            LOG_ERROR("%s%s", label, strerror(errno));
            return FAILURE;
        }
#endif
    }
    return SUCCESS;
}

#endif
