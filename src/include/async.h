#ifndef ASYNC_H
#define ASYNC_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __NetBSD__
    #include <sys/errno.h>
    #include <sys/event.h>
    #include <sys/time.h>

    #include "utilities.h"
#else
    #include <sys/epoll.h>
#endif

#include "constants.h"
#include "log.h"
#include "types.h"
#include "oritlsf.h"

#ifdef __NetBSD__
    typedef struct {
        int async_fd;
        struct kevent event_change[2];
        struct kevent events[MAX_EVENTS];
    } async_type_t;
    
    #define ASYNC_IN_FLAG  (1 << 0)
    #define ASYNC_OUT_FLAG (1 << 1)
    #define ASYNC_HUP_FLAG (1 << 2)
    #define ASYNC_ERR_FLAG (1 << 3)
    #define ASYNC_RDHUP_FLAG (1 << 4)
#else
    typedef struct {
        int async_fd;
        struct epoll_event event;
        struct epoll_event events[MAX_EVENTS];
    } async_type_t;
#endif

#ifdef __NetBSD__
    static inline bool async_event_is_HUP(uint32_t events_flags) {
        return events_flags & ASYNC_HUP_FLAG;
    }
    static inline bool async_event_is_ERR(uint32_t events_flags) {
        return events_flags & ASYNC_ERR_FLAG;
    }
    static inline bool async_event_is_RDHUP(uint32_t events_flags) {
        return events_flags & ASYNC_RDHUP_FLAG;
    }
    static inline bool async_event_is_IN(uint32_t events_flags) {
        return events_flags & ASYNC_IN_FLAG;
    }
    static inline bool async_event_is_OUT(uint32_t events_flags) {
        return events_flags & ASYNC_OUT_FLAG;
    }
#else
    static inline bool async_event_is_HUP(uint32_t events) {
        return events & EPOLLHUP;
    }
    static inline bool async_event_is_ERR(uint32_t events) {
        return events & EPOLLERR;
    }
    static inline bool async_event_is_RDHUP(uint32_t events) {
        return events & EPOLLRDHUP;
    }
    static inline bool async_event_is_IN(uint32_t events) {
        return events & EPOLLIN;
    }
    static inline bool async_event_is_OUT(uint32_t events) {
        return events & EPOLLOUT;
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
        result.r_uint32_t |= ASYNC_IN_FLAG;
    }
    if (async->events[n].filter == EVFILT_WRITE) {
        result.r_uint32_t |= ASYNC_OUT_FLAG;
    }
    if (async->events[n].flags & EV_EOF) {
        result.r_uint32_t |= ASYNC_HUP_FLAG | ASYNC_RDHUP_FLAG;
    }
    if (async->events[n].flags & EV_ERROR) {
        result.r_uint32_t |= ASYNC_ERR_FLAG;
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
    if (set_nonblocking(label, *timer_fd) != SUCCESS) {
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

static inline status_t async_create_in_event(
    const char* label,
    async_type_t *async,
    int *fd
)
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

static inline status_t async_create_inout_event(
    const char* label,
    async_type_t *async,
    int *fd
)
{
#ifdef __NetBSD__
    EV_SET(&async->event_change[0], *fd,
            EVFILT_READ,
            EV_ADD | EV_ENABLE | EV_CLEAR,
            0, 0, NULL);
    EV_SET(&async->event_change[1], *fd,
            EVFILT_WRITE,
            EV_ADD | EV_ENABLE | EV_CLEAR,
            0, 0, NULL);
    if (kevent(async->async_fd,
                async->event_change, 2,
                NULL, 0, NULL) == -1) {
        LOG_ERROR("%skqueue READ/WRITE add failed: %s", label, strerror(errno));
        return FAILURE;
    }
#else
    async->event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
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

static inline status_t async_create_timer_oneshot(const char* label, async_type_t *async , int *file_descriptor, double timer_interval) {
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
        if (async_create_in_event(label, async, file_descriptor) != SUCCESS) {
            return FAILURE;
        }
    }
    return SUCCESS;
}

static inline status_t async_update_timer_oneshot(const char* label, int *file_descriptor, double timer_interval) {
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

static inline et_result_t async_write_event(oritlsf_pool_t *oritlsf_pool, et_buffered_fd_t *et_buffered_fd, bool on_out_ready) {
    et_result_t wetr;
    wetr.failure = false;
    wetr.partial = true;
    wetr.status = FAILURE;
    if (on_out_ready && et_buffered_fd->buffer->out_size_tb == 0) {
        wetr.failure = false;
        wetr.partial = false;
        wetr.status = SUCCESS;
        return wetr;
    }
    if (!on_out_ready) {
        uint64_t u = 1ULL;
        if (et_buffered_fd->buffer->out_size_tb == 0) {
            et_buffered_fd->buffer->out_size_tb = sizeof(uint64_t);
            et_buffered_fd->buffer->buffer_out = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, 
                oritlsf_pool,
                et_buffered_fd->buffer->out_size_tb,
                sizeof(uint8_t)
            );
            if (!et_buffered_fd->buffer->buffer_out) {
                et_buffered_fd->buffer->out_size_tb = 0;
                et_buffered_fd->buffer->out_size_c = 0;
                wetr.failure = true;
                wetr.partial = true;
                wetr.status = FAILURE_NOMEM;
                return wetr;
            }
            memcpy(et_buffered_fd->buffer->buffer_out, &u, sizeof(uint64_t));
        } else {
            ssize_t old_out_size_tb = et_buffered_fd->buffer->out_size_tb;
            et_buffered_fd->buffer->out_size_tb += sizeof(uint64_t);
            et_buffered_fd->buffer->buffer_out = (uint8_t *)oritlsf_realloc(__FILE__, __LINE__, 
                oritlsf_pool,
                et_buffered_fd->buffer->buffer_out,
                et_buffered_fd->buffer->out_size_tb * sizeof(uint8_t)
            );
            if (!et_buffered_fd->buffer->buffer_out) {
                et_buffered_fd->buffer->out_size_tb = 0;
                et_buffered_fd->buffer->out_size_c = 0;
                wetr.failure = true;
                wetr.partial = true;
                wetr.status = FAILURE_NOMEM;
                return wetr;
            }
            memcpy(et_buffered_fd->buffer->buffer_out + old_out_size_tb, &u, sizeof(uint64_t));
        }
    }
    while (true) {
        ssize_t wsize = write(et_buffered_fd->fd, et_buffered_fd->buffer->buffer_out + et_buffered_fd->buffer->out_size_c, et_buffered_fd->buffer->out_size_tb - et_buffered_fd->buffer->out_size_c);
        if (wsize < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (et_buffered_fd->buffer->out_size_tb == et_buffered_fd->buffer->out_size_c) {
                    wetr.failure = false;
                    wetr.partial = false;
                    wetr.status = SUCCESS_EAGNEWBLK;
                } else {
                    wetr.failure = false;
                    wetr.partial = true;
                    wetr.status = FAILURE_EAGNEWBLK;
                }
                break;
            } else {
                oritlsf_free(oritlsf_pool, (void **)&et_buffered_fd->buffer->buffer_out);
                et_buffered_fd->buffer->out_size_tb = 0;
                et_buffered_fd->buffer->out_size_c = 0;
                wetr.failure = true;
                wetr.partial = true;
                wetr.status = FAILURE;
                break;
            }
        } 
        if (wsize > 0) {
            et_buffered_fd->buffer->out_size_c += wsize;
        }
        if (wsize == 0) {
            oritlsf_free(oritlsf_pool, (void **)&et_buffered_fd->buffer->buffer_out);
            et_buffered_fd->buffer->out_size_tb = 0;
            et_buffered_fd->buffer->out_size_c = 0;
            wetr.failure = true;
            wetr.partial = true;
            wetr.status = FAILURE;
            break;
        }
        if (et_buffered_fd->buffer->out_size_tb == et_buffered_fd->buffer->out_size_c) {
            wetr.failure = false;
            wetr.partial = false;
            wetr.status = SUCCESS;
            break;
        }
    }
    return wetr;
}

static inline et_result_t async_read_event(oritlsf_pool_t *oritlsf_pool, et_buffered_fd_t *et_buffered_fd) {
    et_result_t retr;
    retr.failure = false;
    retr.partial = true;
    retr.status = FAILURE;
    if (et_buffered_fd->buffer->in_size_tb == 0) {
        et_buffered_fd->buffer->in_size_tb = sizeof(uint64_t);
        et_buffered_fd->buffer->buffer_in = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, 
            oritlsf_pool,
            et_buffered_fd->buffer->in_size_tb,
            sizeof(uint8_t)
        );
        if (!et_buffered_fd->buffer->buffer_in) {
            et_buffered_fd->buffer->read_step = 0;
            et_buffered_fd->buffer->out_size_tb = 0;
            et_buffered_fd->buffer->out_size_c = 0;
            retr.failure = true;
            retr.partial = true;
            retr.status = FAILURE_NOMEM;
            return retr;
        }
    }
    while (true) {
        ssize_t rsize = read(et_buffered_fd->fd, et_buffered_fd->buffer->buffer_in + et_buffered_fd->buffer->in_size_c, et_buffered_fd->buffer->in_size_tb-et_buffered_fd->buffer->in_size_c);
        if (rsize < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (et_buffered_fd->buffer->in_size_tb == et_buffered_fd->buffer->in_size_c) {
                    retr.failure = false;
                    retr.partial = false;
                    retr.status = SUCCESS_EAGNEWBLK;
                } else {
                    retr.failure = false;
                    retr.partial = true;
                    retr.status = FAILURE_EAGNEWBLK;
                }
                break;
            } else {
                oritlsf_free(oritlsf_pool, (void **)&et_buffered_fd->buffer->buffer_in);
                et_buffered_fd->buffer->read_step = 0;
                et_buffered_fd->buffer->in_size_tb = 0;
                et_buffered_fd->buffer->in_size_c = 0;
                retr.failure = true;
                retr.partial = true;
                retr.status = FAILURE;
                break;
            }
        } 
        if (rsize > 0) {
            et_buffered_fd->buffer->in_size_c += rsize;
        }
        if (rsize == 0) {
            oritlsf_free(oritlsf_pool, (void **)&et_buffered_fd->buffer->buffer_in);
            et_buffered_fd->buffer->read_step = 0;
            et_buffered_fd->buffer->in_size_tb = 0;
            et_buffered_fd->buffer->in_size_c = 0;
            retr.failure = true;
            retr.partial = true;
            retr.status = FAILURE;
            break;
        }
        if (et_buffered_fd->buffer->in_size_tb == et_buffered_fd->buffer->in_size_c) {
            retr.failure = false;
            retr.partial = false;
            retr.status = SUCCESS;
            break;
        }
    }
    return retr;
}

#endif
