#ifndef ASYNC_H
#define ASYNC_H

#include "constants.h"
#include "log.h"
#include "oritlsf.h"
#include "types.h"
#include "utilities.h"
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/event.h>
#include <unistd.h>

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
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

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
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
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
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
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
    if (
            async->events[n].filter == EVFILT_READ ||
            async->events[n].filter == EVFILT_USER ||
            async->events[n].filter == EVFILT_TIMER
       )
    {
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
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
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
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
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

static inline status_t async_create_event(const char* label, int *event_fd, event_type_t event_type) {
    if (event_type == EIT_FD) {
#if !defined(__NetBSD__) && !defined(__OpenBSD__) && !defined(__FreeBSD__)
        *event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (*event_fd == -1) {
            LOG_ERROR("%sGagal membuat eventfd: %s", label, strerror(errno));
            return FAILURE;
        }
        LOG_DEBUG("%sBerhasil membuat eventfd %d", label, *event_fd);
#else
        return FAILURE;
#endif
    } else {
        *event_fd = GENERATE_EVENT_ID();
        if (*event_fd == -1) {
            LOG_ERROR("%sGagal membuat eventfd", label);
            return FAILURE;
        }
        LOG_DEBUG("%sBerhasil membuat eventfd %d", label, *event_fd);
    }
    return SUCCESS;
}

static inline status_t async_create_timerfd(const char* label, int *timer_fd, event_type_t event_type) {
    if (event_type == EIT_FD) {
#if !defined(__NetBSD__) && !defined(__OpenBSD__) && !defined(__FreeBSD__)
        *timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (*timer_fd == -1) {
            LOG_ERROR("%sGagal membuat timerfd: %s", label, strerror(errno));
            return FAILURE;
        }
#else
        return FAILURE;
#endif
    } else {
        *timer_fd = GENERATE_EVENT_ID();
        if (*timer_fd == -1) {
            LOG_ERROR("%sGagal membuat timerfd", label);
            return FAILURE;
        }
    }
    return SUCCESS;
}

static inline status_t async_set_timerfd_time(const char* label, int *timer_fd,
        time_t initial_sec, long initial_nsec,
        time_t interval_sec, long interval_nsec
        )
{
#if !defined(__NetBSD__) && !defined(__OpenBSD__) && !defined(__FreeBSD__)
    struct itimerspec new_value;
    new_value.it_value.tv_sec = initial_sec;
    new_value.it_value.tv_nsec = initial_nsec;
    new_value.it_interval.tv_sec = interval_sec;
    new_value.it_interval.tv_nsec = interval_nsec;
    if (timerfd_settime(*timer_fd, 0, &new_value, NULL) == -1) {
        LOG_ERROR("%sGagal set time timerfd (FD %d): %s", label, *timer_fd, strerror(errno));
        return FAILURE;
    }
#else
    return FAILURE;
#endif
    return SUCCESS;
}

static inline status_t async_create_in_event(
        const char* label,
        async_type_t *async,
        int *fd
        )
{
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
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
        int *fd,
        event_type_t event_type
        )
{
    if (event_type == EIT_FD) {
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
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
    } else {
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
        EV_SET(&async->event_change[0], *fd,
                EVFILT_USER,
                EV_ADD | EV_ENABLE | EV_CLEAR,
                0, 0, NULL);
        if (kevent(async->async_fd,
                    async->event_change, 1,
                    NULL, 0, NULL) == -1) {
            LOG_ERROR("%skqueue USER add failed: %s", label, strerror(errno));
            return FAILURE;
        }
#else
        return FAILURE;
#endif
    }
    return SUCCESS;
}

static inline status_t async_delete_event(const char* label, async_type_t *async, int *fd_to_delete, event_type_t event_type) {
    if (*fd_to_delete != -1) {
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
        struct kevent *ch = async->event_change;
        int chc = 1;
        switch (event_type) {
            case EIT_USER: {
                               EV_SET(&ch[0], *fd_to_delete, EVFILT_USER, EV_DELETE, 0, 0, NULL);
                               chc = 1;
                               break;
                           }
            case EIT_TIMER: {
                                EV_SET(&ch[0], *fd_to_delete, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
                                chc = 1;
                                break;
                            }
            default:
                            EV_SET(&ch[0], *fd_to_delete, EVFILT_READ,  EV_DELETE, 0, 0, NULL);
                            EV_SET(&ch[1], *fd_to_delete, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
                            chc = 2;
        }
        if (kevent(async->async_fd, ch, chc, NULL, 0, NULL) == -1) {
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

static inline status_t async_create_timer_oneshot(const char* label, async_type_t *async , int *file_descriptor, double timer_interval, event_type_t event_type) {
    bool closed = (*file_descriptor == -1);
    if (closed) {
        if (async_create_timerfd(label, file_descriptor, event_type) != SUCCESS) {
            return FAILURE;
        }
    }
    if (event_type == EIT_FD) {
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
    } else {
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
        if (timer_interval <= (double)0.00000001) {
            async_delete_event(label, async, file_descriptor, event_type);
            return SUCCESS;
        }
        uint64_t timeout_ns = (int64_t)(timer_interval * 1000000000.0);
        EV_SET(&async->event_change[0], *file_descriptor,
                EVFILT_TIMER,
                EV_ADD | EV_ENABLE | EV_ONESHOT,
                NOTE_NSECONDS, timeout_ns, NULL);
        if (kevent(async->async_fd,
                    &async->event_change[0], 1,
                    NULL, 0, NULL) == -1) {
            LOG_ERROR("%skqueue TIMER add failed: %s",
                    label, strerror(errno));
            return FAILURE;
        }
#else
        return FAILURE;
#endif
    }
    return SUCCESS;
}

static inline status_t async_update_timer_oneshot(const char* label, async_type_t *async, int *file_descriptor, double timer_interval, event_type_t event_type) {
    if (event_type == EIT_FD) {
        if (async_set_timerfd_time(label, file_descriptor,
                    (time_t)timer_interval,
                    (long)((timer_interval - (time_t)timer_interval) * 1e9),
                    (time_t)0,
                    (long)0) != SUCCESS)
        {
            return FAILURE;
        }
    } else {
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
        if (timer_interval <= (double)0.00000001) {
            async_delete_event(label, async, file_descriptor, event_type);
            return SUCCESS;
        }
        uint64_t timeout_ns = (int64_t)(timer_interval * 1000000000.0);
        EV_SET(&async->event_change[0], *file_descriptor,
                EVFILT_TIMER,
                EV_ADD | EV_ENABLE | EV_ONESHOT,
                NOTE_NSECONDS, timeout_ns, NULL);
        if (kevent(async->async_fd,
                    &async->event_change[0], 1,
                    NULL, 0, NULL) == -1) {
            LOG_ERROR("%skqueue TIMER add failed: %s",
                    label, strerror(errno));
            return FAILURE;
        }
#else
        return FAILURE;
#endif
    }
    return SUCCESS;
}

static inline et_result_t async_write_event(oritlsf_pool_t *oritlsf_pool, async_type_t *async, et_buffered_event_id_t *et_buffered_event_id, bool on_out_ready) {
    et_result_t wetr;
    wetr.failure = false;
    wetr.partial = true;
    wetr.event_type = et_buffered_event_id->event_type;
    wetr.status = FAILURE;

    if (wetr.event_type == EIT_USER) {
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
        EV_SET(&async->event_change[0], et_buffered_event_id->event_id, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
        if (kevent(async->async_fd, &async->event_change[0], 1, NULL, 0, NULL) == -1) {
            wetr.failure = true;
            wetr.partial = true;
            wetr.status = FAILURE;
            return wetr;
        }
        wetr.failure = false;
        wetr.partial = false;
        wetr.status = SUCCESS;
#else
        wetr.failure = true;
        wetr.partial = true;
        wetr.status = FAILURE;
        return wetr;
#endif
    } else {
        if (on_out_ready && et_buffered_event_id->buffer->out_size_tb == 0) {
            wetr.failure = false;
            wetr.partial = false;
            wetr.status = SUCCESS;
            return wetr;
        }
        if (!on_out_ready) {
            uint64_t u = 1ULL;
            if (et_buffered_event_id->buffer->out_size_tb == 0) {
                et_buffered_event_id->buffer->out_size_tb = sizeof(uint64_t);
                et_buffered_event_id->buffer->buffer_out = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__,
                        oritlsf_pool,
                        et_buffered_event_id->buffer->out_size_tb,
                        sizeof(uint8_t)
                        );
                if (!et_buffered_event_id->buffer->buffer_out) {
                    et_buffered_event_id->buffer->out_size_tb = 0;
                    et_buffered_event_id->buffer->out_size_c = 0;
                    wetr.failure = true;
                    wetr.partial = true;
                    wetr.status = FAILURE_NOMEM;
                    return wetr;
                }
                memcpy(et_buffered_event_id->buffer->buffer_out, &u, sizeof(uint64_t));
            } else {
                ssize_t old_out_size_tb = et_buffered_event_id->buffer->out_size_tb;
                et_buffered_event_id->buffer->out_size_tb += sizeof(uint64_t);
                et_buffered_event_id->buffer->buffer_out = (uint8_t *)oritlsf_realloc(__FILE__, __LINE__,
                        oritlsf_pool,
                        et_buffered_event_id->buffer->buffer_out,
                        et_buffered_event_id->buffer->out_size_tb * sizeof(uint8_t)
                        );
                if (!et_buffered_event_id->buffer->buffer_out) {
                    et_buffered_event_id->buffer->out_size_tb = 0;
                    et_buffered_event_id->buffer->out_size_c = 0;
                    wetr.failure = true;
                    wetr.partial = true;
                    wetr.status = FAILURE_NOMEM;
                    return wetr;
                }
                memcpy(et_buffered_event_id->buffer->buffer_out + old_out_size_tb, &u, sizeof(uint64_t));
            }
        }
        while (true) {
            ssize_t wsize = write(et_buffered_event_id->event_id, et_buffered_event_id->buffer->buffer_out + et_buffered_event_id->buffer->out_size_c, et_buffered_event_id->buffer->out_size_tb - et_buffered_event_id->buffer->out_size_c);
            if (wsize < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (et_buffered_event_id->buffer->out_size_tb == et_buffered_event_id->buffer->out_size_c) {
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
                    oritlsf_free(oritlsf_pool, (void **)&et_buffered_event_id->buffer->buffer_out);
                    et_buffered_event_id->buffer->out_size_tb = 0;
                    et_buffered_event_id->buffer->out_size_c = 0;
                    wetr.failure = true;
                    wetr.partial = true;
                    wetr.status = FAILURE;
                    break;
                }
            }
            if (wsize > 0) {
                et_buffered_event_id->buffer->out_size_c += wsize;
            }
            if (wsize == 0) {
                oritlsf_free(oritlsf_pool, (void **)&et_buffered_event_id->buffer->buffer_out);
                et_buffered_event_id->buffer->out_size_tb = 0;
                et_buffered_event_id->buffer->out_size_c = 0;
                wetr.failure = true;
                wetr.partial = true;
                wetr.status = FAILURE;
                break;
            }
            if (et_buffered_event_id->buffer->out_size_tb == et_buffered_event_id->buffer->out_size_c) {
                wetr.failure = false;
                wetr.partial = false;
                wetr.status = SUCCESS;
                break;
            }
        }
    }
    return wetr;
}

static inline et_result_t async_read_event(oritlsf_pool_t *oritlsf_pool, et_buffered_event_id_t *et_buffered_event_id) {
    et_result_t retr;
    retr.failure = false;
    retr.partial = true;
    retr.event_type = et_buffered_event_id->event_type;
    retr.status = FAILURE;

    if (retr.event_type == EIT_USER) {
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
        retr.failure = false;
        retr.partial = false;
        retr.status = SUCCESS;
#else
        retr.failure = true;
        retr.partial = true;
        retr.status = FAILURE;
        return retr;
#endif
    } else if (retr.event_type == EIT_TIMER) {
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
        retr.failure = false;
        retr.partial = false;
        retr.status = SUCCESS;
#else
        retr.failure = true;
        retr.partial = true;
        retr.status = FAILURE;
        return retr;
#endif
    } else {
        if (et_buffered_event_id->buffer->in_size_tb == 0) {
            et_buffered_event_id->buffer->in_size_tb = sizeof(uint64_t);
            et_buffered_event_id->buffer->buffer_in = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__,
                    oritlsf_pool,
                    et_buffered_event_id->buffer->in_size_tb,
                    sizeof(uint8_t)
                    );
            if (!et_buffered_event_id->buffer->buffer_in) {
                et_buffered_event_id->buffer->read_step = 0;
                et_buffered_event_id->buffer->out_size_tb = 0;
                et_buffered_event_id->buffer->out_size_c = 0;
                retr.failure = true;
                retr.partial = true;
                retr.status = FAILURE_NOMEM;
                return retr;
            }
        }
        while (true) {
            ssize_t rsize = read(et_buffered_event_id->event_id, et_buffered_event_id->buffer->buffer_in + et_buffered_event_id->buffer->in_size_c, et_buffered_event_id->buffer->in_size_tb-et_buffered_event_id->buffer->in_size_c);
            if (rsize < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (et_buffered_event_id->buffer->in_size_tb == et_buffered_event_id->buffer->in_size_c) {
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
                    oritlsf_free(oritlsf_pool, (void **)&et_buffered_event_id->buffer->buffer_in);
                    et_buffered_event_id->buffer->read_step = 0;
                    et_buffered_event_id->buffer->in_size_tb = 0;
                    et_buffered_event_id->buffer->in_size_c = 0;
                    retr.failure = true;
                    retr.partial = true;
                    retr.status = FAILURE;
                    break;
                }
            }
            if (rsize > 0) {
                et_buffered_event_id->buffer->in_size_c += rsize;
            }
            if (rsize == 0) {
                oritlsf_free(oritlsf_pool, (void **)&et_buffered_event_id->buffer->buffer_in);
                et_buffered_event_id->buffer->read_step = 0;
                et_buffered_event_id->buffer->in_size_tb = 0;
                et_buffered_event_id->buffer->in_size_c = 0;
                retr.failure = true;
                retr.partial = true;
                retr.status = FAILURE;
                break;
            }
            if (et_buffered_event_id->buffer->in_size_tb == et_buffered_event_id->buffer->in_size_c) {
                retr.failure = false;
                retr.partial = false;
                retr.status = SUCCESS;
                break;
            }
        }
    }
    return retr;
}

#endif
