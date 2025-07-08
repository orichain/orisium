#ifndef ASYNC_H
#define ASYNC_H

#include <sys/epoll.h>
#include <stdbool.h>
#include "types.h"
#include "constants.h"

typedef struct {
    int async_fd;
    struct epoll_event event;
    struct epoll_event events[MAX_EVENTS];
} async_type_t;

bool async_event_is_EPOLLHUP(uint32_t events);
bool async_event_is_EPOLLERR(uint32_t events);
bool async_event_is_EPOLLRDHUP(uint32_t events);
bool async_event_is_EPOLLIN(uint32_t events);
bool async_event_is_EPOLLOUT(uint32_t events);
bool async_event_is_EPOLLET(uint32_t events);
int_status_t async_getfd(const char* label, async_type_t *async, int n);
uint32_t_status_t async_getevents(const char* label, async_type_t *async, int n);
int_status_t async_wait(const char* label, async_type_t *async);
status_t async_create(const char* label, async_type_t *async);
status_t async_create_eventfd_nonblock_close_after_exec(const char* label, int *event_fd);
status_t async_create_timerfd(const char* label, int *timer_fd, int heartbeat_sec);
status_t async_create_incoming_event(const char* label, async_type_t *async, int *fd_to_add);
status_t async_create_incoming_event_with_disconnect(const char* label, async_type_t *async, int *fd_to_add);
status_t async_delete_event(const char* label, async_type_t *async, int *fd_to_delete);

#endif
