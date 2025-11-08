#ifndef MASTER_MASTER_TIMER_H
#define MASTER_MASTER_TIMER_H

#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "log.h"
#include "oritw.h"
#include "types.h"
#include "utilities.h"
#include "master/master.h"
#include "master/ipc/worker_ipc_cmds.h"
#include "constants.h"
#include "stdbool.h"

static inline status_t drain_event_fd(const char *label, int fd) {
    uint64_t u;
    while (true) {
        ssize_t r = read(fd, &u, sizeof(uint64_t));
        if (r == (ssize_t)sizeof(uint64_t)) continue;
        if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) return SUCCESS;
        if (r == -1) {
            LOG_ERROR("%sFailed to read event_fd %d: %s", label, fd, strerror(errno));
            return FAILURE;
        }
        LOG_WARN("%sUnexpected read from event_fd %d: returned %zd bytes", label, fd, r);
        break;
    }
    return SUCCESS;
}

static inline status_t handle_master_timer_event(const char *label, master_context_t *master_ctx, int *current_fd) {
    for (uint32_t llv = 0; llv < MAX_TIMER_LEVELS; ++llv) {
        ori_timer_wheel_t *timer = master_ctx->timer[llv];
        if (*current_fd == timer->add_event_fd) {
            if (drain_event_fd(label, timer->add_event_fd) != SUCCESS) return FAILURE;
            if (oritw_move_queue_to_wheel(master_ctx->timer, llv) != SUCCESS) return FAILURE;
            //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
            return oritw_reschedule_main_timer(label, &master_ctx->master_async, master_ctx->timer, llv);
        } else if (*current_fd == timer->tick_event_fd) {
            if (drain_event_fd(label, timer->tick_event_fd) != SUCCESS) return FAILURE;
            uint64_t advance_ticks = (uint64_t)(timer->last_delay_us);
            if (oritw_advance_time_and_process_expired(label, master_ctx->timer, llv, advance_ticks) != SUCCESS) return FAILURE;
            if (oritw_reschedule_main_timer(label, &master_ctx->master_async, master_ctx->timer, llv) != SUCCESS) return FAILURE;
            uint64_t val = 1ULL;
            ssize_t w;
            do {
                w = write(timer->timeout_event_fd, &val, sizeof(uint64_t));
            } while (w == -1 && errno == EINTR);
            if (w == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return SUCCESS;
                }
                LOG_ERROR("%sFailed to write timeout_event_fd: %s", label, strerror(errno));
                return FAILURE;
            }
            if (w != sizeof(uint64_t)) {
                LOG_ERROR("%sPartial write to timeout_event_fd: %zd bytes", label, w);
                return FAILURE;
            }
            //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
            return SUCCESS;
        } else if (*current_fd == timer->remove_event_fd) {
            if (drain_event_fd(label, timer->remove_event_fd) != SUCCESS) return FAILURE;
            if (oritw_process_remove_queue(master_ctx->timer, llv) != SUCCESS) return FAILURE;
            //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
            return oritw_reschedule_main_timer(label, &master_ctx->master_async, master_ctx->timer, llv);
        } else if (*current_fd == timer->timeout_event_fd) {
            if (drain_event_fd(label, timer->timeout_event_fd) != SUCCESS) return FAILURE;
            timer_event_t *current_event = timer->ready_queue_head;
            timer->ready_queue_head = NULL;
            timer->ready_queue_tail = NULL;
            status_t handler_result = SUCCESS;
            while (current_event != NULL) {
                timer_event_t *next = current_event->next;
                uint64_t expired_timer_id = current_event->timer_id;
                if (expired_timer_id == master_ctx->check_healthy_timer_id.id) {
                    double ch = worker_check_healthy_us();
                    status_t chst = oritw_add_event(master_ctx->timer, &master_ctx->check_healthy_timer_id, ch);
                    if (chst != SUCCESS) {
                        LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", label);
                        master_ctx->shutdown_requested = 1;
                        master_workers_info(label, master_ctx, IT_SHUTDOWN);
                        handler_result = FAILURE;
                        oritw_pool_free(master_ctx->timer, current_event);
                        current_event = next;
                        break;
                    }
                    master_ctx->hb_check_times++;
                    if (master_ctx->hb_check_times >= REKEYING_HB_TIMES) {
                        master_ctx->hb_check_times = (uint16_t)0;
                        master_ctx->is_rekeying = true;
                        master_ctx->all_workers_is_ready = false;
                        handler_result = master_workers_info(label, master_ctx, IT_REKEYING);
                        if (handler_result != SUCCESS) {
                            oritw_pool_free(master_ctx->timer, current_event);
                            current_event = next;
                            break;
                        }
                    } else {
                        handler_result = check_workers_healthy(label, master_ctx);
                        if (handler_result != SUCCESS) {
                            oritw_pool_free(master_ctx->timer, current_event);
                            current_event = next;
                            break;
                        }
                    }
                } else {
                    handler_result = FAILURE;
                    oritw_pool_free(master_ctx->timer, current_event);
                    current_event = next;
                    break;
                }
                oritw_pool_free(master_ctx->timer, current_event);
                current_event = next;
            }
            //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
            return handler_result;
        }
    }
    return SUCCESS;
}

#endif
