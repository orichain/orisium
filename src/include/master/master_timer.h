#ifndef MASTER_MASTER_TIMER_H
#define MASTER_MASTER_TIMER_H

#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "log.h"
#include "timer.h"
#include "types.h"
#include "utilities.h"
#include "master/master.h"
#include "master/ipc/worker_ipc_cmds.h"
#include "master/worker_metrics.h"

static inline status_t drain_event_fd(const char *label, int fd) {
    uint64_t u;
    while (true) {
        ssize_t r = read(fd, &u, sizeof(uint64_t));
        if (r == sizeof(uint64_t)) continue;
        if (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) return SUCCESS;
        if (r == -1) {
            LOG_ERROR("%sFailed to read event_fd %d: %s", label, fd, strerror(errno));
            return FAILURE;
        }
        break;
    }
    return SUCCESS;
}

static inline status_t handle_master_timer_event(const char *label, master_context_t *master_ctx, int *current_fd) {
    hierarchical_timer_wheel_t *timer = &master_ctx->timer;
    if (*current_fd == timer->add_event_fd) {
        if (drain_event_fd(label, timer->add_event_fd) != SUCCESS) return FAILURE;
        if (htw_move_queue_to_wheel(timer) != SUCCESS) return FAILURE;
        return htw_reschedule_main_timer(label, &master_ctx->master_async, timer);
    } else if (*current_fd == timer->tick_event_fd) {
        if (drain_event_fd(label, timer->tick_event_fd) != SUCCESS) return FAILURE;
        uint64_t advance_ticks = (uint64_t)(timer->last_delay_ms);
        if (htw_advance_time_and_process_expired(timer, advance_ticks) != SUCCESS) return FAILURE;
        if (htw_reschedule_main_timer(label, &master_ctx->master_async, timer) != SUCCESS) return FAILURE;
        uint64_t val = 1ULL;
        if (write(timer->timeout_event_fd, &val, sizeof(uint64_t)) != sizeof(uint64_t)) {
            LOG_ERROR("%sFailed to write timeout_event_fd: %s", label, strerror(errno));
            return FAILURE;
        }
        return SUCCESS;
    } else if (*current_fd == timer->timeout_event_fd) {
        if (drain_event_fd(label, timer->timeout_event_fd) != SUCCESS) return FAILURE;
        timer_event_t *current_event = timer->ready_queue_head;
        timer->ready_queue_head = NULL;
        timer->ready_queue_tail = NULL;
        status_t handler_result = SUCCESS;
        while (current_event != NULL) {
            timer_event_t *next = current_event->next;
            uint64_t expired_timer_id = current_event->timer_id;
            if (expired_timer_id == master_ctx->check_healthy_timer_id) {
                double ch = worker_check_healthy_ms();
                status_t chst = htw_add_event(&master_ctx->timer, master_ctx->check_healthy_timer_id, ch);
                if (chst != SUCCESS) {
                    LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", label);
                    master_ctx->shutdown_requested = 1;
                    master_workers_info(label, master_ctx, IT_SHUTDOWN);
                    handler_result = FAILURE;
                }
                master_ctx->hb_check_times++;
                if (master_ctx->hb_check_times >= REKEYING_HB_TIMES) {
                    master_ctx->hb_check_times = (uint16_t)0;
                    master_ctx->is_rekeying = true;
                    master_ctx->all_workers_is_ready = false;
                    master_workers_info(label, master_ctx, IT_REKEYING);
                } else {
                    check_workers_healthy(label, master_ctx);
                }
            } else {
                handler_result = FAILURE;
            }
            htw_pool_free(timer, current_event);
            current_event = next;
        }
        return handler_result;
    } else {
        return FAILURE;
    }
}

#endif
