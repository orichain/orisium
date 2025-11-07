#ifndef WORKERS_WORKER_TIMER_H
#define WORKERS_WORKER_TIMER_H

#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "log.h"
#include "timer.h"
#include "types.h"
#include "utilities.h"
#include "workers/workers.h"
#include "workers/worker_ipc.h"
#include "workers/heartbeat.h"
#include "constants.h"
#include "orilink/protocol.h"
#include "stdbool.h"

static inline status_t retry_transmit(
    worker_context_t *worker_ctx, 
    void *xsession, 
    control_packet_t *h, 
    orilink_protocol_type_t orilink_protocol
)
{
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
            cow_c_session_t *session = (cow_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
            worker_type_t c_wot = identity->local_wot;
            uint8_t c_index = identity->local_index;
            uint8_t c_session_index = identity->local_session_index;
            if (h->sent_try_count > (uint8_t)MAX_RETRY_CNT) {
                LOG_DEVEL_DEBUG("%sDisconnected => session_index %d, trycount %d.", worker_ctx->label, c_session_index, h->sent_try_count);
                cleanup_cow_session(worker_ctx, session);
                if (setup_cow_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                    return FAILURE;
                }
                if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE_MAXTRY;
            }
            if (h->udp_data.r_puint8_t == NULL) {
                return FAILURE;
            }
            double try_count = (double)h->sent_try_count;
            calculate_retry(worker_ctx->label, session, c_wot, try_count);
            if (retry_control_packet(
                    worker_ctx, 
                    identity, 
                    security, 
                    h,
                    orilink_protocol
                ) != SUCCESS
            )
            {
                return FAILURE;
            }
            break;
        }
        case SIO: {
            sio_c_session_t *session = (sio_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
            worker_type_t c_wot = identity->local_wot;
            uint8_t c_index = identity->local_index;
            uint8_t c_session_index = identity->local_session_index;
            if (h->sent_try_count > (uint8_t)MAX_RETRY_CNT) {
                LOG_DEVEL_DEBUG("%sDisconnected => session_index %d, trycount %d.", worker_ctx->label, c_session_index, h->sent_try_count);
                cleanup_sio_session(worker_ctx, session);
                if (setup_sio_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                    return FAILURE;
                }
                if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE_MAXTRY;
            }
            if (h->udp_data.r_puint8_t == NULL) {
                return FAILURE;
            }
            double try_count = (double)h->sent_try_count;
            calculate_retry(worker_ctx->label, session, c_wot, try_count);
            if (retry_control_packet(
                    worker_ctx, 
                    identity, 
                    security, 
                    h,
                    orilink_protocol
                ) != SUCCESS
            )
            {
                return FAILURE;
            }
            break;
        }
        default:
            return FAILURE;
    }
    return SUCCESS;
}

static inline status_t handle_worker_session_timer_event(worker_context_t *worker_ctx, void *sessions, uint64_t *timer_id) {
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
            cow_c_session_t *c_sessions = (cow_c_session_t *)sessions;
            for (uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
                cow_c_session_t *session;
                session = &c_sessions[i];
                if (*timer_id == session->hello1.retry_timer_id.id) {
                    status_t result = retry_transmit(worker_ctx, session, &session->hello1, ORILINK_HELLO1);
//----------------------------------------------------------------------
                    session->hello1.retry_timer_id.event = NULL;
//----------------------------------------------------------------------
                    return result;
                } else if (*timer_id == session->hello2.retry_timer_id.id) {
                    status_t result = retry_transmit(worker_ctx, session, &session->hello2, ORILINK_HELLO2);
//----------------------------------------------------------------------
                    session->hello2.retry_timer_id.event = NULL;
//----------------------------------------------------------------------
                    return result;
                } else if (*timer_id == session->hello3.retry_timer_id.id) {
                    status_t result = retry_transmit(worker_ctx, session, &session->hello3, ORILINK_HELLO3);
//----------------------------------------------------------------------
                    session->hello3.retry_timer_id.event = NULL;
//----------------------------------------------------------------------
                    return result;
                } else if (*timer_id == session->hello4.retry_timer_id.id) {
                    status_t result = retry_transmit(worker_ctx, session, &session->hello4, ORILINK_HELLO4);
//----------------------------------------------------------------------
                    session->hello4.retry_timer_id.event = NULL;
//----------------------------------------------------------------------
                    return result;
                } else if (*timer_id == session->heartbeat.retry_timer_id.id) {
                    status_t result = retry_transmit(worker_ctx, session, &session->heartbeat, ORILINK_HEARTBEAT);
//----------------------------------------------------------------------
                    session->heartbeat.retry_timer_id.event = NULL;
//----------------------------------------------------------------------
                    return result;
                } else if (*timer_id == session->heartbeat_sender_timer_id.id) {
                    if (!session->heartbeat.ack_rcvd) {
                        double timer_interval = session->heartbeat_interval;
                        status_t chst = htw_add_event(&worker_ctx->timer, &session->heartbeat_sender_timer_id.event, session->heartbeat_sender_timer_id.id, timer_interval);
                        if (chst != SUCCESS) {
                            return FAILURE;
                        }
                    } else {
                        send_heartbeat(worker_ctx, session, ORILINK_HEARTBEAT);
//----------------------------------------------------------------------
                        session->heartbeat_sender_timer_id.event = NULL;
//----------------------------------------------------------------------
                    }
                    return SUCCESS;
                } else if (*timer_id == session->heartbeat_openner_timer_id.id) {
                    session->heartbeat_ack.ack_sent = true;
//----------------------------------------------------------------------
                    session->heartbeat_openner_timer_id.event = NULL;
//----------------------------------------------------------------------
                    return SUCCESS;
                }
            }
            break;
        }
        case SIO: {
            sio_c_session_t *c_sessions = (sio_c_session_t *)sessions;
            for (uint8_t i = 0; i < MAX_CONNECTION_PER_SIO_WORKER; ++i) {
                sio_c_session_t *session;
                session = &c_sessions[i];
                if (*timer_id == session->heartbeat.retry_timer_id.id) {
                    status_t result = retry_transmit(worker_ctx, session, &session->heartbeat, ORILINK_HEARTBEAT);
//----------------------------------------------------------------------
                    session->heartbeat.retry_timer_id.event = NULL;
//----------------------------------------------------------------------
                    return result;
                } else if (*timer_id == session->heartbeat_sender_timer_id.id) {
                    if (!session->heartbeat.ack_rcvd) {
                        double timer_interval = session->heartbeat_interval;
                        status_t chst = htw_add_event(&worker_ctx->timer, &session->heartbeat_sender_timer_id.event, session->heartbeat_sender_timer_id.id, timer_interval);
                        if (chst != SUCCESS) {
                            return FAILURE;
                        }
                    } else {
                        send_heartbeat(worker_ctx, session, ORILINK_HEARTBEAT);
//----------------------------------------------------------------------
                        session->heartbeat_sender_timer_id.event = NULL;
//----------------------------------------------------------------------
                    }
                    return SUCCESS;
                } else if (*timer_id == session->heartbeat_openner_timer_id.id) {
                    session->heartbeat_ack.ack_sent = true;
//----------------------------------------------------------------------
                    session->heartbeat_openner_timer_id.event = NULL;
//----------------------------------------------------------------------
                    return SUCCESS;
                }
            }
            break;
        }
        default:
            return FAILURE;
    }
    return FAILURE;
}

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

static inline status_t handle_worker_timer_event(worker_context_t *worker_ctx, void *worker_sessions, int *current_fd) {
    hierarchical_timer_wheel_t *timer = &worker_ctx->timer;
    if (*current_fd == timer->add_event_fd) {
        if (drain_event_fd(worker_ctx->label, timer->add_event_fd) != SUCCESS) return FAILURE;
        if (htw_move_queue_to_wheel(timer) != SUCCESS) return FAILURE;
        //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
        return htw_reschedule_main_timer(worker_ctx->label, &worker_ctx->async, timer);
    } else if (*current_fd == timer->tick_event_fd) {
        if (drain_event_fd(worker_ctx->label, timer->tick_event_fd) != SUCCESS) return FAILURE;
        uint64_t advance_ticks = (uint64_t)(timer->last_delay_us);
        if (htw_advance_time_and_process_expired(worker_ctx->label, timer, advance_ticks) != SUCCESS) return FAILURE;
        if (htw_reschedule_main_timer(worker_ctx->label, &worker_ctx->async, timer) != SUCCESS) return FAILURE;
        uint64_t val = 1ULL;
        ssize_t w;
        do {
            w = write(timer->timeout_event_fd, &val, sizeof(uint64_t));
        } while (w == -1 && errno == EINTR);
        if (w == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return SUCCESS;
            }
            LOG_ERROR("%sFailed to write timeout_event_fd: %s", worker_ctx->label, strerror(errno));
            return FAILURE;
        }
        if (w != sizeof(uint64_t)) {
            LOG_ERROR("%sPartial write to timeout_event_fd: %zd bytes", worker_ctx->label, w);
            return FAILURE;
        }
        //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
        return SUCCESS;
    } else if (*current_fd == timer->remove_event_fd) {
        if (drain_event_fd(worker_ctx->label, timer->remove_event_fd) != SUCCESS) return FAILURE;
        if (htw_process_remove_queue(timer) != SUCCESS) return FAILURE;
        //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
        return htw_reschedule_main_timer(worker_ctx->label, &worker_ctx->async, timer);
    } else if (*current_fd == timer->timeout_event_fd) {
        if (drain_event_fd(worker_ctx->label, timer->timeout_event_fd) != SUCCESS) return FAILURE;
        timer_event_t *current_event = timer->ready_queue_head;
        timer->ready_queue_head = NULL;
        timer->ready_queue_tail = NULL;
        status_t handler_result = SUCCESS;
        while (current_event != NULL) {
            timer_event_t *next = current_event->next;
            uint64_t expired_timer_id = current_event->timer_id;
            if (expired_timer_id == worker_ctx->heartbeat_timer_id.id) {
                double new_heartbeat_interval_double = worker_hb_interval_with_jitter_us();
                status_t chst = htw_add_event(&worker_ctx->timer, &worker_ctx->heartbeat_timer_id.event, worker_ctx->heartbeat_timer_id.id, new_heartbeat_interval_double);
                if (chst != SUCCESS) {
                    LOG_ERROR("%sWorker error htw_add_event for heartbeat.", worker_ctx->label);
                    handler_result = FAILURE;
                    htw_pool_free(timer, current_event);
                    current_event = next;
                    break;
                }
                if (worker_master_heartbeat(worker_ctx, new_heartbeat_interval_double) != SUCCESS) {
                    handler_result = FAILURE;
                    htw_pool_free(timer, current_event);
                    current_event = next;
                    break;
                }
            } else {
                if (worker_sessions != NULL) {
                    handler_result = handle_worker_session_timer_event(worker_ctx, worker_sessions, &expired_timer_id);
                    if (handler_result != SUCCESS) {
                        htw_pool_free(timer, current_event);
                        current_event = next;
                        break;
                    }
                } else {
                    handler_result = FAILURE;
                    htw_pool_free(timer, current_event);
                    current_event = next;
                    break;
                }
            }
            htw_pool_free(timer, current_event);
            current_event = next;
        }
        //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
        return handler_result;
    } else {
        return FAILURE;
    }
}

#endif
