#include <math.h>
#include <unistd.h>
#include <inttypes.h>
#include <stddef.h>

#include "types.h"
#include "workers/workers.h"
#include "workers/timer/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "constants.h"
#include "log.h"
#include "async.h"
#include "stdbool.h"
#include "utilities.h"
#include "orilink/heartbeat.h"
#include "orilink/protocol.h"

static inline status_t timer_handle_event_create(worker_context_t *worker_ctx, control_packet_t *h) {
    if (create_timer(worker_ctx, &h->timer_fd, h->interval_timer_fd) != SUCCESS) {
        double create_interval = (double)RETRY_TIMER_CREATE_DELAY_NS / (double)1e9;
        update_timer(worker_ctx, &h->creator_timer_fd, create_interval);
        return FAILURE;
    }
    async_delete_event(worker_ctx->label, &worker_ctx->async, &h->creator_timer_fd);
    CLOSE_FD(&h->creator_timer_fd);
    return SUCCESS;
}

static inline status_t timer_handle_event(worker_context_t *worker_ctx, void *xsession, control_packet_t *h, orilink_protocol_type_t orilink_protocol) {
    if (h->ack_rcvd) {
//======================================================================
// Let The Timer Dies By Itself
//======================================================================
        cleanup_control_packet(worker_ctx->label, &worker_ctx->async, h, false);
        LOG_DEBUG("%sTimer Retry Hello1 Closed", worker_ctx->label);
        return SUCCESS;
    }
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
            cow_c_session_t *session = (cow_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
            double retry_timer_interval = pow((double)2, (double)session->retry.value_prediction);
            worker_type_t c_wot = identity->local_wot;
            uint8_t c_index = identity->local_index;
            uint8_t c_session_index = identity->local_session_index;
            if (h->sent_try_count > MAX_RETRY) {
                LOG_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, h->interval_timer_fd, h->sent_try_count);
//----------------------------------------------------------------------
// Disconnected => 1. Reset Session
//                 2. Send Info To Master
//----------------------------------------------------------------------
                cleanup_cow_session(worker_ctx->label, &worker_ctx->async, session);
                if (setup_cow_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                    return FAILURE;
                }
                if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                    return FAILURE;
                }
//----------------------------------------------------------------------
                return SUCCESS;
            }
            if (h->data == NULL) {
                update_timer(worker_ctx, &h->timer_fd, retry_timer_interval);
                return FAILURE;
            }
            double try_count = (double)h->sent_try_count;
            calculate_retry(worker_ctx->label, session, c_wot, try_count);
            retry_timer_interval = pow((double)2, (double)session->retry.value_prediction);
            h->interval_timer_fd = retry_timer_interval;
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
            double retry_timer_interval = pow((double)2, (double)session->retry.value_prediction);
            worker_type_t c_wot = identity->local_wot;
            uint8_t c_index = identity->local_index;
            uint8_t c_session_index = identity->local_session_index;
            if (h->sent_try_count > MAX_RETRY) {
                LOG_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, h->interval_timer_fd, h->sent_try_count);
//----------------------------------------------------------------------
// Disconnected => 1. Reset Session
//                 2. Send Info To Master
//----------------------------------------------------------------------
                cleanup_sio_session(worker_ctx->label, &worker_ctx->async, session);
                if (setup_sio_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                    return FAILURE;
                }
                if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                    return FAILURE;
                }
//----------------------------------------------------------------------
                return SUCCESS;
            }
            if (h->data == NULL) {
                update_timer(worker_ctx, &h->timer_fd, retry_timer_interval);
                return FAILURE;
            }
            double try_count = (double)h->sent_try_count;
            calculate_retry(worker_ctx->label, session, c_wot, try_count);
            retry_timer_interval = pow((double)2, (double)session->retry.value_prediction);
            h->interval_timer_fd = retry_timer_interval;
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

static inline status_t timer_handle_event_send_heartbeat(worker_context_t *worker_ctx, void *xsession, orilink_protocol_type_t orilink_protocol) {
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
            cow_c_session_t *session = (cow_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
            double timer_interval = session->heartbeat_interval * pow((double)2, (double)session->retry.value_prediction);
            timer_interval += session->rtt.value_prediction / (double)1e9;
            if (
                session->heartbeat.timer_fd != -1 ||
                session->heartbeat.creator_timer_fd != -1
            )
            {
//======================================================================
// Let The Retry Timer Finish The Retry Job
//======================================================================
                if (update_timer(worker_ctx, &session->heartbeat_sender_timer_fd, timer_interval) != SUCCESS) {
                    return FAILURE;
                }
                return SUCCESS;
            }
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                if (update_timer(worker_ctx, &session->heartbeat_sender_timer_fd, timer_interval) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE;
            }
//----------------------------------------------------------------------
            session->heartbeat.sent_try_count++;
            session->heartbeat.sent_time = current_time.r_uint64_t;
//======================================================================
            double hb_interval = (double)NODE_HEARTBEAT_INTERVAL * pow((double)2, (double)session->retry.value_prediction);
            hb_interval += session->rtt.value_prediction / (double)1e9;
//======================================================================
            uint8_t l_inc_ctr = 0x01;
            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat(
                worker_ctx->label,
                l_inc_ctr,
                identity->remote_wot,
                identity->remote_index,
                identity->remote_session_index,
                identity->local_wot,
                identity->local_index,
                identity->local_session_index,
                identity->id_connection,
                identity->local_id,
                identity->remote_id,
                hb_interval,
                session->heartbeat.sent_try_count
            );
            if (orilink_cmd_result.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                if (update_timer(worker_ctx, &session->heartbeat_sender_timer_fd, timer_interval) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE;
            }
            puint8_t_size_t_status_t udp_data = create_orilink_raw_protocol_packet(
                worker_ctx->label,
                security->aes_key,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr,
                orilink_cmd_result.r_orilink_protocol_t
            );
            CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
            if (udp_data.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                if (update_timer(worker_ctx, &session->heartbeat_sender_timer_fd, timer_interval) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE;
            }
            //print_hex("COW Sending Heartbeat ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
            if (worker_master_udp_data(
                    worker_ctx->label, 
                    worker_ctx, 
                    identity->local_wot, 
                    identity->local_index, 
                    identity->local_session_index, 
                    (uint8_t)orilink_protocol,
                    session->heartbeat.sent_try_count,
                    &session->identity.remote_addr, 
                    &udp_data, 
                    &session->heartbeat
                ) != SUCCESS
            )
            {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                if (update_timer(worker_ctx, &session->heartbeat_sender_timer_fd, timer_interval) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE;
            }
//======================================================================
// Heartbeat Ack Security 1 & Security 2 Open
//======================================================================
            session->heartbeat.sent = true;
            session->heartbeat.ack_rcvd = false;
//======================================================================
// Heartbeat Security 2 Open
//======================================================================
            session->heartbeat_ack.rcvd = false;
//======================================================================
            async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
            CLOSE_FD(&session->heartbeat_sender_timer_fd);
            break;
        }
        case SIO: {
            sio_c_session_t *session = (sio_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
            double timer_interval = session->heartbeat_interval * pow((double)2, (double)session->retry.value_prediction);
            timer_interval += session->rtt.value_prediction / (double)1e9;
            if (
                session->heartbeat.timer_fd != -1 ||
                session->heartbeat.creator_timer_fd != -1
            )
            {
//======================================================================
// Let The Retry Timer Finish The Retry Job
//======================================================================
                if (update_timer(worker_ctx, &session->heartbeat_sender_timer_fd, timer_interval) != SUCCESS) {
                    return FAILURE;
                }
                return SUCCESS;
            }
//----------------------------------------------------------------------
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                if (update_timer(worker_ctx, &session->heartbeat_sender_timer_fd, timer_interval) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE;
            }
            session->heartbeat.sent_try_count++;
            session->heartbeat.sent_time = current_time.r_uint64_t;
//======================================================================
            double hb_interval = (double)NODE_HEARTBEAT_INTERVAL * pow((double)2, (double)session->retry.value_prediction);
            hb_interval += session->rtt.value_prediction / (double)1e9;
//======================================================================
            uint8_t l_inc_ctr = 0x01;
            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat(
                worker_ctx->label,
                l_inc_ctr,
                identity->remote_wot,
                identity->remote_index,
                identity->remote_session_index,
                identity->local_wot,
                identity->local_index,
                identity->local_session_index,
                identity->id_connection,
                identity->local_id,
                identity->remote_id,
                hb_interval,
                session->heartbeat.sent_try_count
            );
            if (orilink_cmd_result.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                if (update_timer(worker_ctx, &session->heartbeat_sender_timer_fd, timer_interval) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE;
            }
            puint8_t_size_t_status_t udp_data = create_orilink_raw_protocol_packet(
                worker_ctx->label,
                security->aes_key,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr,
                orilink_cmd_result.r_orilink_protocol_t
            );
            CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
            if (udp_data.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                if (update_timer(worker_ctx, &session->heartbeat_sender_timer_fd, timer_interval) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE;
            }
            //print_hex("SIO Sending Heartbeat ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
            if (worker_master_udp_data(
                    worker_ctx->label, 
                    worker_ctx, 
                    identity->local_wot, 
                    identity->local_index, 
                    identity->local_session_index, 
                    (uint8_t)orilink_protocol,
                    session->heartbeat.sent_try_count,
                    &session->identity.remote_addr, 
                    &udp_data, 
                    &session->heartbeat
                ) != SUCCESS
            )
            {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                if (update_timer(worker_ctx, &session->heartbeat_sender_timer_fd, timer_interval) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE;
            }
//======================================================================
// Heartbeat Ack Security 1 & Security 2 Open
//======================================================================
            session->heartbeat.sent = true;
            session->heartbeat.ack_rcvd = false;
//======================================================================
// Heartbeat Security 2 Open
//======================================================================
            session->heartbeat_ack.rcvd = false;
//======================================================================
            async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
            CLOSE_FD(&session->heartbeat_sender_timer_fd);
            break;
        }
        default:
            return FAILURE;
    }
    return SUCCESS;
}

status_t handle_workers_timer_event(worker_context_t *worker_ctx, void *sessions, int *current_fd) {
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
            cow_c_session_t *c_sessions = (cow_c_session_t *)sessions;
            for (uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
                cow_c_session_t *session;
                session = &c_sessions[i];
                if (*current_fd == session->hello1.creator_timer_fd) {
                    uint64_t u;
                    read(session->hello1.creator_timer_fd, &u, sizeof(u));
                    return timer_handle_event_create(worker_ctx, &session->hello1);
                } else if (*current_fd == session->hello1.timer_fd) {
                    uint64_t u;
                    read(session->hello1.timer_fd, &u, sizeof(u));
                    return timer_handle_event(worker_ctx, session, &session->hello1, ORILINK_HELLO1);
                } else if (*current_fd == session->hello2.creator_timer_fd) {
                    uint64_t u;
                    read(session->hello2.creator_timer_fd, &u, sizeof(u));
                    return timer_handle_event_create(worker_ctx, &session->hello2);
                } else if (*current_fd == session->hello2.timer_fd) {
                    uint64_t u;
                    read(session->hello2.timer_fd, &u, sizeof(u));
                    return timer_handle_event(worker_ctx, session, &session->hello2, ORILINK_HELLO2);
                } else if (*current_fd == session->hello3.creator_timer_fd) {
                    uint64_t u;
                    read(session->hello3.creator_timer_fd, &u, sizeof(u));
                    return timer_handle_event_create(worker_ctx, &session->hello3);
                } else if (*current_fd == session->hello3.timer_fd) {
                    uint64_t u;
                    read(session->hello3.timer_fd, &u, sizeof(u));
                    return timer_handle_event(worker_ctx, session, &session->hello3, ORILINK_HELLO3);
                } else if (*current_fd == session->hello4.creator_timer_fd) {
                    uint64_t u;
                    read(session->hello4.creator_timer_fd, &u, sizeof(u));
                    return timer_handle_event_create(worker_ctx, &session->hello4);
                } else if (*current_fd == session->hello4.timer_fd) {
                    uint64_t u;
                    read(session->hello4.timer_fd, &u, sizeof(u));
                    return timer_handle_event(worker_ctx, session, &session->hello4, ORILINK_HELLO4);
                } else if (*current_fd == session->heartbeat.creator_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat.creator_timer_fd, &u, sizeof(u));
                    return timer_handle_event_create(worker_ctx, &session->heartbeat);
                } else if (*current_fd == session->heartbeat.timer_fd) {
                    uint64_t u;
                    read(session->heartbeat.timer_fd, &u, sizeof(u));
                    return timer_handle_event(worker_ctx, session, &session->heartbeat, ORILINK_HEARTBEAT);
                } else if (*current_fd == session->heartbeat_sender_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_sender_timer_fd, &u, sizeof(u));
                    return timer_handle_event_send_heartbeat(worker_ctx, session, ORILINK_HEARTBEAT);
                } else if (*current_fd == session->heartbeat_openner_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_openner_timer_fd, &u, sizeof(u));
                    session->heartbeat_openned = true;
                    async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_openner_timer_fd);
                    CLOSE_FD(&session->heartbeat_openner_timer_fd);
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
                if (*current_fd == session->heartbeat.creator_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat.creator_timer_fd, &u, sizeof(u));
                    return timer_handle_event_create(worker_ctx, &session->heartbeat);
                } else if (*current_fd == session->heartbeat.timer_fd) {
                    uint64_t u;
                    read(session->heartbeat.timer_fd, &u, sizeof(u));
                    return timer_handle_event(worker_ctx, session, &session->heartbeat, ORILINK_HEARTBEAT);
                } else if (*current_fd == session->heartbeat_sender_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_sender_timer_fd, &u, sizeof(u));
                    return timer_handle_event_send_heartbeat(worker_ctx, session, ORILINK_HEARTBEAT);
                } else if (*current_fd == session->heartbeat_openner_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_openner_timer_fd, &u, sizeof(u));
                    session->heartbeat_openned = true;
                    async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_openner_timer_fd);
                    CLOSE_FD(&session->heartbeat_openner_timer_fd);
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
