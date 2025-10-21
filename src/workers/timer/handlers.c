#include <math.h>
#include <unistd.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>

#include "types.h"
#include "workers/workers.h"
#include "workers/timer/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "constants.h"
#include "log.h"
#include "stdbool.h"
#include "utilities.h"
#include "orilink/heartbeat.h"
#include "orilink/protocol.h"

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
                cleanup_cow_session(worker_ctx->label, &worker_ctx->async, session);
                if (setup_cow_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                    return FAILURE;
                }
                if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE_MAXTRY;
            }
            if (h->data == NULL) {
                return FAILURE;
            }
            double try_count = (double)h->sent_try_count;
            calculate_retry(worker_ctx->label, session, c_wot, try_count);
//----------------------------------------------------------------------            
            double retry_timer_interval = (double)session->retry.value_prediction;
            retry_timer_interval = pow((double)2, retry_timer_interval);
            if (retry_timer_interval < (double)MIN_RETRY_SEC) retry_timer_interval = (double)MIN_RETRY_SEC;
            double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * JITTER_PERCENTAGE * 2) - JITTER_PERCENTAGE;
            retry_timer_interval *= (1.0 + jitter_amount);
//----------------------------------------------------------------------
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
            if (orilink_protocol == ORILINK_HEARTBEAT) {
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
            }
            h->polling_1ms_cnt = (uint16_t)0;
            if (create_polling_1ms(worker_ctx, h, retry_timer_interval) != SUCCESS) {
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
                cleanup_sio_session(worker_ctx->label, &worker_ctx->async, session);
                if (setup_sio_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                    return FAILURE;
                }
                if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE_MAXTRY;
            }
            if (h->data == NULL) {
                return FAILURE;
            }
            double try_count = (double)h->sent_try_count;
            calculate_retry(worker_ctx->label, session, c_wot, try_count);
//----------------------------------------------------------------------   
            double retry_timer_interval = (double)session->retry.value_prediction;
            retry_timer_interval = pow((double)2, retry_timer_interval);
            if (retry_timer_interval < (double)MIN_RETRY_SEC) retry_timer_interval = (double)MIN_RETRY_SEC;
            double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * JITTER_PERCENTAGE * 2) - JITTER_PERCENTAGE;
            retry_timer_interval *= (1.0 + jitter_amount);
//----------------------------------------------------------------------
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
            if (orilink_protocol == ORILINK_HEARTBEAT) {
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
            }
            h->polling_1ms_cnt = (uint16_t)0;
            if (create_polling_1ms(worker_ctx, h, retry_timer_interval) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        default:
            return FAILURE;
    }
    return SUCCESS;
}

static inline status_t polling_1ms(
    worker_context_t *worker_ctx, 
    void *xsession, 
    control_packet_t *h, 
    orilink_protocol_type_t orilink_protocol
)
{
    double polling_interval = (double)1000000 / (double)1e9;
    if (h->data != NULL) {
        if (!h->ack_rcvd) {
            h->polling_1ms_cnt++;
            uint16_t polling_1ms_max_cnt = h->polling_1ms_max_cnt;
            if (h->polling_1ms_cnt >= polling_1ms_max_cnt) {
                retry_transmit(
                    worker_ctx,
                    xsession,
                    h,
                    orilink_protocol
                );
            } else {
                if (update_timer_oneshot(worker_ctx->label, &h->polling_timer_fd, polling_interval) != SUCCESS) {
                    update_timer_oneshot(worker_ctx->label, &h->polling_timer_fd, polling_interval);
                    return FAILURE;
                }
            }
        } else {
            cleanup_control_packet(worker_ctx->label, &worker_ctx->async, h, false);
        }
    }
    return SUCCESS;
}

static inline status_t send_heartbeat(worker_context_t *worker_ctx, void *xsession, orilink_protocol_type_t orilink_protocol) {
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
            cow_c_session_t *session = (cow_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
//======================================================================
            double hb_interval = (double)NODE_HEARTBEAT_INTERVAL * pow((double)2, (double)session->retry.value_prediction);
            double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * JITTER_PERCENTAGE * 2) - JITTER_PERCENTAGE;
            hb_interval *= (1.0 + jitter_amount);
            hb_interval += session->rtt.value_prediction / (double)1e9;
//======================================================================
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, hb_interval) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE;
            }
//----------------------------------------------------------------------
            session->heartbeat.sent_try_count++;
            session->heartbeat.sent_time = current_time.r_uint64_t;
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
                if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, hb_interval) != SUCCESS) {
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
                if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, hb_interval) != SUCCESS) {
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
                if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, hb_interval) != SUCCESS) {
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
            break;
        }
        case SIO: {
            sio_c_session_t *session = (sio_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
//======================================================================
            double hb_interval = (double)NODE_HEARTBEAT_INTERVAL * pow((double)2, (double)session->retry.value_prediction);
            double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * JITTER_PERCENTAGE * 2) - JITTER_PERCENTAGE;
            hb_interval *= (1.0 + jitter_amount);
            hb_interval += session->rtt.value_prediction / (double)1e9;
//======================================================================
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, hb_interval) != SUCCESS) {
                    return FAILURE;
                }
                return FAILURE;
            }
//----------------------------------------------------------------------
            session->heartbeat.sent_try_count++;
            session->heartbeat.sent_time = current_time.r_uint64_t;
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
                if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, hb_interval) != SUCCESS) {
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
                if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, hb_interval) != SUCCESS) {
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
                if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, hb_interval) != SUCCESS) {
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
            break;
        }
        default:
            return FAILURE;
    }
    return SUCCESS;
}

static inline status_t turns_to_polling_1ms(
    worker_context_t *worker_ctx, 
    void *xsession, 
    orilink_protocol_type_t orilink_protocol
)
{
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
            cow_c_session_t *session = (cow_c_session_t *)xsession;
            double polling_interval = (double)1000000 / (double)1e9;
            if (!session->heartbeat.ack_rcvd) {
                //printf("COW Heartbeat Waiting Previous Ack\n");
                if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, polling_interval) != SUCCESS) {
                    update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, polling_interval);
                    return FAILURE;
                }
            } else {
                if (session->heartbeat_sender_polling_1ms_cnt >= (uint16_t)1 + (uint16_t)session->heartbeat.polling_1ms_last_cnt) {
                    session->heartbeat_sender_polling_1ms_cnt = (uint16_t)0;
                    send_heartbeat(worker_ctx, xsession, orilink_protocol);
                } else {
                    session->heartbeat_sender_polling_1ms_cnt++;
                    if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, polling_interval) != SUCCESS) {
                        update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, polling_interval);
                        return FAILURE;
                    }
                }
            }
            break;
        }
        case SIO: {
            sio_c_session_t *session = (sio_c_session_t *)xsession;
            double polling_interval = (double)1000000 / (double)1e9;
            if (!session->heartbeat.ack_rcvd) {
                //printf("SIO Heartbeat Waiting Previous Ack\n");
                if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, polling_interval) != SUCCESS) {
                    update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, polling_interval);
                    return FAILURE;
                }
            } else {
                if (session->heartbeat_sender_polling_1ms_cnt >= (uint16_t)1 + (uint16_t)session->heartbeat.polling_1ms_last_cnt) {
                    session->heartbeat_sender_polling_1ms_cnt = (uint16_t)0;
                    send_heartbeat(worker_ctx, xsession, orilink_protocol);
                } else {
                    session->heartbeat_sender_polling_1ms_cnt++;
                    if (update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, polling_interval) != SUCCESS) {
                        update_timer_oneshot(worker_ctx->label, &session->heartbeat_sender_timer_fd, polling_interval);
                        return FAILURE;
                    }
                }
            }
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
                if (*current_fd == session->hello1.polling_timer_fd) {
                    uint64_t u;
                    read(session->hello1.polling_timer_fd, &u, sizeof(u));
                    return polling_1ms(worker_ctx, session, &session->hello1, ORILINK_HELLO1);
                } else if (*current_fd == session->hello2.polling_timer_fd) {
                    uint64_t u;
                    read(session->hello2.polling_timer_fd, &u, sizeof(u));
                    return polling_1ms(worker_ctx, session, &session->hello2, ORILINK_HELLO2);
                } else if (*current_fd == session->hello3.polling_timer_fd) {
                    uint64_t u;
                    read(session->hello3.polling_timer_fd, &u, sizeof(u));
                    return polling_1ms(worker_ctx, session, &session->hello3, ORILINK_HELLO3);
                } else if (*current_fd == session->hello4.polling_timer_fd) {
                    uint64_t u;
                    read(session->hello4.polling_timer_fd, &u, sizeof(u));
                    return polling_1ms(worker_ctx, session, &session->hello4, ORILINK_HELLO4);
                } else if (*current_fd == session->heartbeat.polling_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat.polling_timer_fd, &u, sizeof(u));
                    return polling_1ms(worker_ctx, session, &session->heartbeat, ORILINK_HEARTBEAT);
                } else if (*current_fd == session->heartbeat_sender_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_sender_timer_fd, &u, sizeof(u));
                    return turns_to_polling_1ms(worker_ctx, session, ORILINK_HEARTBEAT);
                } else if (*current_fd == session->heartbeat_openner_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_openner_timer_fd, &u, sizeof(u));
                    session->heartbeat_ack.ack_sent = true;
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
                if (*current_fd == session->heartbeat.polling_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat.polling_timer_fd, &u, sizeof(u));
                    return polling_1ms(worker_ctx, session, &session->heartbeat, ORILINK_HEARTBEAT);
                } else if (*current_fd == session->heartbeat_sender_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_sender_timer_fd, &u, sizeof(u));
                    return turns_to_polling_1ms(worker_ctx, session, ORILINK_HEARTBEAT);
                } else if (*current_fd == session->heartbeat_openner_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_openner_timer_fd, &u, sizeof(u));
                    session->heartbeat_ack.ack_sent = true;
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
