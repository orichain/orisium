#include <math.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>

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

status_t handle_workers_timer_event(worker_context_t *worker_ctx, void *sessions, int *current_fd) {
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
            cow_c_session_t *c_sessions = (cow_c_session_t *)sessions;
            for (uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
                cow_c_session_t *session;
                session = &c_sessions[i];
                orilink_identity_t *identity = &session->identity;
                orilink_security_t *security = &session->security;
                if (*current_fd == session->hello1.timer_fd) {
                    uint64_t u;
                    read(session->hello1.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    if (session->hello1.ack_rcvd) {
//======================================================================
// Let The Timer Dies By Itself
//======================================================================
                        cleanup_control_packet(worker_ctx->label, &worker_ctx->async, &session->hello1, false);
                        LOG_DEVEL_DEBUG("%sTimer Retry Hello1 Closed", worker_ctx->label);
                        return SUCCESS;
                    }
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->hello1.sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello1.interval_timer_fd, session->hello1.sent_try_count);
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
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello1.interval_timer_fd);
                    double try_count = (double)session->hello1.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello1.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_control_packet(worker_ctx, identity, security, &session->hello1) != SUCCESS) {
                        return FAILURE;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->hello2.timer_fd) {
                    uint64_t u;
                    read(session->hello2.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    if (session->hello2.ack_rcvd) {
//======================================================================
// Let The Timer Dies By Itself
//======================================================================
                        cleanup_control_packet(worker_ctx->label, &worker_ctx->async, &session->hello2, false);
                        LOG_DEVEL_DEBUG("%sTimer Retry Hello2 Closed", worker_ctx->label);
                        return SUCCESS;
                    }
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->hello2.sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello2.interval_timer_fd, session->hello2.sent_try_count);
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
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello2.interval_timer_fd);
                    double try_count = (double)session->hello2.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello2.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_control_packet(worker_ctx, identity, security, &session->hello2) != SUCCESS) {
                        return FAILURE;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->hello3.timer_fd) {
                    uint64_t u;
                    read(session->hello3.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    if (session->hello3.ack_rcvd) {
//======================================================================
// Let The Timer Dies By Itself
//======================================================================
                        cleanup_control_packet(worker_ctx->label, &worker_ctx->async, &session->hello3, false);
                        LOG_DEVEL_DEBUG("%sTimer Retry Hello3 Closed", worker_ctx->label);
                        return SUCCESS;
                    }
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->hello3.sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello3.interval_timer_fd, session->hello3.sent_try_count);
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
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello3.interval_timer_fd);
                    double try_count = (double)session->hello3.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello3.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_control_packet(worker_ctx, identity, security, &session->hello3) != SUCCESS) {
                        return FAILURE;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->hello4.timer_fd) {
                    uint64_t u;
                    read(session->hello4.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    if (session->hello4.ack_rcvd) {
//======================================================================
// Let The Timer Dies By Itself
//======================================================================
                        cleanup_control_packet(worker_ctx->label, &worker_ctx->async, &session->hello4, false);
                        LOG_DEVEL_DEBUG("%sTimer Retry Hello4 Closed", worker_ctx->label);
                        return SUCCESS;
                    }
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->hello4.sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello4.interval_timer_fd, session->hello4.sent_try_count);
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
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello4.interval_timer_fd);
                    double try_count = (double)session->hello4.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello4.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_control_packet(worker_ctx, identity, security, &session->hello4) != SUCCESS) {
                        return FAILURE;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->heartbeat.timer_fd) {
                    uint64_t u;
                    read(session->heartbeat.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    if (session->heartbeat.ack_rcvd) {
//======================================================================
// Let The Timer Dies By Itself
//======================================================================
                        cleanup_control_packet(worker_ctx->label, &worker_ctx->async, &session->heartbeat, false);
                        LOG_DEVEL_DEBUG("%sTimer Retry Heartbeat Closed", worker_ctx->label);
                        return SUCCESS;
                    }
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->heartbeat.sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->heartbeat.interval_timer_fd, session->heartbeat.sent_try_count);
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
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->heartbeat.interval_timer_fd);
                    double try_count = (double)session->heartbeat.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->heartbeat.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_control_packet(worker_ctx, identity, security, &session->heartbeat) != SUCCESS) {
                        return FAILURE;
                    }
//======================================================================
// Heartbeat Ack Security 1 & Security 2 Open
//======================================================================
                    session->heartbeat.sent = true;
                    session->heartbeat.ack_rcvd = false;
                    return SUCCESS;
                } else if (*current_fd == session->heartbeat_sender_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_sender_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    if (
                        session->heartbeat_interval_extended_retrycount != 0x00 ||
                        session->heartbeat.timer_fd != -1
                    )
                    {
//======================================================================
// Retry Detected (Peer Retry || Our Retry)
//======================================================================
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
//======================================================================
                        uint8_t extended = session->heartbeat_interval_extended_retrycount;
                        session->heartbeat_interval_extended_retrycount = 0x00;
                        double timer_interval = pow((double)2, (double)extended)-(double)1;
                        timer_interval += pow((double)2, (double)session->retry.value_prediction);
                        LOG_DEVEL_DEBUG("%sRetry Detected. Add Interval To Heartbeat Timer Sender For %fsec", worker_ctx->label, timer_interval);
                        if (async_create_timerfd(worker_ctx->label, &session->heartbeat_sender_timer_fd) != SUCCESS) {
                            return FAILURE;
                        }
//======================================================================
                        if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat_sender_timer_fd,
                            (time_t)timer_interval,
                            (long)((timer_interval - (time_t)timer_interval) * 1e9),
                            (time_t)timer_interval,
                            (long)((timer_interval - (time_t)timer_interval) * 1e9)) != SUCCESS)
                        {
                            return FAILURE;
                        }
                        if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd) != SUCCESS) {
                            return FAILURE;
                        }
                        return SUCCESS;
                    }
//======================================================================
// Initialize session->heartbeat
//======================================================================
                    cleanup_control_packet(worker_ctx->label, &worker_ctx->async, &session->heartbeat, false);
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
                    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
                    if (current_time.status != SUCCESS) {
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        return FAILURE;
                    }
                    if (async_create_timerfd(worker_ctx->label, &session->heartbeat.timer_fd) != SUCCESS) {
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        return FAILURE;
                    }
                    session->heartbeat.sent_try_count++;
                    session->heartbeat.sent_time = current_time.r_uint64_t;
                    if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat.timer_fd,
                        (time_t)session->heartbeat.interval_timer_fd,
                        (long)((session->heartbeat.interval_timer_fd - (time_t)session->heartbeat.interval_timer_fd) * 1e9),
                        (time_t)session->heartbeat.interval_timer_fd,
                        (long)((session->heartbeat.interval_timer_fd - (time_t)session->heartbeat.interval_timer_fd) * 1e9)) != SUCCESS)
                    {
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        return FAILURE;
                    }
                    //printf("Hereeeeeeeeeeeeeeeeeeeee....... handlers.c SIO *current_fd == session->heartbeat_sender_timer_fd FD %d\n", session->heartbeat.timer_fd);
                    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat.timer_fd) != SUCCESS) {
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        return FAILURE;
                    }
//======================================================================
// Acumulate Different RTT Between Peers
//======================================================================
                    double hb_interval = (double)NODE_HEARTBEAT_INTERVAL * pow((double)2, (double)session->retry.value_prediction);
                    hb_interval += session->rtt.value_prediction / (double)1e9;
//======================================================================
                    orilink_identity_t *identity = &session->identity;
                    orilink_security_t *security = &session->security;
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
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        if (l_inc_ctr != 0xFF) {
                            decrement_ctr(&security->local_ctr, security->local_nonce);
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
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        if (l_inc_ctr != 0xFF) {
                            decrement_ctr(&security->local_ctr, security->local_nonce);
                        }
                        return FAILURE;
                    }
                    if (worker_master_udp_data(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &session->identity.remote_addr, &udp_data, &session->heartbeat) != SUCCESS) {
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        if (l_inc_ctr != 0xFF) {
                            decrement_ctr(&security->local_ctr, security->local_nonce);
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
                orilink_identity_t *identity = &session->identity;
                orilink_security_t *security = &session->security;
                if (*current_fd == session->heartbeat.timer_fd) {
                    uint64_t u;
                    read(session->heartbeat.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    if (session->heartbeat.ack_rcvd) {
//======================================================================
// Let The Timer Dies By Itself
//======================================================================
                        cleanup_control_packet(worker_ctx->label, &worker_ctx->async, &session->heartbeat, false);
                        LOG_DEVEL_DEBUG("%sTimer Retry Heartbeat Closed", worker_ctx->label);
                        return SUCCESS;
                    }
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->heartbeat.sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->heartbeat.interval_timer_fd, session->heartbeat.sent_try_count);
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
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->heartbeat.interval_timer_fd);
                    double try_count = (double)session->heartbeat.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->heartbeat.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_control_packet(worker_ctx, identity, security, &session->heartbeat) != SUCCESS) {
                        return FAILURE;
                    }
//======================================================================
// Heartbeat Ack Security 1 & Security 2 Open
//======================================================================
                    session->heartbeat.sent = true;
                    session->heartbeat.ack_rcvd = false;
                    return SUCCESS;
                } else if (*current_fd == session->heartbeat_sender_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_sender_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    if (
                        session->heartbeat_interval_extended_retrycount != 0x00 ||
                        session->heartbeat.timer_fd != -1
                    )
                    {
//======================================================================
// Retry Detected (Peer Retry || Our Retry)
//======================================================================
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
//======================================================================
                        uint8_t extended = session->heartbeat_interval_extended_retrycount;
                        session->heartbeat_interval_extended_retrycount = 0x00;
                        double timer_interval = pow((double)2, (double)extended)-(double)1;
                        timer_interval += pow((double)2, (double)session->retry.value_prediction);
                        LOG_DEVEL_DEBUG("%sRetry Detected. Add Interval To Heartbeat Timer Sender For %fsec", worker_ctx->label, timer_interval);
                        if (async_create_timerfd(worker_ctx->label, &session->heartbeat_sender_timer_fd) != SUCCESS) {
                            return FAILURE;
                        }
//======================================================================
                        if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat_sender_timer_fd,
                            (time_t)timer_interval,
                            (long)((timer_interval - (time_t)timer_interval) * 1e9),
                            (time_t)timer_interval,
                            (long)((timer_interval - (time_t)timer_interval) * 1e9)) != SUCCESS)
                        {
                            return FAILURE;
                        }
                        if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd) != SUCCESS) {
                            return FAILURE;
                        }
                        return SUCCESS;
                    }
//======================================================================
// Initialize session->heartbeat
//======================================================================
                    cleanup_control_packet(worker_ctx->label, &worker_ctx->async, &session->heartbeat, false);
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
                    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
                    if (current_time.status != SUCCESS) {
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        return FAILURE;
                    }
                    if (async_create_timerfd(worker_ctx->label, &session->heartbeat.timer_fd) != SUCCESS) {
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        return FAILURE;
                    }
                    session->heartbeat.sent_try_count++;
                    session->heartbeat.sent_time = current_time.r_uint64_t;
                    if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat.timer_fd,
                        (time_t)session->heartbeat.interval_timer_fd,
                        (long)((session->heartbeat.interval_timer_fd - (time_t)session->heartbeat.interval_timer_fd) * 1e9),
                        (time_t)session->heartbeat.interval_timer_fd,
                        (long)((session->heartbeat.interval_timer_fd - (time_t)session->heartbeat.interval_timer_fd) * 1e9)) != SUCCESS)
                    {
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        return FAILURE;
                    }
                    //printf("Hereeeeeeeeeeeeeeeeeeeee....... handlers.c SIO *current_fd == session->heartbeat_sender_timer_fd FD %d\n", session->heartbeat.timer_fd);
                    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat.timer_fd) != SUCCESS) {
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        return FAILURE;
                    }
//======================================================================
// Acumulate Different RTT Between Peers
//======================================================================
                    double hb_interval = (double)NODE_HEARTBEAT_INTERVAL * pow((double)2, (double)session->retry.value_prediction);
                    hb_interval += session->rtt.value_prediction / (double)1e9;
//======================================================================
                    orilink_identity_t *identity = &session->identity;
                    orilink_security_t *security = &session->security;
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
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        if (l_inc_ctr != 0xFF) {
                            decrement_ctr(&security->local_ctr, security->local_nonce);
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
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        if (l_inc_ctr != 0xFF) {
                            decrement_ctr(&security->local_ctr, security->local_nonce);
                        }
                        return FAILURE;
                    }
                    if (worker_master_udp_data(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &session->identity.remote_addr, &udp_data, &session->heartbeat) != SUCCESS) {
                        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
                        CLOSE_FD(&session->heartbeat_sender_timer_fd);
                        if (l_inc_ctr != 0xFF) {
                            decrement_ctr(&security->local_ctr, security->local_nonce);
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
