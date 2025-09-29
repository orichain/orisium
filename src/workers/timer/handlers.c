#include <math.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

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
                if (*current_fd == session->hello1.timer_fd) {
                    uint64_t u;
                    read(session->hello1.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
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
                            continue;
                        }
                        if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        return SUCCESS;
                    }
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello1.interval_timer_fd);
                    double try_count = (double)session->hello1.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello1.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_packet(worker_ctx, session, &session->hello1) != SUCCESS) {
                        continue;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->hello2.timer_fd) {
                    uint64_t u;
                    read(session->hello2.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
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
                            continue;
                        }
                        if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        return SUCCESS;
                    }
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello2.interval_timer_fd);
                    double try_count = (double)session->hello2.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello2.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_packet(worker_ctx, session, &session->hello2) != SUCCESS) {
                        continue;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->hello3.timer_fd) {
                    uint64_t u;
                    read(session->hello3.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
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
                            continue;
                        }
                        if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        return SUCCESS;
                    }
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello3.interval_timer_fd);
                    double try_count = (double)session->hello3.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello3.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_packet(worker_ctx, session, &session->hello3) != SUCCESS) {
                        continue;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->hello4.timer_fd) {
                    uint64_t u;
                    read(session->hello4.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
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
                            continue;
                        }
                        if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        return SUCCESS;
                    }
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello4.interval_timer_fd);
                    double try_count = (double)session->hello4.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello4.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_packet(worker_ctx, session, &session->hello4) != SUCCESS) {
                        continue;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->heartbeat.timer_fd) {
                    uint64_t u;
                    read(session->heartbeat.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
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
                            continue;
                        }
                        if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        return SUCCESS;
                    }
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->heartbeat.interval_timer_fd);
                    double try_count = (double)session->heartbeat.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->heartbeat.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_packet(worker_ctx, session, &session->heartbeat) != SUCCESS) {
                        continue;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->heartbeat_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
                    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
                    if (current_time.status != SUCCESS) {
                        return FAILURE;
                    }
                    if (async_create_timerfd(worker_ctx->label, &session->heartbeat.timer_fd) != SUCCESS) {
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
                        return FAILURE;
                    }
                    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat.timer_fd) != SUCCESS) {
                        return FAILURE;
                    }
//======================================================================
                    double hb_interval = (double)NODE_HEARTBEAT_INTERVAL * pow((double)2, (double)session->retry.value_prediction);
//======================================================================
                    orilink_identity_t *identity = &session->identity;
                    orilink_security_t *security = &session->security;
                    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat(
                        worker_ctx->label,
                        0x01,
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
                        return FAILURE;
                    }
//======================================================================
// Test Packet Dropped
//======================================================================
                    session->test_drop_heartbeat++;
                    if (session->test_drop_heartbeat == 5) {
                        printf("[Debug Here Helper]: Heartbeat Packet Number %d. Sending To Fake Addr To Force Retry\n", session->test_drop_heartbeat);
                        struct sockaddr_in6 fake_addr;
                        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
                        if (worker_master_udp_data(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &fake_addr, &udp_data, &session->heartbeat) != SUCCESS) {
                            return FAILURE;
                        }
                    } else {
                        printf("[Debug Here Helper]: Heartbeat Packet Number %d\n", session->test_drop_heartbeat);
                        if (worker_master_udp_data(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &session->identity.remote_addr, &udp_data, &session->heartbeat) != SUCCESS) {
                            return FAILURE;
                        }
                        if (session->test_drop_heartbeat >= 25) {
                            session->test_drop_heartbeat = 0;
                        }
                    }
                    async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_timer_fd);
                    CLOSE_FD(&session->heartbeat_timer_fd);
//======================================================================
                    session->heartbeat.sent = true;
//======================================================================
                    return SUCCESS;
                } else if (*current_fd == session->heartbeat_fin.timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_fin.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->heartbeat_fin.sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->heartbeat_fin.interval_timer_fd, session->heartbeat_fin.sent_try_count);
//----------------------------------------------------------------------
// Disconnected => 1. Reset Session
//                 2. Send Info To Master
//----------------------------------------------------------------------
                        cleanup_cow_session(worker_ctx->label, &worker_ctx->async, session);
                        if (setup_cow_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                            continue;
                        }
                        if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        return SUCCESS;
                    }
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->heartbeat_fin.interval_timer_fd);
                    double try_count = (double)session->heartbeat_fin.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->heartbeat_fin.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_heartbeat_fin(worker_ctx, session) != SUCCESS) {
                        continue;
                    }
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
                if (*current_fd == session->hello1_ack.ack_timer_fd) {
                    uint64_t u;
                    read(session->hello1_ack.ack_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->hello1_ack.ack_sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello1_ack.interval_ack_timer_fd, session->hello1_ack.ack_sent_try_count);
//----------------------------------------------------------------------
// Disconnected => 1. Reset Session
//                 2. Send Info To Master
//----------------------------------------------------------------------
                        cleanup_sio_session(worker_ctx->label, &worker_ctx->async, session);
                        if (setup_sio_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                            continue;
                        }
                        if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        return SUCCESS;
                    }
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello1_ack.interval_ack_timer_fd);
                    double try_count = (double)session->hello1_ack.ack_sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello1_ack.interval_ack_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_packet_ack(worker_ctx, session, &session->hello1_ack) != SUCCESS) {
                        continue;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->hello2_ack.ack_timer_fd) {
                    uint64_t u;
                    read(session->hello2_ack.ack_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->hello2_ack.ack_sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello2_ack.interval_ack_timer_fd, session->hello2_ack.ack_sent_try_count);
//----------------------------------------------------------------------
// Disconnected => 1. Reset Session
//                 2. Send Info To Master
//----------------------------------------------------------------------
                        cleanup_sio_session(worker_ctx->label, &worker_ctx->async, session);
                        if (setup_sio_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                            continue;
                        }
                        if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        return SUCCESS;
                    }
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello2_ack.interval_ack_timer_fd);
                    double try_count = (double)session->hello2_ack.ack_sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello2_ack.interval_ack_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_packet_ack(worker_ctx, session, &session->hello2_ack) != SUCCESS) {
                        continue;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->hello3_ack.ack_timer_fd) {
                    uint64_t u;
                    read(session->hello3_ack.ack_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->hello3_ack.ack_sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello3_ack.interval_ack_timer_fd, session->hello3_ack.ack_sent_try_count);
//----------------------------------------------------------------------
// Disconnected => 1. Reset Session
//                 2. Send Info To Master
//----------------------------------------------------------------------
                        cleanup_sio_session(worker_ctx->label, &worker_ctx->async, session);
                        if (setup_sio_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                            continue;
                        }
                        if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        return SUCCESS;
                    }
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello3_ack.interval_ack_timer_fd);
                    double try_count = (double)session->hello3_ack.ack_sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello3_ack.interval_ack_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_packet_ack(worker_ctx, session, &session->hello3_ack) != SUCCESS) {
                        continue;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->hello4_ack.ack_timer_fd) {
                    uint64_t u;
                    read(session->hello4_ack.ack_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->hello4_ack.ack_sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello4_ack.interval_ack_timer_fd, session->hello4_ack.ack_sent_try_count);
//----------------------------------------------------------------------
// Disconnected => 1. Reset Session
//                 2. Send Info To Master
//----------------------------------------------------------------------
                        cleanup_sio_session(worker_ctx->label, &worker_ctx->async, session);
                        if (setup_sio_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                            continue;
                        }
                        if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        return SUCCESS;
                    }
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->hello4_ack.interval_ack_timer_fd);
                    double try_count = (double)session->hello4_ack.ack_sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->hello4_ack.interval_ack_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_packet_ack(worker_ctx, session, &session->hello4_ack) != SUCCESS) {
                        continue;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->heartbeat_ack.ack_timer_fd) {
                    uint64_t u;
                    read(session->heartbeat_ack.ack_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    worker_type_t c_wot = session->identity.local_wot;
                    uint8_t c_index = session->identity.local_index;
                    uint8_t c_session_index = session->identity.local_session_index;
                    if (session->heartbeat_ack.ack_sent_try_count > MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->heartbeat_ack.interval_ack_timer_fd, session->heartbeat_ack.ack_sent_try_count);
//----------------------------------------------------------------------
// Disconnected => 1. Reset Session
//                 2. Send Info To Master
//----------------------------------------------------------------------
                        cleanup_sio_session(worker_ctx->label, &worker_ctx->async, session);
                        if (setup_sio_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                            continue;
                        }
                        if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        return SUCCESS;
                    }
                    LOG_DEBUG("%sSession %d: interval = %lf.", worker_ctx->label, i, session->heartbeat_ack.interval_ack_timer_fd);
                    double try_count = (double)session->heartbeat_ack.ack_sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->heartbeat_ack.interval_ack_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                    if (retry_packet_ack(worker_ctx, session, &session->heartbeat_ack) != SUCCESS) {
                        continue;
                    }
                    return SUCCESS;
                } else if (*current_fd == session->heartbeat_openner_fd) {
                    uint64_t u;
                    read(session->heartbeat_openner_fd, &u, sizeof(u)); //Jangan lupa read event timer
                    if (!session->remote_heartbeat_fin_ack_not_reveived) {
                        session->heartbeat_ack.rcvd = false;
                    }
                    async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_openner_fd);
                    CLOSE_FD(&session->heartbeat_openner_fd);
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
