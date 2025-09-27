#include <stdint.h>
#include <math.h>
#include <unistd.h>

#include "types.h"
#include "workers/workers.h"
#include "workers/timer/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "constants.h"
#include "log.h"

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
                        LOG_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello1.interval_timer_fd, session->hello1.sent_try_count);
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
                        LOG_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello2.interval_timer_fd, session->hello2.sent_try_count);
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
                        LOG_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello3.interval_timer_fd, session->hello3.sent_try_count);
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
                        LOG_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello4.interval_timer_fd, session->hello4.sent_try_count);
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
                    if (session->heartbeat.sent_try_count > NODE_HEARTBEAT_MAX_RETRY) {
                        LOG_DEVEL_DEBUG("%sWaiting For Heartbeat Ack. Session %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->heartbeat.interval_timer_fd, session->heartbeat.sent_try_count);
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
                    LOG_DEVEL_DEBUG("%sWaiting For Heartbeat Ack. Session %d: interval = %lf.", worker_ctx->label, i, session->heartbeat.interval_timer_fd);
                    double try_count = (double)session->heartbeat.sent_try_count;
                    calculate_retry(worker_ctx->label, session, c_wot, try_count);
                    session->heartbeat.interval_timer_fd = (double)NODE_HEARTBEAT_INTERVAL * pow((double)2, (double)session->retry.value_prediction);
                    if (retry_packet(worker_ctx, session, &session->heartbeat) != SUCCESS) {
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
                        LOG_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello1_ack.interval_ack_timer_fd, session->hello1_ack.ack_sent_try_count);
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
                        LOG_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello2_ack.interval_ack_timer_fd, session->hello2_ack.ack_sent_try_count);
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
                        LOG_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello3_ack.interval_ack_timer_fd, session->hello3_ack.ack_sent_try_count);
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
                        LOG_DEBUG("%sSession %d: interval = %lf. Disconnect => try count %d.", worker_ctx->label, c_session_index, session->hello4_ack.interval_ack_timer_fd, session->hello4_ack.ack_sent_try_count);
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
                }
            }
            break;
        }
        default:
            return FAILURE;
    }
    return FAILURE;
}
