#include <stdint.h>
#include <math.h>
#include <stdio.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "orilink/protocol.h"
#include "workers/timer/handlers.h"

status_t handle_workers_ipc_udp_data_ack_cow(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol) {
    ipc_udp_data_ack_t *iudp_data_acki = received_protocol->payload.ipc_udp_data_ack;
    uint8_t index = received_protocol->index;
    uint8_t session_index = iudp_data_acki->session_index;
    cow_c_session_t *cow_c_session = (cow_c_session_t *)worker_sessions;
    cow_c_session_t *session = &cow_c_session[session_index];
    switch ((orilink_protocol_type_t)iudp_data_acki->orilink_protocol) {
        case ORILINK_HELLO1: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                double retry_timer_interval = pow((double)2, (double)session->retry.value_prediction);
                session->hello1.interval_timer_fd = retry_timer_interval;
                if (create_timer(worker_ctx, &session->hello1.timer_fd, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO2: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                double retry_timer_interval = pow((double)2, (double)session->retry.value_prediction);
                session->hello2.interval_timer_fd = retry_timer_interval;
                if (create_timer(worker_ctx, &session->hello2.timer_fd, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO3: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                double retry_timer_interval = pow((double)2, (double)session->retry.value_prediction);
                session->hello3.interval_timer_fd = retry_timer_interval;
                if (create_timer(worker_ctx, &session->hello3.timer_fd, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO4: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                double retry_timer_interval = pow((double)2, (double)session->retry.value_prediction);
                session->hello4.interval_timer_fd = retry_timer_interval;
                if (create_timer(worker_ctx, &session->hello4.timer_fd, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HEARTBEAT: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                double retry_timer_interval = pow((double)2, (double)session->retry.value_prediction);
                printf("%s===Initial Retry Interva %f ===\n", worker_ctx->label, retry_timer_interval);
                session->heartbeat.interval_timer_fd = retry_timer_interval;
                session->test_double_heartbeat++;
                if (
                    session->test_double_heartbeat == 7 ||
                    session->test_double_heartbeat == 9 ||
                    session->test_double_heartbeat == 11
                )
                {
                    LOG_DEVEL_DEBUG("[Debug Here Helper]: Heartbeat Packet Number %d. Test Burst/Double. Retry Interval To 0.000001", session->test_drop_heartbeat_ack);
                    retry_timer_interval = (double)0.000001;
                } else {
                    if (session->test_double_heartbeat >= 1000000) {
                        session->test_double_heartbeat = 0;
                    }
                }
                if (create_timer(worker_ctx, &session->heartbeat.timer_fd, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
                double timer_interval = session->heartbeat_interval;
                if (create_timer(worker_ctx, &session->heartbeat_openner_timer_fd, timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HEARTBEAT_ACK: {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        default:
            LOG_ERROR("%sUnknown ORILINK protocol type %d From Master To COW-%d[%d]. Ignoring.", worker_ctx->label, (orilink_protocol_type_t)iudp_data_acki->orilink_protocol, index, session_index);
            CLOSE_IPC_PROTOCOL(&received_protocol);
    }
    return SUCCESS;
}
