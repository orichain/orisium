#include <stdint.h>
#include <math.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "orilink/protocol.h"
#include "workers/timer/handlers.h"
#include "utilities.h"

status_t handle_workers_ipc_udp_data_ack_cow(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol) {
    ipc_udp_data_ack_t *iudp_data_acki = received_protocol->payload.ipc_udp_data_ack;
    uint8_t index = received_protocol->index;
    uint8_t session_index = iudp_data_acki->session_index;
    cow_c_session_t *cow_c_session = (cow_c_session_t *)worker_sessions;
    cow_c_session_t *session = &cow_c_session[session_index];
    orilink_security_t *security = &session->security;
    switch ((orilink_protocol_type_t)iudp_data_acki->orilink_protocol) {
        case ORILINK_HELLO1: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                double retry_timer_interval = pow((double)2, (double)session->retry.value_prediction);
                if (create_polling_1ms(worker_ctx, &session->hello1, retry_timer_interval) != SUCCESS) {
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
                if (create_polling_1ms(worker_ctx, &session->hello2, retry_timer_interval) != SUCCESS) {
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
                if (create_polling_1ms(worker_ctx, &session->hello3, retry_timer_interval) != SUCCESS) {
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
                if (create_polling_1ms(worker_ctx, &session->hello4, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HEARTBEAT: {
            if (iudp_data_acki->status != SUCCESS) {
                decrement_ctr(&security->local_ctr, security->local_nonce);
                return SUCCESS;
            }
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                double retry_timer_interval = pow((double)2, (double)session->retry.value_prediction);
                if (create_polling_1ms(worker_ctx, &session->heartbeat, retry_timer_interval) != SUCCESS) {
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
