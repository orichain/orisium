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

status_t handle_workers_ipc_udp_data_ack_sio(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol) {
    ipc_udp_data_ack_t *iudp_data_acki = received_protocol->payload.ipc_udp_data_ack;
    uint8_t index = received_protocol->index;
    uint8_t session_index = iudp_data_acki->session_index;
    sio_c_session_t *sio_c_session = (sio_c_session_t *)worker_sessions;
    sio_c_session_t *session = &sio_c_session[session_index];
    orilink_security_t *security = &session->security;
    switch ((orilink_protocol_type_t)iudp_data_acki->orilink_protocol) {
        case ORILINK_HELLO1_ACK: {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO2_ACK: {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO3_ACK: {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO4_ACK: {
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
            LOG_ERROR("%sUnknown ORILINK protocol type %d From Master To SIO-%d[%d]. Ignoring.", worker_ctx->label, (orilink_protocol_type_t)iudp_data_acki->orilink_protocol, index, session_index);
            CLOSE_IPC_PROTOCOL(&received_protocol);
    }
    return SUCCESS;
}
