#include <stdint.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"

status_t handle_workers_ipc_udp_data(worker_context_t *worker_ctx, void *worker_sessions, ipc_raw_protocol_t_status_t *ircvdi) {
    worker_type_t remote_wot = UNKNOWN;
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
        worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    } else {
        remote_wot = ircvdi->r_ipc_raw_protocol_t->wot;
        LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t *received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    switch (remote_wot) {
//----------------------------------------------------------------------
// UDP Data From Remote COW
//----------------------------------------------------------------------
        case COW: {
            if (handle_workers_ipc_udp_data_cow(worker_ctx, worker_sessions, received_protocol) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
//----------------------------------------------------------------------
// UDP Data From Remote SIO
//----------------------------------------------------------------------
        case SIO: {
            if (handle_workers_ipc_udp_data_sio(worker_ctx, worker_sessions, received_protocol) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
//----------------------------------------------------------------------
        default:
            LOG_ERROR("%sUnknown Source. UDP Remote Worker %d. Ignoring.", worker_ctx->label, remote_wot);
            CLOSE_IPC_PROTOCOL(&received_protocol);
    }
    return SUCCESS;
}
