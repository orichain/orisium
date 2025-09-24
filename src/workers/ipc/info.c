#include <stdint.h>
#include <stdbool.h>

#include "log.h"
#include "ipc/protocol.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "pqc.h"

status_t handle_workers_ipc_info(worker_context_t *worker_ctx, double *initial_delay_ms, ipc_raw_protocol_t_status_t *ircvdi) {
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
        worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_master_worker_info_t *iinfoi = received_protocol->payload.ipc_master_worker_info;
    switch (iinfoi->flag) {
        case IT_SHUTDOWN: {
            LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            worker_ctx->shutdown_requested = 1;
            break;
        }
        case IT_READY: {
            LOG_INFO("%sMaster Ready ...", worker_ctx->label);
//----------------------------------------------------------------------
            if (*initial_delay_ms > 0) {
                LOG_DEBUG("%sApplying initial delay of %ld ms...", worker_ctx->label, *initial_delay_ms);
                sleep_ms(*initial_delay_ms);
            }
//----------------------------------------------------------------------
            if (KEM_GENERATE_KEYPAIR(worker_ctx->kem_publickey, worker_ctx->kem_privatekey) != 0) {
                LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", worker_ctx->label);
                worker_ctx->shutdown_requested = 1;
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            if (worker_master_hello1(worker_ctx) != SUCCESS) {
                LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
                worker_ctx->shutdown_requested = 1;
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case IT_REKEYING: {
            LOG_INFO("%sMaster Rekeying ...", worker_ctx->label);
//----------------------------------------------------------------------
            if (*initial_delay_ms > 0) {
                LOG_DEBUG("%sApplying initial delay of %ld ms...", worker_ctx->label, *initial_delay_ms);
                sleep_ms(*initial_delay_ms);
            }
//----------------------------------------------------------------------
            if (KEM_GENERATE_KEYPAIR(worker_ctx->kem_publickey, worker_ctx->kem_privatekey) != 0) {
                LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", worker_ctx->label);
                worker_ctx->shutdown_requested = 1;
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            if (async_delete_event(worker_ctx->label, &worker_ctx->async, &worker_ctx->heartbeat_timer_fd) != SUCCESS) {		
                LOG_INFO("%sGagal async_delete_event hb timer, Untuk Rekeying", worker_ctx->label);
                worker_ctx->shutdown_requested = 1;
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            CLOSE_FD(&worker_ctx->heartbeat_timer_fd);
            worker_ctx->hello1_sent = false;
            worker_ctx->hello1_ack_rcvd = false;
            worker_ctx->hello2_sent = false;
            worker_ctx->hello2_ack_rcvd = false;
            if (worker_master_hello1(worker_ctx) != SUCCESS) {
                LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
                worker_ctx->shutdown_requested = 1;
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        default:
            LOG_ERROR("%sUnknown Info Flag %d from Master. Ignoring.", worker_ctx->label, iinfoi->flag);
            CLOSE_IPC_PROTOCOL(&received_protocol);
    }
    return SUCCESS;
}
