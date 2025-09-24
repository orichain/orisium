#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "pqc.h"

status_t handle_workers_ipc_hello1_ack(worker_context_t *worker_ctx, ipc_raw_protocol_t_status_t *ircvdi) {
    if (!worker_ctx->hello1_sent) {
        LOG_ERROR("%sBelum pernah mengirim HELLO1", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    }
    if (worker_ctx->hello1_ack_rcvd) {
        LOG_ERROR("%sSudah ada HELLO1_ACK", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    }
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
    ipc_master_worker_hello1_ack_t *ihello1_acki = received_protocol->payload.ipc_master_worker_hello1_ack;
    memcpy(worker_ctx->kem_ciphertext, ihello1_acki->kem_ciphertext, KEM_CIPHERTEXT_BYTES);
    if (KEM_DECODE_SHAREDSECRET(worker_ctx->kem_sharedsecret, worker_ctx->kem_ciphertext, worker_ctx->kem_privatekey) != 0) {
        LOG_ERROR("%sFailed to KEM_DECODE_SHAREDSECRET. Worker error. Initiating graceful shutdown...", worker_ctx->label);
        worker_ctx->shutdown_requested = 1;
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    if (worker_master_hello2(worker_ctx) != SUCCESS) {
        LOG_ERROR("%sFailed to worker_master_hello2. Worker error. Initiating graceful shutdown...", worker_ctx->label);
        worker_ctx->shutdown_requested = 1;
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    memcpy(worker_ctx->remote_nonce, ihello1_acki->nonce, AES_NONCE_BYTES);
    worker_ctx->hello1_ack_rcvd = true;
    CLOSE_IPC_PROTOCOL(&received_protocol);
    return SUCCESS;
}
