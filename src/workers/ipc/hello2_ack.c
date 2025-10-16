#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"

status_t handle_workers_ipc_hello2_ack(worker_context_t *worker_ctx, ipc_raw_protocol_t_status_t *ircvdi) {
    if (!worker_ctx->hello2_sent) {
        LOG_ERROR("%sBelum pernah mengirim HELLO2", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    }
    if (worker_ctx->hello2_ack_rcvd) {
        LOG_ERROR("%sSudah ada HELLO2_ACK", worker_ctx->label);
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
    ipc_master_worker_hello2_ack_t *ihello2_acki = received_protocol->payload.ipc_master_worker_hello2_ack;
//======================================================================
// Ambil remote_nonce
// Set remote_ctr = 0
// Ambil encrypter wot+index
// Ambil Mac
// Cocokkan MAc
// Decrypt wot dan index
//======================================================================
    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
    memcpy(encrypted_wot_index, ihello2_acki->encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
    uint8_t data_mac[AES_TAG_BYTES];
    memcpy(data_mac, ihello2_acki->encrypted_wot_index + sizeof(uint8_t) + sizeof(uint8_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// Tmp aes_key
//----------------------------------------------------------------------
    uint8_t aes_key[HASHES_BYTES];
    kdf1(worker_ctx->kem_sharedsecret, aes_key);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
    const size_t data_len_0 = sizeof(uint8_t) + sizeof(uint8_t);
    if (compare_mac(
            worker_ctx->mac_key,
            encrypted_wot_index,
            data_len_0,
            data_mac
        ) != SUCCESS
    )
    {
        LOG_ERROR("%sIPC Hello2 Ack Mac mismatch!", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE_MACMSMTCH;
    }
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
    uint8_t decrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
    const size_t data_len = sizeof(uint8_t) + sizeof(uint8_t);
    if (encrypt_decrypt(
            worker_ctx->label,
            aes_key,
            worker_ctx->remote_nonce,
            &worker_ctx->remote_ctr,
            encrypted_wot_index,
            decrypted_wot_index,
            data_len
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
// Mencocokkan wot index
//----------------------------------------------------------------------
    worker_type_t data_wot;
    memcpy((uint8_t *)&data_wot, decrypted_wot_index, sizeof(uint8_t));
    if (*(uint8_t *)worker_ctx->wot != *(uint8_t *)&data_wot) {
        LOG_ERROR("%sberbeda wot. Worker error...", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    uint8_t data_index;
    memcpy(&data_index, decrypted_wot_index + sizeof(uint8_t), sizeof(uint8_t));
    if (*worker_ctx->index != data_index) {
        LOG_ERROR("%sberbeda index. Worker error...", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    if (!worker_ctx->is_rekeying) {
//----------------------------------------------------------------------
// Aktifkan Heartbeat Karna security/Enkripsi Sudah Ready
//---------------------------------------------------------------------- 
        status_t chst = create_timer_oneshot(worker_ctx->label, &worker_ctx->async, &worker_ctx->heartbeat_timer_fd, (double)WORKER_HEARTBEAT_INTERVAL);
        if (chst != SUCCESS) {
            LOG_ERROR("%sWorker error async_create_timerfd...", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            return FAILURE;
        }
    } else {
        worker_ctx->is_rekeying = false;
        ipc_protocol_queue_t *current = worker_ctx->rekeying_queue;
        ipc_protocol_queue_t *next;
        while (current != NULL) {
            next = current->next;
            ssize_t_status_t send_result = send_ipc_protocol_message(
                worker_ctx->label, 
                worker_ctx->aes_key,
                worker_ctx->mac_key,
                worker_ctx->local_nonce,
                &worker_ctx->local_ctr,
                current->uds_fd,
                current->p
            );
            if (send_result.status != SUCCESS) {
                LOG_ERROR("%sFailed to sent rekeying queue data to Master.", worker_ctx->label);
            } else {
                LOG_DEBUG("%sSent rekeying queue data to Master.", worker_ctx->label);
            }
            CLOSE_IPC_PROTOCOL(&current->p);
            free(current);
            current = next;
        }
        worker_ctx->rekeying_queue = NULL;
    }
//----------------------------------------------------------------------
// Menganggap data valid dengan integritas
//---------------------------------------------------------------------- 
    memcpy(worker_ctx->aes_key, aes_key, HASHES_BYTES);
    memset(aes_key, 0, HASHES_BYTES);
    worker_ctx->remote_ctr = (uint32_t)0;
    worker_ctx->hello2_ack_rcvd = true;
//---------------------------------------------------------------------- 
    CLOSE_IPC_PROTOCOL(&received_protocol);
    return SUCCESS;
}
