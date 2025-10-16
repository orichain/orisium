#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <endian.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "pqc.h"
#include "poly1305-donna.h"
#include "utilities.h"
#include "aes_custom.h"
#include "aes.h"

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
//----------------------------------------------------------------------
// Temporary Key
//----------------------------------------------------------------------
    uint8_t aes_key[HASHES_BYTES];
    kdf1(worker_ctx->kem_sharedsecret, aes_key);
    uint8_t local_nonce[AES_NONCE_BYTES];
    if (generate_nonce(worker_ctx->label, local_nonce) != SUCCESS) {
        LOG_ERROR("%sFailed to generate_nonce. Worker error. Initiating graceful shutdown...", worker_ctx->label);
        worker_ctx->shutdown_requested = 1;
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
// HELLO2 Memakai mac_key baru
//----------------------------------------------------------------------
    kdf2(aes_key, worker_ctx->mac_key);
//----------------------------------------------------------------------
    uint8_t wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
    uint8_t encrypted_wot_index1[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index2[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES];
    memcpy(encrypted_wot_index1, local_nonce, AES_NONCE_BYTES);
    memcpy(wot_index, (uint8_t *)worker_ctx->wot, sizeof(uint8_t));
    memcpy(wot_index + sizeof(uint8_t), worker_ctx->index, sizeof(uint8_t));
//======================================================================    
    aes256ctx aes_ctx;
    aes256_ctr_keyexp(&aes_ctx, aes_key);
//=========================================IV===========================    
    uint8_t keystream_buffer[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t iv[AES_IV_BYTES];
    memcpy(iv, local_nonce, AES_NONCE_BYTES);
    uint32_t local_ctr_be = htobe32(worker_ctx->local_ctr);
    memcpy(iv + AES_NONCE_BYTES, &local_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr_custom(keystream_buffer, sizeof(uint8_t) + sizeof(uint8_t), iv, &aes_ctx);
    for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t); i++) {
        encrypted_wot_index[i] = wot_index[i] ^ keystream_buffer[i];
    }
    aes256_ctx_release(&aes_ctx);
//======================================================================    
    memcpy(encrypted_wot_index1 + AES_NONCE_BYTES, encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
//======================================================================    
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context mac_ctx;
    poly1305_init(&mac_ctx, worker_ctx->mac_key);
    poly1305_update(&mac_ctx, encrypted_wot_index1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
    poly1305_finish(&mac_ctx, mac);
//====================================================================== 
    memcpy(encrypted_wot_index2, encrypted_wot_index1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
    memcpy(encrypted_wot_index2 + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t), mac, AES_TAG_BYTES);
//======================================================================
    if (worker_master_hello2(worker_ctx, encrypted_wot_index2) != SUCCESS) {
        LOG_ERROR("%sFailed to worker_master_hello2. Worker error. Initiating graceful shutdown...", worker_ctx->label);
        worker_ctx->shutdown_requested = 1;
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    memset(aes_key, 0, HASHES_BYTES);
    memcpy(worker_ctx->local_nonce, local_nonce, AES_NONCE_BYTES);
    memset(local_nonce, 0, AES_NONCE_BYTES);
    worker_ctx->local_ctr = (uint32_t)0;
    memcpy(worker_ctx->remote_nonce, ihello1_acki->nonce, AES_NONCE_BYTES);
    worker_ctx->hello1_ack_rcvd = true;
    CLOSE_IPC_PROTOCOL(&received_protocol);
    return SUCCESS;
}
