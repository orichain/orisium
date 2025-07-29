#include <stdint.h>
#include <endian.h>
#include <string.h>

#include "log.h"
#include "types.h"
#include "ipc/protocol.h"
#include "ipc/worker_master_heartbeat.h"
#include "ipc/worker_master_hello1.h"
#include "ipc/worker_master_hello2.h"
#include "ipc/cow_master_connection.h"
#include "workers/worker.h"
#include "constants.h"
#include "poly1305-donna.h"
#include "aes.h"
#include "stdbool.h"

struct sockaddr_in6;

status_t worker_master_heartbeat(worker_context_t *ctx, double new_heartbeat_interval_double) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_heartbeat(ctx->label, ctx->wot, ctx->idx, new_heartbeat_interval_double);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(ctx->label, &ctx->master_uds_fd, cmd_result.r_ipc_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_heartbeat to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_heartbeat to Master.", ctx->label);
    }
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t worker_master_hello1(worker_context_t *ctx) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello1(ctx->label, ctx->wot, ctx->idx, ctx->kem_publickey);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(ctx->label, &ctx->master_uds_fd, cmd_result.r_ipc_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_hello1 to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_hello1 to Master.", ctx->label);
    }
    ctx->hello1_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t worker_master_hello2(worker_context_t *ctx) {
    uint8_t wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
    uint8_t encrypted_wot_index1[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index2[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES];
    memcpy(encrypted_wot_index1, ctx->local_nonce, AES_NONCE_BYTES);
    memcpy(wot_index, (uint8_t *)&ctx->wot, sizeof(uint8_t));
    memcpy(wot_index + sizeof(uint8_t), &ctx->idx, sizeof(uint8_t));
//======================================================================    
    aes256ctx aes_ctx;
    aes256_ctr_keyexp(&aes_ctx, ctx->kem_sharedsecret);
//=========================================IV===========================    
    uint8_t keystream_buffer[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t iv[AES_IV_BYTES];
    memcpy(iv, ctx->local_nonce, AES_NONCE_BYTES);
    uint32_t local_ctr_be = htobe32(ctx->local_ctr);
    memcpy(iv + AES_NONCE_BYTES, &local_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr(keystream_buffer, sizeof(uint8_t) + sizeof(uint8_t), iv, &aes_ctx);
    for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t); i++) {
        encrypted_wot_index[i] = wot_index[i] ^ keystream_buffer[i];
    }
    aes256_ctx_release(&aes_ctx);
//======================================================================    
    memcpy(encrypted_wot_index1 + AES_NONCE_BYTES, encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
//======================================================================    
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context mac_ctx;
    poly1305_init(&mac_ctx, ctx->kem_sharedsecret);
    poly1305_update(&mac_ctx, encrypted_wot_index1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
    poly1305_finish(&mac_ctx, mac);
//====================================================================== 
    memcpy(encrypted_wot_index2, encrypted_wot_index1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
    memcpy(encrypted_wot_index2 + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t), mac, AES_TAG_BYTES);
//======================================================================
// Prinsip Local Crt dan Remote Crt
// Tambah Local Counter Jika Berhasil Encrypt    
// Tambah Remote Counter Jika Mac Cocok dan Berhasil Decrypt
//======================================================================
    ctx->local_ctr++;
//======================================================================
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello2(ctx->label, ctx->wot, ctx->idx, encrypted_wot_index2);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(ctx->label, &ctx->master_uds_fd, cmd_result.r_ipc_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_hello2 to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_hello2 to Master.", ctx->label);
    }
    ctx->hello2_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t cow_master_connection(worker_context_t *ctx, struct sockaddr_in6 *addr, connection_type_t flag) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_cow_master_connection(ctx->label, ctx->wot, ctx->idx, addr, flag);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(ctx->label, &ctx->master_uds_fd, cmd_result.r_ipc_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent cow_master_connection to master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent cow_master_connection to master.", ctx->label);
    }
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}
