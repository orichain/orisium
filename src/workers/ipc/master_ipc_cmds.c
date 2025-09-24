#include <string.h>
#include <inttypes.h>
#include <endian.h>
#include <stdlib.h>

#include "log.h"
#include "types.h"
#include "ipc/protocol.h"
#include "ipc/worker_master_heartbeat.h"
#include "ipc/worker_master_hello1.h"
#include "ipc/worker_master_hello2.h"
#include "workers/workers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "constants.h"
#include "poly1305-donna.h"
#include "aes.h"
#include "stdbool.h"
#include "utilities.h"
#include "ipc/udp_data.h"

struct sockaddr_in6;

status_t worker_master_heartbeat(worker_context_t *ctx, double new_heartbeat_interval_double) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_heartbeat(
        ctx->label, 
        *ctx->wot, 
        *ctx->index, 
        new_heartbeat_interval_double
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        ctx->label, 
        ctx->aes_key,
        ctx->mac_key,
        ctx->local_nonce,
        &ctx->local_ctr,
        ctx->master_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
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
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello1(
        ctx->label, 
        *ctx->wot, 
        *ctx->index, 
        ctx->kem_publickey
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        ctx->label, 
        ctx->aes_key,
        ctx->mac_key,
        ctx->local_nonce,
        &ctx->local_ctr,
        ctx->master_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
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
//----------------------------------------------------------------------
// Temporary Key
//----------------------------------------------------------------------
    uint8_t aes_key[HASHES_BYTES];
    kdf1(ctx->kem_sharedsecret, aes_key);
    uint8_t local_nonce[AES_NONCE_BYTES];
    if (generate_nonce(ctx->label, local_nonce) != SUCCESS) {
        LOG_ERROR("%sFailed to generate_nonce.", ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------
// HELLO2 Memakai mac_key baru
//----------------------------------------------------------------------
    kdf2(aes_key, ctx->mac_key);
//----------------------------------------------------------------------
    uint8_t wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
    uint8_t encrypted_wot_index1[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index2[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES];
    memcpy(encrypted_wot_index1, local_nonce, AES_NONCE_BYTES);
    memcpy(wot_index, (uint8_t *)ctx->wot, sizeof(uint8_t));
    memcpy(wot_index + sizeof(uint8_t), ctx->index, sizeof(uint8_t));
//======================================================================    
    aes256ctx aes_ctx;
    aes256_ctr_keyexp(&aes_ctx, aes_key);
//=========================================IV===========================    
    uint8_t keystream_buffer[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t iv[AES_IV_BYTES];
    memcpy(iv, local_nonce, AES_NONCE_BYTES);
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
    poly1305_init(&mac_ctx, ctx->mac_key);
    poly1305_update(&mac_ctx, encrypted_wot_index1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
    poly1305_finish(&mac_ctx, mac);
//====================================================================== 
    memcpy(encrypted_wot_index2, encrypted_wot_index1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
    memcpy(encrypted_wot_index2 + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t), mac, AES_TAG_BYTES);
//======================================================================
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello2(
        ctx->label, 
        *ctx->wot, 
        *ctx->index, 
        encrypted_wot_index2
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        ctx->label, 
        ctx->aes_key,
        ctx->mac_key,
        ctx->local_nonce,
        &ctx->local_ctr,
        ctx->master_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_hello2 to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_hello2 to Master.", ctx->label);
    }
    memset(aes_key, 0, HASHES_BYTES);
    memcpy(ctx->local_nonce, local_nonce, AES_NONCE_BYTES);
    memset(local_nonce, 0, AES_NONCE_BYTES);
    ctx->local_ctr = (uint32_t)0;
    ctx->hello2_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t worker_master_udp_data(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    struct sockaddr_in6 *addr,
    puint8_t_size_t_status_t *r,
    hello_t *h
) 
{
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data(
        label,
        wot,
        index,
        0xff,
        addr,
        r->r_size_t,
        r->r_puint8_t
    );
    if (cmd_result.status != SUCCESS) {
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        worker_ctx->label,
        worker_ctx->aes_key,
        worker_ctx->mac_key,
        worker_ctx->local_nonce,
        &worker_ctx->local_ctr,
        worker_ctx->master_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
    }
    h->len = r->r_size_t;
    h->data = (uint8_t *)calloc(1, r->r_size_t);
    memcpy(h->data, r->r_puint8_t, h->len);
    free(r->r_puint8_t);
    r->r_puint8_t = NULL;
    r->r_size_t = 0;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t worker_master_udp_data_ack(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    struct sockaddr_in6 *addr,
    puint8_t_size_t_status_t *r,
    hello_ack_t *h
) 
{
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data(
        label,
        wot,
        index,
        0xff,
        addr,
        r->r_size_t,
        r->r_puint8_t
    );
    if (cmd_result.status != SUCCESS) {
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        worker_ctx->label,
        worker_ctx->aes_key,
        worker_ctx->mac_key,
        worker_ctx->local_nonce,
        &worker_ctx->local_ctr,
        worker_ctx->master_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
    }
    h->len = r->r_size_t;
    h->data = (uint8_t *)calloc(1, r->r_size_t);
    memcpy(h->data, r->r_puint8_t, h->len);
    free(r->r_puint8_t);
    r->r_puint8_t = NULL;
    r->r_size_t = 0;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}
