#include <stddef.h>
#include <stdint.h>
#include <endian.h>
#include <string.h>

#include "log.h"
#include "constants.h"
#include "utilities.h"
#include "types.h"
#include "master/process.h"
#include "ipc/protocol.h"
#include "ipc/master_worker_info.h"
#include "ipc/master_worker_hello1_ack.h"
#include "ipc/master_worker_hello2_ack.h"
#include "ipc/master_cow_connect.h"
#include "poly1305-donna.h"
#include "aes.h"
#include "sessions/master_session.h"
#include "stdbool.h"

struct sockaddr_in6;

status_t master_worker_info(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, info_type_t flag) {
    worker_security_t * security = NULL;
    uds_pair_pid_t *upp = NULL;
    if (wot == SIO) {
        security = &master_ctx->sio_session[index].security;
        upp = &master_ctx->sio_session[index].upp;
    } else if (wot == LOGIC) {
        security = &master_ctx->logic_session[index].security;
        upp = &master_ctx->logic_session[index].upp;
    } else if (wot == COW) {
        security = &master_ctx->cow_session[index].security;
        upp = &master_ctx->cow_session[index].upp;
    } else if (wot == DBR) {
        security = &master_ctx->dbr_session[index].security;
        upp = &master_ctx->dbr_session[index].upp;
    } else if (wot == DBW) {
        security = &master_ctx->dbw_session[index].security;
        upp = &master_ctx->dbw_session[index].upp;
    } else {
        return FAILURE;
    }
    if (!security || !upp) return FAILURE;
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_info(label, wot, index, flag);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        label, 
        security->aes_key,
        security->mac_key,
        security->local_nonce,
        &security->local_ctr,
        &upp->uds[0], 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent master_worker_info to worker.", label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sSent master_worker_info to worker.", label);
    }
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}

status_t master_workers_info(const char *label, master_context_t *master_ctx, info_type_t flag) {
	for (uint8_t i = 0; i < MAX_SIO_WORKERS; ++i) { 
		if (master_worker_info(label, master_ctx, SIO, i, flag) != SUCCESS) return FAILURE;
	}
	for (uint8_t i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		if (master_worker_info(label, master_ctx, LOGIC, i, flag) != SUCCESS) return FAILURE;
	}
	for (uint8_t i = 0; i < MAX_COW_WORKERS; ++i) { 
		if (master_worker_info(label, master_ctx, COW, i, flag) != SUCCESS) return FAILURE;
	}
    for (uint8_t i = 0; i < MAX_DBR_WORKERS; ++i) { 
		if (master_worker_info(label, master_ctx, DBR, i, flag) != SUCCESS) return FAILURE;
	}
    for (uint8_t i = 0; i < MAX_DBW_WORKERS; ++i) { 
		if (master_worker_info(label, master_ctx, DBW, i, flag) != SUCCESS) return FAILURE;
	}
	return SUCCESS;
}

status_t master_cow_connect(const char *label, master_context_t *master_ctx, struct sockaddr_in6 *addr, uint8_t index) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_cow_connect(label, COW, index, addr);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        label, 
        master_ctx->cow_session[index].security.aes_key,
        master_ctx->cow_session[index].security.mac_key,
        master_ctx->cow_session[index].security.local_nonce,
        &master_ctx->cow_session[index].security.local_ctr,
        &master_ctx->cow_session[index].upp.uds[0], 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent master_cow_connect to COW %ld.", label, index);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sSent master_cow_connect to COW %ld.", label, index);
    }
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}

status_t master_worker_hello1_ack(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
    uint8_t *kem_ciphertext = NULL;
    worker_security_t *security = NULL;
    int *worker_uds_fd = NULL;
    const char *worker_name = "Unknown";
    if (wot == SIO) {
        kem_ciphertext = master_ctx->sio_session[index].security.kem_ciphertext;
        security = &master_ctx->sio_session[index].security;
        worker_uds_fd = &master_ctx->sio_session[index].upp.uds[0];
        worker_name = "SIO";
    } else if (wot == LOGIC) {
        kem_ciphertext = master_ctx->logic_session[index].security.kem_ciphertext;
        security = &master_ctx->logic_session[index].security;
        worker_uds_fd = &master_ctx->logic_session[index].upp.uds[0];
        worker_name = "Logic";
    } else if (wot == COW) {
        kem_ciphertext = master_ctx->cow_session[index].security.kem_ciphertext;
        security = &master_ctx->cow_session[index].security;
        worker_uds_fd = &master_ctx->cow_session[index].upp.uds[0];
        worker_name = "COW";
    } else if (wot == DBR) {
        kem_ciphertext = master_ctx->dbr_session[index].security.kem_ciphertext;
        security = &master_ctx->dbr_session[index].security;
        worker_uds_fd = &master_ctx->dbr_session[index].upp.uds[0];
        worker_name = "DBR";
    } else if (wot == DBW) {
        kem_ciphertext = master_ctx->dbw_session[index].security.kem_ciphertext;
        security = &master_ctx->dbw_session[index].security;
        worker_uds_fd = &master_ctx->dbw_session[index].upp.uds[0];
        worker_name = "DBW";
    } else {
        return FAILURE;
    }
    if (!security || !kem_ciphertext || *worker_uds_fd == -1) return FAILURE;
    uint8_t tmp_local_nonce[AES_NONCE_BYTES];
    if (generate_nonce(label, tmp_local_nonce) != SUCCESS) {
        LOG_ERROR("%sFailed to generate_nonce.", label);
        return FAILURE;
    }
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_hello1_ack(
        label, 
        wot, 
        index, 
        tmp_local_nonce,
        kem_ciphertext
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        label, 
        security->aes_key,
        security->mac_key,
        security->local_nonce,
        &security->local_ctr,
        worker_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent master_worker_hello1_ack to %s %ld.", label, worker_name, index);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sSent master_worker_hello1_ack to %s %ld.", label, worker_name, index);
    }
    memcpy(security->local_nonce, tmp_local_nonce, AES_NONCE_BYTES);
    memset(tmp_local_nonce, 0, AES_NONCE_BYTES);
    security->hello1_ack_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}

status_t master_worker_hello2_ack(const char *label, master_context_t *master_ctx, worker_type_t wot, int index) {
    worker_security_t *security = NULL;
    int *worker_uds_fd = NULL;
    const char *worker_name = "Unknown";
    if (wot == SIO) {
        security = &master_ctx->sio_session[index].security;
        worker_uds_fd = &master_ctx->sio_session[index].upp.uds[0];
        worker_name = "SIO";
    } else if (wot == LOGIC) {
        security = &master_ctx->logic_session[index].security;
        worker_uds_fd = &master_ctx->logic_session[index].upp.uds[0];
        worker_name = "Logic";
    } else if (wot == COW) {
        security = &master_ctx->cow_session[index].security;
        worker_uds_fd = &master_ctx->cow_session[index].upp.uds[0];
        worker_name = "COW";
    } else if (wot == DBR) {
        security = &master_ctx->dbr_session[index].security;
        worker_uds_fd = &master_ctx->dbr_session[index].upp.uds[0];
        worker_name = "DBR";
    } else if (wot == DBW) {
        security = &master_ctx->dbw_session[index].security;
        worker_uds_fd = &master_ctx->dbw_session[index].upp.uds[0];
        worker_name = "DBW";
    } else {
        return FAILURE;
    }
    if (!security || *worker_uds_fd == -1) return FAILURE;
    uint8_t wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
    uint8_t encrypted_wot_index1[sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES];
    memcpy(wot_index, (uint8_t *)&wot, sizeof(uint8_t));
    memcpy(wot_index + sizeof(uint8_t), &index, sizeof(uint8_t));
//----------------------------------------------------------------------
// Tmp aes_key
//----------------------------------------------------------------------
    uint8_t tmp_aes_key[HASHES_BYTES];
    kdf1(security->kem_sharedsecret, tmp_aes_key);
//======================================================================    
    aes256ctx aes_ctx;
    aes256_ctr_keyexp(&aes_ctx, tmp_aes_key);
//=========================================IV===========================    
    uint8_t keystream_buffer[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t iv[AES_IV_BYTES];
    memcpy(iv, security->local_nonce, AES_NONCE_BYTES);
    uint32_t local_ctr_be = htobe32(security->local_ctr);
    memcpy(iv + AES_NONCE_BYTES, &local_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr(keystream_buffer, sizeof(uint8_t) + sizeof(uint8_t), iv, &aes_ctx);
    for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t); i++) {
        encrypted_wot_index[i] = wot_index[i] ^ keystream_buffer[i];
    }
    aes256_ctx_release(&aes_ctx);
//======================================================================    
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context mac_ctx;
    poly1305_init(&mac_ctx, security->mac_key);
    poly1305_update(&mac_ctx, encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
    poly1305_finish(&mac_ctx, mac);
//====================================================================== 
    memcpy(encrypted_wot_index1, encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
    memcpy(encrypted_wot_index1 + sizeof(uint8_t) + sizeof(uint8_t), mac, AES_TAG_BYTES);
//======================================================================
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_hello2_ack(
        label, 
        wot,
        index,
        encrypted_wot_index1
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        label, 
        security->aes_key,
        security->mac_key,
        security->local_nonce,
        &security->local_ctr,
        worker_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent master_worker_hello2_ack to %s %ld.", label, worker_name, index);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sSent master_worker_hello2_ack to %s %ld.", label, worker_name, index);
    }
    memcpy(security->aes_key, tmp_aes_key, HASHES_BYTES);
    memset (tmp_aes_key, 0, HASHES_BYTES);
    security->local_ctr = (uint32_t)0;
    security->hello2_ack_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}
