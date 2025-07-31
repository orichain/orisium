#include <stddef.h>
#include <stdint.h>
#include <endian.h>
#include <string.h>

#include "log.h"
#include "constants.h"
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
#include "utilities.h"

struct sockaddr_in6;

status_t master_workers_info(master_context_t *master_ctx, info_type_t flag) {
	const char *label = "[Master]: ";
	for (uint8_t i = 0; i < MAX_SIO_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_info(label, SIO, i, flag);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}
		ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            master_ctx->sio_session[i].security.aes_key,
            master_ctx->sio_session[i].security.mac_key,
            master_ctx->sio_session[i].security.local_nonce,
            &master_ctx->sio_session[i].security.local_ctr,
            &master_ctx->sio_session[i].upp.uds[0], 
            cmd_result.r_ipc_protocol_t
        );
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent master_worker_info to SIO %ld.", label, i);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
		} else {
			LOG_DEBUG("%sSent master_worker_info to SIO %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	}
	for (uint8_t i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_info(label, LOGIC, i, flag);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            master_ctx->logic_session[i].security.aes_key,
            master_ctx->logic_session[i].security.mac_key,
            master_ctx->logic_session[i].security.local_nonce,
            &master_ctx->logic_session[i].security.local_ctr,
            &master_ctx->logic_session[i].upp.uds[0], 
            cmd_result.r_ipc_protocol_t
        );
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent master_worker_info to Logic %ld.", label, i);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
		} else {
			LOG_DEBUG("%sSent master_worker_info to Logic %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
	for (uint8_t i = 0; i < MAX_COW_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_info(label, COW, i, flag);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            master_ctx->cow_session[i].security.aes_key,
            master_ctx->cow_session[i].security.mac_key,
            master_ctx->cow_session[i].security.local_nonce,
            &master_ctx->cow_session[i].security.local_ctr,
            &master_ctx->cow_session[i].upp.uds[0], 
            cmd_result.r_ipc_protocol_t
        );
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent master_worker_info to COW %ld.", label, i);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
		} else {
			LOG_DEBUG("%sSent master_worker_info to COW %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
    for (uint8_t i = 0; i < MAX_DBR_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_info(label, DBR, i, flag);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            master_ctx->dbr_session[i].security.aes_key,
            master_ctx->dbr_session[i].security.mac_key,
            master_ctx->dbr_session[i].security.local_nonce,
            &master_ctx->dbr_session[i].security.local_ctr,
            &master_ctx->dbr_session[i].upp.uds[0], 
            cmd_result.r_ipc_protocol_t
        );
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent master_worker_info to DBR %ld.", label, i);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
		} else {
			LOG_DEBUG("%sSent master_worker_info to DBR %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
    for (uint8_t i = 0; i < MAX_DBW_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_info(label, DBW, i, flag);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            master_ctx->dbw_session[i].security.aes_key,
            master_ctx->dbw_session[i].security.mac_key,
            master_ctx->dbw_session[i].security.local_nonce,
            &master_ctx->dbw_session[i].security.local_ctr,
            &master_ctx->dbw_session[i].upp.uds[0], 
            cmd_result.r_ipc_protocol_t
        );
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent master_worker_info to DBW %ld.", label, i);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
		} else {
			LOG_DEBUG("%sSent master_worker_info to DBW %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
	return SUCCESS;
}

status_t master_cow_connect(master_context_t *master_ctx, struct sockaddr_in6 *addr, uint8_t index) {
	const char *label = "[Master]: ";
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

status_t master_worker_hello1_ack(master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
	const char *label = "[Master]: ";
    uint8_t *kem_ciphertext = NULL;
    worker_security_t *security;
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
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_hello1_ack(
        label, 
        wot, 
        index, 
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
    security->hello1_ack_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}

status_t master_worker_hello2_ack(master_context_t *master_ctx, worker_type_t wot, int index) {
	const char *label = "[Master]: ";
    worker_security_t *security;
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
//======================================================================    
    uint8_t wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
    uint8_t encrypted_wot_index1[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index2[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES];
    memcpy(encrypted_wot_index1, security->local_nonce, AES_NONCE_BYTES);
    memcpy(wot_index, (uint8_t *)&wot, sizeof(uint8_t));
    memcpy(wot_index + sizeof(uint8_t), &index, sizeof(uint8_t));
//======================================================================    
    aes256ctx aes_ctx;
    aes256_ctr_keyexp(&aes_ctx, security->kem_sharedsecret);
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
    memcpy(encrypted_wot_index1 + AES_NONCE_BYTES, encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
//======================================================================    
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context mac_ctx;
    poly1305_init(&mac_ctx, security->kem_sharedsecret);
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
    increment_ctr(&security->local_ctr, security->local_nonce);
//======================================================================
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_hello2_ack(
        label, 
        wot,
        index,
        encrypted_wot_index2
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
    security->hello2_ack_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}
