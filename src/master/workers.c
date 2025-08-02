#include <string.h>      // for memset, strncpy
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#include "log.h"
#include "utilities.h"
#include "constants.h"
#include "types.h"
#include "workers/workers.h"
#include "master/workers.h"
#include "master/worker_metrics.h"
#include "async.h"
#include "master/master.h"
#include "stdbool.h"
#include "kalman.h"
#include "pqc.h"

status_t close_worker(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
	if (wot == SIO) {
        for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
            master_sio_c_session_t *c_session;
            c_session = &master_ctx->sio_c_session[i];
            if (c_session->in_use && (c_session->sio_index == index)) {
                cleanup_master_sio_session(label, &master_ctx->master_async, c_session);
            }
        }
        master_sio_session_t *session = &master_ctx->sio_session[index];
        uds_pair_pid_t *upp = &session->upp;
        worker_security_t *security = &session->security;
        cleanup_oricle_long_double(&session->avgtt);
        cleanup_oricle_double(&session->healthy);
        session->isactive = false;
        session->ishealthy = false;
        session->isready = false;
        memset(security->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
        memset(security->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
        memset(security->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
        memset(security->aes_key, 0, HASHES_BYTES);
        memset(security->mac_key, 0, HASHES_BYTES);
        memset(security->local_nonce, 0, AES_NONCE_BYTES);
        security->local_ctr = (uint32_t)0;
        memset(security->remote_nonce, 0, AES_NONCE_BYTES);
        security->remote_ctr = (uint32_t)0;
        free(security->kem_publickey);
        free(security->kem_ciphertext);
        free(security->kem_sharedsecret);
        free(security->aes_key);
        free(security->mac_key);
        free(security->local_nonce);
        free(security->remote_nonce);
        security->hello1_rcvd = false;
        security->hello1_ack_sent = false;
        security->hello2_rcvd = false;
        security->hello2_ack_sent = false;
        if (async_delete_event(label, &master_ctx->master_async, &upp->uds[0]) != SUCCESS) {		
			return FAILURE;
		}
        CLOSE_UDS(&upp->uds[0]);
		CLOSE_UDS(&upp->uds[1]);
		CLOSE_PID(&upp->pid);
	} else if (wot == LOGIC) {
        master_logic_session_t *session = &master_ctx->logic_session[index];
        uds_pair_pid_t *upp = &session->upp;
        worker_security_t *security = &session->security;
        cleanup_oricle_long_double(&session->avgtt);
        cleanup_oricle_double(&session->healthy);
        session->isactive = false;
        session->ishealthy = false;
        session->isready = false;
        memset(security->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
        memset(security->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
        memset(security->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
        memset(security->aes_key, 0, HASHES_BYTES);
        memset(security->mac_key, 0, HASHES_BYTES);
        memset(security->local_nonce, 0, AES_NONCE_BYTES);
        security->local_ctr = (uint32_t)0;
        memset(security->remote_nonce, 0, AES_NONCE_BYTES);
        security->remote_ctr = (uint32_t)0;
        free(security->kem_publickey);
        free(security->kem_ciphertext);
        free(security->kem_sharedsecret);
        free(security->aes_key);
        free(security->mac_key);
        free(security->local_nonce);
        free(security->remote_nonce);
        security->hello1_rcvd = false;
        security->hello1_ack_sent = false;
        security->hello2_rcvd = false;
        security->hello2_ack_sent = false;
        if (async_delete_event(label, &master_ctx->master_async, &upp->uds[0]) != SUCCESS) {		
			return FAILURE;
		}
        CLOSE_UDS(&upp->uds[0]);
		CLOSE_UDS(&upp->uds[1]);
		CLOSE_PID(&upp->pid);
	} else if (wot == COW) {
        for (int i = 0; i < MAX_MASTER_COW_SESSIONS; ++i) {
            master_cow_c_session_t *c_session;
            c_session = &master_ctx->cow_c_session[i];
            if (c_session->in_use && (c_session->cow_index == index)) {
                cleanup_master_cow_session(c_session);
            }
        }
        master_cow_session_t *session = &master_ctx->cow_session[index];
        uds_pair_pid_t *upp = &session->upp;
        worker_security_t *security = &session->security;
        cleanup_oricle_long_double(&session->avgtt);
        cleanup_oricle_double(&session->healthy);
        session->isactive = false;
        session->ishealthy = false;
        session->isready = false;
        memset(security->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
        memset(security->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
        memset(security->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
        memset(security->aes_key, 0, HASHES_BYTES);
        memset(security->mac_key, 0, HASHES_BYTES);
        memset(security->local_nonce, 0, AES_NONCE_BYTES);
        security->local_ctr = (uint32_t)0;
        memset(security->remote_nonce, 0, AES_NONCE_BYTES);
        security->remote_ctr = (uint32_t)0;
        free(security->kem_publickey);
        free(security->kem_ciphertext);
        free(security->kem_sharedsecret);
        free(security->aes_key);
        free(security->mac_key);
        free(security->local_nonce);
        free(security->remote_nonce);
        security->hello1_rcvd = false;
        security->hello1_ack_sent = false;
        security->hello2_rcvd = false;
        security->hello2_ack_sent = false;
        if (async_delete_event(label, &master_ctx->master_async, &upp->uds[0]) != SUCCESS) {		
			return FAILURE;
		}
        CLOSE_UDS(&upp->uds[0]);
		CLOSE_UDS(&upp->uds[1]);
		CLOSE_PID(&upp->pid);
	} else if (wot == DBR) {
        master_dbr_session_t *session = &master_ctx->dbr_session[index];
        uds_pair_pid_t *upp = &session->upp;
        worker_security_t *security = &session->security;
        cleanup_oricle_long_double(&session->avgtt);
        cleanup_oricle_double(&session->healthy);
        session->isactive = false;
        session->ishealthy = false;
        session->isready = false;
        memset(security->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
        memset(security->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
        memset(security->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
        memset(security->aes_key, 0, HASHES_BYTES);
        memset(security->mac_key, 0, HASHES_BYTES);
        memset(security->local_nonce, 0, AES_NONCE_BYTES);
        security->local_ctr = (uint32_t)0;
        memset(security->remote_nonce, 0, AES_NONCE_BYTES);
        security->remote_ctr = (uint32_t)0;
        free(security->kem_publickey);
        free(security->kem_ciphertext);
        free(security->kem_sharedsecret);
        free(security->aes_key);
        free(security->mac_key);
        free(security->local_nonce);
        free(security->remote_nonce);
        security->hello1_rcvd = false;
        security->hello1_ack_sent = false;
        security->hello2_rcvd = false;
        security->hello2_ack_sent = false;
        if (async_delete_event(label, &master_ctx->master_async, &upp->uds[0]) != SUCCESS) {		
			return FAILURE;
		}
        CLOSE_UDS(&upp->uds[0]);
		CLOSE_UDS(&upp->uds[1]);
		CLOSE_PID(&upp->pid);
	} else if (wot == DBW) {
        master_dbw_session_t *session = &master_ctx->dbw_session[index];
        uds_pair_pid_t *upp = &session->upp;
        worker_security_t *security = &session->security;
        cleanup_oricle_long_double(&session->avgtt);
        cleanup_oricle_double(&session->healthy);
        session->isactive = false;
        session->ishealthy = false;
        session->isready = false;
        memset(security->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
        memset(security->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
        memset(security->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
        memset(security->aes_key, 0, HASHES_BYTES);
        memset(security->mac_key, 0, HASHES_BYTES);
        memset(security->local_nonce, 0, AES_NONCE_BYTES);
        security->local_ctr = (uint32_t)0;
        memset(security->remote_nonce, 0, AES_NONCE_BYTES);
        security->remote_ctr = (uint32_t)0;
        free(security->kem_publickey);
        free(security->kem_ciphertext);
        free(security->kem_sharedsecret);
        free(security->aes_key);
        free(security->mac_key);
        free(security->local_nonce);
        free(security->remote_nonce);
        security->hello1_rcvd = false;
        security->hello1_ack_sent = false;
        security->hello2_rcvd = false;
        security->hello2_ack_sent = false;
        if (async_delete_event(label, &master_ctx->master_async, &upp->uds[0]) != SUCCESS) {		
			return FAILURE;
		}
        CLOSE_UDS(&upp->uds[0]);
		CLOSE_UDS(&upp->uds[1]);
		CLOSE_PID(&upp->pid);
	} else {
        return FAILURE;
    }
	return SUCCESS;
}

status_t create_socket_pair(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
	if (wot == SIO) {
		const char *worker_name = "SIO";
        master_sio_session_t *session = &master_ctx->sio_session[index];
        uds_pair_pid_t *upp = &session->upp;
        worker_security_t *security = &session->security;
        upp->uds[0] = 0; 
		upp->uds[1] = 0; 
        setup_oricle_long_double(&session->avgtt, (long double)0);
        setup_oricle_double(&session->healthy, (double)100);
        session->isactive = true;
        session->ishealthy = true;        
        session->isready = false;   
        security->kem_publickey = (uint8_t *)calloc(1, KEM_PUBLICKEY_BYTES);
        security->kem_ciphertext = (uint8_t *)calloc(1, KEM_CIPHERTEXT_BYTES);
        security->kem_sharedsecret = (uint8_t *)calloc(1, KEM_SHAREDSECRET_BYTES);
        security->aes_key = (uint8_t *)calloc(1, HASHES_BYTES);
        security->mac_key = (uint8_t *)calloc(1, HASHES_BYTES);
        security->local_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
        security->remote_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
        security->local_ctr = (uint32_t)0;
        security->remote_ctr = (uint32_t)0;
        security->hello1_rcvd = false;
        security->hello1_ack_sent = false;
        security->hello2_rcvd = false;
        security->hello2_ack_sent = false;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, upp->uds) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, upp->uds[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, upp->uds[1]) != SUCCESS) {
			return FAILURE;
		}
		if (async_create_incoming_event(label, &master_ctx->master_async, &upp->uds[0]) != SUCCESS) {
			return FAILURE;
		}
		LOG_DEBUG("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, upp->uds[0], upp->uds[1]);
	} else if (wot == LOGIC) {
		const char *worker_name = "Logic";
        master_logic_session_t *session = &master_ctx->logic_session[index];
        uds_pair_pid_t *upp = &session->upp;
        worker_security_t *security = &session->security;
        upp->uds[0] = 0; 
		upp->uds[1] = 0; 
        setup_oricle_long_double(&session->avgtt, (long double)0);
        setup_oricle_double(&session->healthy, (double)100);
        session->isactive = true;
        session->ishealthy = true;        
        session->isready = false;     
        security->kem_publickey = (uint8_t *)calloc(1, KEM_PUBLICKEY_BYTES);
        security->kem_ciphertext = (uint8_t *)calloc(1, KEM_CIPHERTEXT_BYTES);
        security->kem_sharedsecret = (uint8_t *)calloc(1, KEM_SHAREDSECRET_BYTES);
        security->aes_key = (uint8_t *)calloc(1, HASHES_BYTES);
        security->mac_key = (uint8_t *)calloc(1, HASHES_BYTES);
        security->local_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
        security->remote_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
        security->local_ctr = (uint32_t)0;
        security->remote_ctr = (uint32_t)0;
        security->hello1_rcvd = false;
        security->hello1_ack_sent = false;
        security->hello2_rcvd = false;
        security->hello2_ack_sent = false;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, upp->uds) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, upp->uds[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, upp->uds[1]) != SUCCESS) {
			return FAILURE;
		}
		if (async_create_incoming_event(label, &master_ctx->master_async, &upp->uds[0]) != SUCCESS) {
			return FAILURE;
		}
		LOG_DEBUG("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, upp->uds[0], upp->uds[1]);
	} else if (wot == COW) {
		const char *worker_name = "COW";
        master_cow_session_t *session = &master_ctx->cow_session[index];
        uds_pair_pid_t *upp = &session->upp;
        worker_security_t *security = &session->security;
        upp->uds[0] = 0; 
		upp->uds[1] = 0; 
        setup_oricle_long_double(&session->avgtt, (long double)0);
        setup_oricle_double(&session->healthy, (double)100);
        session->isactive = true;
        session->ishealthy = true;        
        session->isready = false;     
        security->kem_publickey = (uint8_t *)calloc(1, KEM_PUBLICKEY_BYTES);
        security->kem_ciphertext = (uint8_t *)calloc(1, KEM_CIPHERTEXT_BYTES);
        security->kem_sharedsecret = (uint8_t *)calloc(1, KEM_SHAREDSECRET_BYTES);
        security->aes_key = (uint8_t *)calloc(1, HASHES_BYTES);
        security->mac_key = (uint8_t *)calloc(1, HASHES_BYTES);
        security->local_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
        security->remote_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
        security->local_ctr = (uint32_t)0;
        security->remote_ctr = (uint32_t)0;
        security->hello1_rcvd = false;
        security->hello1_ack_sent = false;
        security->hello2_rcvd = false;
        security->hello2_ack_sent = false;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, upp->uds) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, upp->uds[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, upp->uds[1]) != SUCCESS) {
			return FAILURE;
		}
		if (async_create_incoming_event(label, &master_ctx->master_async, &upp->uds[0]) != SUCCESS) {
			return FAILURE;
		}
		LOG_DEBUG("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, upp->uds[0], upp->uds[1]);
	} else if (wot == DBR) {
		const char *worker_name = "DBR";
        master_dbr_session_t *session = &master_ctx->dbr_session[index];
        uds_pair_pid_t *upp = &session->upp;
        worker_security_t *security = &session->security;
        upp->uds[0] = 0; 
		upp->uds[1] = 0; 
        setup_oricle_long_double(&session->avgtt, (long double)0);
        setup_oricle_double(&session->healthy, (double)100);
        session->isactive = true;
        session->ishealthy = true;        
        session->isready = false;     
        security->kem_publickey = (uint8_t *)calloc(1, KEM_PUBLICKEY_BYTES);
        security->kem_ciphertext = (uint8_t *)calloc(1, KEM_CIPHERTEXT_BYTES);
        security->kem_sharedsecret = (uint8_t *)calloc(1, KEM_SHAREDSECRET_BYTES);
        security->aes_key = (uint8_t *)calloc(1, HASHES_BYTES);
        security->mac_key = (uint8_t *)calloc(1, HASHES_BYTES);
        security->local_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
        security->remote_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
        security->local_ctr = (uint32_t)0;
        security->remote_ctr = (uint32_t)0;
        security->hello1_rcvd = false;
        security->hello1_ack_sent = false;
        security->hello2_rcvd = false;
        security->hello2_ack_sent = false;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, upp->uds) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, upp->uds[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, upp->uds[1]) != SUCCESS) {
			return FAILURE;
		}
		if (async_create_incoming_event(label, &master_ctx->master_async, &upp->uds[0]) != SUCCESS) {
			return FAILURE;
		}
		LOG_DEBUG("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, upp->uds[0], upp->uds[1]);
	} else if (wot == DBW) {
		const char *worker_name = "DBW";
        master_dbw_session_t *session = &master_ctx->dbw_session[index];
        uds_pair_pid_t *upp = &session->upp;
        worker_security_t *security = &session->security;
        upp->uds[0] = 0; 
		upp->uds[1] = 0; 
        setup_oricle_long_double(&session->avgtt, (long double)0);
        setup_oricle_double(&session->healthy, (double)100);
        session->isactive = true;
        session->ishealthy = true;        
        session->isready = false;     
        security->kem_publickey = (uint8_t *)calloc(1, KEM_PUBLICKEY_BYTES);
        security->kem_ciphertext = (uint8_t *)calloc(1, KEM_CIPHERTEXT_BYTES);
        security->kem_sharedsecret = (uint8_t *)calloc(1, KEM_SHAREDSECRET_BYTES);
        security->aes_key = (uint8_t *)calloc(1, HASHES_BYTES);
        security->mac_key = (uint8_t *)calloc(1, HASHES_BYTES);
        security->local_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
        security->remote_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
        security->local_ctr = (uint32_t)0;
        security->remote_ctr = (uint32_t)0;
        security->hello1_rcvd = false;
        security->hello1_ack_sent = false;
        security->hello2_rcvd = false;
        security->hello2_ack_sent = false;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, upp->uds) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, upp->uds[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, upp->uds[1]) != SUCCESS) {
			return FAILURE;
		}
		if (async_create_incoming_event(label, &master_ctx->master_async, &upp->uds[0]) != SUCCESS) {
			return FAILURE;
		}
		LOG_DEBUG("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, upp->uds[0], upp->uds[1]);
	} else {
        return FAILURE;
    }
	return SUCCESS;
}

void close_master_resource(master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
    worker_security_t *security = NULL;
    if (wot == SIO) {
        security = &master_ctx->sio_session[index].security;
    } else if (wot == LOGIC) {
        security = &master_ctx->logic_session[index].security;
    } else if (wot == COW) {
        security = &master_ctx->cow_session[index].security;
    } else if (wot == DBR) {
        security = &master_ctx->dbr_session[index].security;
    } else if (wot == DBW) {
        security = &master_ctx->dbw_session[index].security;
    } else {
        return;
    }
    if (!security) return;
    CLOSE_FD(&master_ctx->listen_sock);
    CLOSE_FD(&master_ctx->master_async.async_fd);
    CLOSE_FD(&master_ctx->heartbeat_timer_fd);
    CLOSE_FD(&master_ctx->shutdown_event_fd);
    memset(security->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(security->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(security->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    memset(security->aes_key, 0, HASHES_BYTES);
    memset(security->mac_key, 0, HASHES_BYTES);
    memset(security->local_nonce, 0, AES_NONCE_BYTES);
    security->local_ctr = (uint32_t)0;
    memset(security->remote_nonce, 0, AES_NONCE_BYTES);
    security->remote_ctr = (uint32_t)0;
    free(security->kem_publickey);
    free(security->kem_ciphertext);
    free(security->kem_sharedsecret);
    free(security->aes_key);
    free(security->mac_key);
    free(security->local_nonce);
    free(security->remote_nonce);
    memset(master_ctx->kem_privatekey, 0, KEM_PRIVATEKEY_BYTES);
    free(master_ctx->kem_privatekey);
    memset(master_ctx->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    free(master_ctx->kem_publickey);
    for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio_session[j].upp.uds[0]); }
    for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic_session[j].upp.uds[0]); }
    for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow_session[j].upp.uds[0]); }
    for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr_session[j].upp.uds[0]); }           
    for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw_session[j].upp.uds[0]); }
}

status_t setup_fork_worker(const char* label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
	if (wot == SIO) {
		const char *worker_name = "SIO";
        double initial_delay_ms = (double)0;
		master_ctx->sio_session[index].upp.pid = fork();
        if (master_ctx->sio_session[index].upp.pid == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->sio_session[index].upp.pid == 0) {
            close_master_resource(master_ctx, wot, index);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) {
				if (j != index) {
					CLOSE_FD(&master_ctx->sio_session[j].upp.uds[1]);
				}
            }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow_session[j].upp.uds[1]); }            
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw_session[j].upp.uds[1]); }          
            worker_type_t x_wot = wot;
            uint8_t x_index = index;
            double x_initial_delay_ms = initial_delay_ms;
            int *master_uds_fd = &master_ctx->sio_session[index].upp.uds[1];
            run_sio_worker(&x_wot, &x_index, &x_initial_delay_ms, master_uds_fd);
            exit(EXIT_SUCCESS);
        } else {
			CLOSE_FD(&master_ctx->sio_session[index].upp.uds[1]);
//======================================================================
// Hitung delay start dan inisialisasi metrics
//======================================================================
            master_ctx->sio_session[index].task_count = (uint16_t)0;
            initial_delay_ms = initialize_metrics(label, &master_ctx->sio_session[index].metrics, wot, index);
//======================================================================
            LOG_DEBUG("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->sio_session[index].upp.pid);
        }
	} else if (wot == LOGIC) {
		const char *worker_name = "Logic";	
        double initial_delay_ms = (double)0;	
		master_ctx->logic_session[index].upp.pid = fork();
        if (master_ctx->logic_session[index].upp.pid == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->logic_session[index].upp.pid == 0) {
            close_master_resource(master_ctx, wot, index);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) {
				if (j != index) {
					CLOSE_FD(&master_ctx->logic_session[j].upp.uds[1]);
				}
			}
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw_session[j].upp.uds[1]); }
            worker_type_t x_wot = wot;
            uint8_t x_index = index;
            double x_initial_delay_ms = initial_delay_ms;
            int *master_uds_fd = &master_ctx->logic_session[index].upp.uds[1];
            run_logic_worker(&x_wot, &x_index, &x_initial_delay_ms, master_uds_fd);
            exit(EXIT_SUCCESS);
        } else {
			CLOSE_FD(&master_ctx->logic_session[index].upp.uds[1]);
//======================================================================
// Hitung delay start dan inisialisasi metrics
//======================================================================
            master_ctx->logic_session[index].task_count = (uint16_t)0;
            initial_delay_ms = initialize_metrics(label, &master_ctx->logic_session[index].metrics, wot, index);
//======================================================================
            LOG_DEBUG("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->logic_session[index].upp.pid);
        }
	} else if (wot == COW) {
		const char *worker_name = "COW";
        double initial_delay_ms = (double)0;
		master_ctx->cow_session[index].upp.pid = fork();
        if (master_ctx->cow_session[index].upp.pid == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->cow_session[index].upp.pid == 0) {
            close_master_resource(master_ctx, wot, index);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) {
				if (j != index) {
					CLOSE_FD(&master_ctx->cow_session[j].upp.uds[1]); 
				}
			}
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw_session[j].upp.uds[1]); }
            worker_type_t x_wot = wot;
            uint8_t x_index = index;
            double x_initial_delay_ms = initial_delay_ms;
            int *master_uds_fd = &master_ctx->cow_session[index].upp.uds[1];
            run_cow_worker(&x_wot, &x_index, &x_initial_delay_ms, master_uds_fd);
            exit(EXIT_SUCCESS);
        } else {
			CLOSE_FD(&master_ctx->cow_session[index].upp.uds[1]);
//======================================================================
// Hitung delay start dan inisialisasi metrics
//======================================================================
            master_ctx->cow_session[index].task_count = (uint16_t)0;
            initial_delay_ms = initialize_metrics(label, &master_ctx->cow_session[index].metrics, wot, index);
//======================================================================
            LOG_DEBUG("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->cow_session[index].upp.pid);
        }
	} else if (wot == DBR) {
		const char *worker_name = "DBR";
        double initial_delay_ms = (double)0;
		master_ctx->dbr_session[index].upp.pid = fork();
        if (master_ctx->dbr_session[index].upp.pid == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->dbr_session[index].upp.pid == 0) {
            close_master_resource(master_ctx, wot, index);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { 
                if (j != index) {
                    CLOSE_FD(&master_ctx->dbr_session[j].upp.uds[1]); 
                }
            }
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw_session[j].upp.uds[1]); }
            worker_type_t x_wot = wot;
            uint8_t x_index = index;
            double x_initial_delay_ms = initial_delay_ms;
            int *master_uds_fd = &master_ctx->dbr_session[index].upp.uds[1];
            run_dbr_worker(&x_wot, &x_index, &x_initial_delay_ms, master_uds_fd);
            exit(EXIT_SUCCESS);
        } else {
			CLOSE_FD(&master_ctx->dbr_session[index].upp.uds[1]);
//======================================================================
// Hitung delay start dan inisialisasi metrics
//======================================================================
            master_ctx->dbr_session[index].task_count = (uint16_t)0;
            initial_delay_ms = initialize_metrics(label, &master_ctx->dbr_session[index].metrics, wot, index);
//======================================================================
            LOG_DEBUG("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->dbr_session[index].upp.pid);
        }
	} else if (wot == DBW) {
		const char *worker_name = "DBW";
        double initial_delay_ms = (double)0;
		master_ctx->dbw_session[index].upp.pid = fork();
        if (master_ctx->dbw_session[index].upp.pid == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->dbw_session[index].upp.pid == 0) {
            close_master_resource(master_ctx, wot, index);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio_session[j].upp.uds[0]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic_session[j].upp.uds[0]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow_session[j].upp.uds[0]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr_session[j].upp.uds[0]); }           
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw_session[j].upp.uds[0]); }
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr_session[j].upp.uds[1]); }
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) {
                if (j != index) {
                    CLOSE_FD(&master_ctx->dbw_session[j].upp.uds[1]);
                }
            }
            worker_type_t x_wot = wot;
            uint8_t x_index = index;
            double x_initial_delay_ms = initial_delay_ms;
            int *master_uds_fd = &master_ctx->dbw_session[index].upp.uds[1];
            run_dbw_worker(&x_wot, &x_index, &x_initial_delay_ms, master_uds_fd);
            exit(EXIT_SUCCESS);
        } else {
			CLOSE_FD(&master_ctx->dbw_session[index].upp.uds[1]);
//======================================================================
// Hitung delay start dan inisialisasi metrics
//======================================================================
            initial_delay_ms = initialize_metrics(label, &master_ctx->dbw_session[index].metrics, wot, index);
//======================================================================
            LOG_DEBUG("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->dbw_session[index].upp.pid);
        }
	} else {
        return FAILURE;
    }
    return SUCCESS;
}

void cleanup_workers(const char *label, master_context_t *master_ctx) {
    LOG_INFO("[Master]: Performing cleanup...");
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        close_worker(label, master_ctx, SIO, i);
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        close_worker(label, master_ctx, LOGIC, i);
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        close_worker(label, master_ctx, COW, i);
    }
    for (int i = 0; i < MAX_DBR_WORKERS; ++i) {
        close_worker(label, master_ctx, DBR, i);
    }
    for (int i = 0; i < MAX_DBW_WORKERS; ++i) {
        close_worker(label, master_ctx, DBW, i);
    }
    LOG_INFO("[Master]: Cleanup complete.");
}

status_t setup_workers(const char *label, master_context_t *master_ctx) {
    for (int index = 0; index < MAX_SIO_WORKERS; ++index) {
		if (create_socket_pair(label, master_ctx, SIO, index) != SUCCESS) return FAILURE;
    }
    for (int index = 0; index < MAX_LOGIC_WORKERS; ++index) {
		if (create_socket_pair(label, master_ctx, LOGIC, index) != SUCCESS) return FAILURE;
    }
    for (int index = 0; index < MAX_COW_WORKERS; ++index) {
		if (create_socket_pair(label, master_ctx, COW, index) != SUCCESS) return FAILURE;
    }
    for (int index = 0; index < MAX_DBR_WORKERS; ++index) {
		if (create_socket_pair(label, master_ctx, DBR, index) != SUCCESS) return FAILURE;
    }
    for (int index = 0; index < MAX_DBW_WORKERS; ++index) {
		if (create_socket_pair(label, master_ctx, DBW, index) != SUCCESS) return FAILURE;
    }    
	for (uint8_t index = 0; index < MAX_SIO_WORKERS; ++index) {
		if (setup_fork_worker(label, master_ctx, SIO, index) != SUCCESS) {
			return FAILURE;
		}
    }
    for (uint8_t index = 0; index < MAX_LOGIC_WORKERS; ++index) {
		if (setup_fork_worker(label, master_ctx, LOGIC, index) != SUCCESS) {
			return FAILURE;
		}
    }
    for (uint8_t index = 0; index < MAX_COW_WORKERS; ++index) {
		if (setup_fork_worker(label, master_ctx, COW, index) != SUCCESS) {
			return FAILURE;
		}
    }
    for (uint8_t index = 0; index < MAX_DBR_WORKERS; ++index) {
		if (setup_fork_worker(label, master_ctx, DBR, index) != SUCCESS) {
			return FAILURE;
		}
    }
    for (uint8_t index = 0; index < MAX_DBW_WORKERS; ++index) {
		if (setup_fork_worker(label, master_ctx, DBW, index) != SUCCESS) {
			return FAILURE;
		}
    }    
    return SUCCESS;
}

status_t calculate_avgtt(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
    const char *worker_name = "Unknown";
    switch (wot) {
        case SIO: { worker_name = "SIO"; break; }
        case LOGIC: { worker_name = "Logic"; break; }
        case COW: { worker_name = "COW"; break; }
        case DBR: { worker_name = "DBR"; break; }
        case DBW: { worker_name = "DBW"; break; }
        default: { worker_name = "Unknown"; break; }
    }
    uint64_t_status_t rt = get_realtime_time_ns(label);
    if (rt.status != SUCCESS) return rt.status;
    worker_metrics_t *metrics = NULL;
    uint16_t *task_count = NULL;
    oricle_long_double_t *oricle;
    uint64_t MAX_CONNECTION_PER_WORKER;
    if (wot == SIO) {
        metrics = &master_ctx->sio_session[index].metrics;
        task_count = &master_ctx->sio_session[index].task_count;
        MAX_CONNECTION_PER_WORKER = MAX_CONNECTION_PER_SIO_WORKER;
        oricle = &master_ctx->sio_session[index].avgtt;
    } else if (wot == COW) {
        metrics = &master_ctx->cow_session[index].metrics;
        task_count = &master_ctx->cow_session[index].task_count;
        MAX_CONNECTION_PER_WORKER = MAX_CONNECTION_PER_COW_WORKER;
        oricle = &master_ctx->cow_session[index].avgtt;
    }
    if (!task_count || !metrics || !oricle) return FAILURE;
    metrics->last_ack = rt.r_uint64_t;
    metrics->last_task_finished = rt.r_uint64_t;
    uint64_t task_time;
    if (metrics->last_task_started == 0 ||
        rt.r_uint64_t < metrics->last_task_started) {
        task_time = 0;
        LOG_WARN("%s%s Worker %d: Invalid last_task_started detected. Resetting task_time to 0.", label, worker_name, index);
    } else {
        task_time = rt.r_uint64_t - metrics->last_task_started;
    }
    if (metrics->longest_task_time < task_time) {
        metrics->longest_task_time = task_time;
    }
    uint64_t previous_task_count = *task_count;
    if (previous_task_count > 0) {
        *task_count -= 1;
    } else {
        LOG_WARN("%sTask count for %s worker %d is already zero. Possible logic error.",
                 label, worker_name, index);
        *task_count = 0;
    }
    uint64_t current_task_count = *task_count;
    uint64_t previous_slot_kosong = MAX_CONNECTION_PER_WORKER - previous_task_count;
    uint64_t current_slot_kosong = MAX_CONNECTION_PER_WORKER - current_task_count;
    long double current_avgtt_measurement;
    if (current_slot_kosong > 0 && previous_slot_kosong > 0) {
        current_avgtt_measurement = ((oricle->value_prediction * previous_slot_kosong) + task_time) / (long double)current_slot_kosong;
    } else if (previous_slot_kosong == 0 && current_slot_kosong > 0) {
        current_avgtt_measurement = (long double)task_time;
    } else {
        current_avgtt_measurement = (long double)0;
    }
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => AVGTT %s-%d", worker_name, index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => AVGTT %s-%d", worker_name, index);
    calculate_oricle_long_double(label, desc, oricle, current_avgtt_measurement, (long double)0);
    free(desc);
    return SUCCESS;
}

status_t calculate_healthy(const char* label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
    const char *worker_name = "Unknown";
    switch (wot) {
        case SIO: { worker_name = "SIO"; break; }
        case LOGIC: { worker_name = "Logic"; break; }
        case COW: { worker_name = "COW"; break; }
        case DBR: { worker_name = "DBR"; break; }
        case DBW: { worker_name = "DBW"; break; }
        default: { worker_name = "Unknown"; break; }
    }
    uint64_t_status_t rt = get_realtime_time_ns(label);
    if (rt.status != SUCCESS) return rt.status;
    worker_metrics_t *metrics = NULL;
    oricle_double_t *oricle;
    bool *ishealthy;
    if (wot == SIO) {
        metrics = &master_ctx->sio_session[index].metrics;
        oricle = &master_ctx->sio_session[index].healthy;
        ishealthy = &master_ctx->sio_session[index].ishealthy;
    } else if (wot == LOGIC) {
        metrics = &master_ctx->logic_session[index].metrics;
        oricle = &master_ctx->logic_session[index].healthy;
        ishealthy = &master_ctx->logic_session[index].ishealthy;
    } else if (wot == COW) {
        metrics = &master_ctx->cow_session[index].metrics;
        oricle = &master_ctx->cow_session[index].healthy;
        ishealthy = &master_ctx->cow_session[index].ishealthy;
    } else if (wot == DBR) {
        metrics = &master_ctx->dbr_session[index].metrics;
        oricle = &master_ctx->dbr_session[index].healthy;
        ishealthy = &master_ctx->dbr_session[index].ishealthy;
    } else if (wot == DBW) {
        metrics = &master_ctx->dbw_session[index].metrics;
        oricle = &master_ctx->dbw_session[index].healthy;
        ishealthy = &master_ctx->dbw_session[index].ishealthy;
    } else {
        return FAILURE;
    }
    if (!metrics || !oricle || !ishealthy) return FAILURE;
    uint64_t now_ns = rt.r_uint64_t;
    double actual_elapsed_sec = (double)(now_ns - metrics->last_checkhealthy) / 1e9;
    double ttl_delay_jitter = (metrics->sum_hbtime - metrics->hbtime) - ((double)WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * metrics->count_ack);
    double setup_elapsed_sec = (double)WORKER_HEARTBEATSEC_TIMEOUT + ttl_delay_jitter;
    double setup_count_ack = setup_elapsed_sec / (double)WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT;
    double comp_elapsed_sec = actual_elapsed_sec / setup_elapsed_sec;
    double expected_count_ack = setup_count_ack * comp_elapsed_sec;
    double current_health_measurement;
    if (expected_count_ack <= (double)0) {
        current_health_measurement = (double)100;
    } else {
        current_health_measurement = metrics->count_ack / expected_count_ack;
    }
    current_health_measurement *= (double)100;    
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => HEALTHY %s-%d", worker_name, index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => HEALTHY %s-%d", worker_name, index);
    calculate_oricle_double(label, desc, oricle, current_health_measurement, (double)200);
    free(desc);
    *ishealthy = (oricle->value_prediction >= HEALTHY_THRESHOLD);
    metrics->last_checkhealthy = now_ns;
    metrics->count_ack = (double)0;
    metrics->sum_hbtime = metrics->hbtime;
    return SUCCESS;
}

status_t check_workers_healthy(const char *label, master_context_t *master_ctx) {
	for (int i = 0; i < MAX_SIO_WORKERS; ++i) { 
		if (calculate_healthy(label, master_ctx, SIO, i) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->sio_session[i].healthy.value_prediction < (double)25) {
            master_ctx->sio_session[i].isactive = false;
            if (close_worker(label, master_ctx, SIO, i) != SUCCESS) {
                return FAILURE;
            }
            if (create_socket_pair(label, master_ctx, SIO, i) != SUCCESS) {
                return FAILURE;
            }
            if (setup_fork_worker(label, master_ctx, SIO, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
	for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		if (calculate_healthy(label, master_ctx, LOGIC, i) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->logic_session[i].healthy.value_prediction < (double)25) {
            master_ctx->logic_session[i].isactive = false;
            if (close_worker(label, master_ctx, LOGIC, i) != SUCCESS) {
                return FAILURE;
            }
            if (create_socket_pair(label, master_ctx, LOGIC, i) != SUCCESS) {
                return FAILURE;
            }
            if (setup_fork_worker(label, master_ctx, LOGIC, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
	for (int i = 0; i < MAX_COW_WORKERS; ++i) { 
		if (calculate_healthy(label, master_ctx, COW, i) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->cow_session[i].healthy.value_prediction < (double)25) {
            master_ctx->cow_session[i].isactive = false;
            if (close_worker(label, master_ctx, COW, i) != SUCCESS) {
                return FAILURE;
            }
            if (create_socket_pair(label, master_ctx, COW, i) != SUCCESS) {
                return FAILURE;
            }
            if (setup_fork_worker(label, master_ctx, COW, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
    for (int i = 0; i < MAX_DBR_WORKERS; ++i) { 
		if (calculate_healthy(label, master_ctx, DBR, i) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->dbr_session[i].healthy.value_prediction < (double)25) {
            master_ctx->dbr_session[i].isactive = false;
            if (close_worker(label, master_ctx, DBR, i) != SUCCESS) {
                return FAILURE;
            }
            if (create_socket_pair(label, master_ctx, DBR, i) != SUCCESS) {
                return FAILURE;
            }
            if (setup_fork_worker(label, master_ctx, DBR, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
    for (int i = 0; i < MAX_DBW_WORKERS; ++i) { 
		if (calculate_healthy(label, master_ctx, DBW, i) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->dbw_session[i].healthy.value_prediction < (double)25) {
            master_ctx->dbw_session[i].isactive = false;
            if (close_worker(label, master_ctx, DBW, i) != SUCCESS) {
                return FAILURE;
            }
            if (create_socket_pair(label, master_ctx, DBW, i) != SUCCESS) {
                return FAILURE;
            }
            if (setup_fork_worker(label, master_ctx, DBW, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
	return SUCCESS;
}
