#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/worker.h"
#include "pqc.h"
#include "stdbool.h"

status_t setup_worker(worker_context_t *ctx, const char *worker_name, worker_type_t wot, uint8_t worker_idx, int master_uds_fd) {
    ctx->pid = getpid();
    ctx->shutdown_requested = 0;
    ctx->async.async_fd = -1;
    ctx->heartbeat_timer_fd = -1;
    ctx->wot = wot;
    ctx->idx = worker_idx;
    ctx->master_uds_fd = master_uds_fd;
//----------------------------------------------------------------------
// Inisialisasi seed dengan waktu saat ini untuk hasil yang berbeda setiap kali
// Seed untuk random() jitter
//----------------------------------------------------------------------
    srandom(time(NULL) ^ ctx->pid);
//----------------------------------------------------------------------
// Setup label
//----------------------------------------------------------------------
	int needed = snprintf(NULL, 0, "[%s %d]: ", worker_name, worker_idx);
	ctx->label = malloc(needed + 1);
	snprintf(ctx->label, needed + 1, "[%s %d]: ", worker_name, worker_idx);  
//----------------------------------------------------------------------
// Setup IPC security
//----------------------------------------------------------------------
    if (KEM_GENERATE_KEYPAIR(ctx->kem_publickey, ctx->kem_privatekey) != 0) {
        LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", ctx->label);
        return FAILURE;
    }
    if (generate_nonce(ctx->label, ctx->local_nonce) != SUCCESS) {
        LOG_ERROR("%sFailed to generate_nonce.", ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------	
	if (async_create(ctx->label, &ctx->async) != SUCCESS) return FAILURE;
	if (async_create_incoming_event_with_disconnect(ctx->label, &ctx->async, &ctx->master_uds_fd) != SUCCESS) return FAILURE;
//----------------------------------------------------------------------
	if (async_create_timerfd(ctx->label, &ctx->heartbeat_timer_fd) != SUCCESS) {
		 return FAILURE;
	}
	if (async_set_timerfd_time(ctx->label, &ctx->heartbeat_timer_fd,
		WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0,
        WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0) != SUCCESS)
    {
		 return FAILURE;
	}
    if (KEM_GENERATE_KEYPAIR(ctx->kem_publickey, ctx->kem_privatekey) != 0) {
        LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", ctx->label);
        return FAILURE;
    }
    memset(ctx->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(ctx->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    if (generate_nonce(ctx->label, ctx->local_nonce) != SUCCESS) {
        LOG_ERROR("%sFailed to generate_nonce.", ctx->label);
        return FAILURE;
    }
    ctx->local_ctr = (uint32_t)0;
    memset(ctx->remote_nonce, 0, AES_NONCE_BYTES);
    ctx->remote_ctr = (uint32_t)0;
    ctx->hello1_sent = false;
    ctx->hello1_ack_rcvd = false;
    ctx->hello2_sent = false;
    ctx->hello2_ack_rcvd = false;
    return SUCCESS;
}

void cleanup_worker(worker_context_t *ctx) {
    async_delete_event(ctx->label, &ctx->async, &ctx->master_uds_fd);
    CLOSE_FD(&ctx->master_uds_fd);
	async_delete_event(ctx->label, &ctx->async, &ctx->heartbeat_timer_fd);
    CLOSE_FD(&ctx->heartbeat_timer_fd);
    CLOSE_FD(&ctx->async.async_fd);
    memset(ctx->kem_privatekey, 0, KEM_PRIVATEKEY_BYTES);
    memset(ctx->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(ctx->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(ctx->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    memset(ctx->local_nonce, 0, AES_NONCE_BYTES);
    ctx->local_ctr = (uint32_t)0;
    memset(ctx->remote_nonce, 0, AES_NONCE_BYTES);
    ctx->remote_ctr = (uint32_t)0;
    ctx->hello1_sent = false;
    ctx->hello1_ack_rcvd = false;
    ctx->hello2_sent = false;
    ctx->hello2_ack_rcvd = false;
    free(ctx->label);
}
