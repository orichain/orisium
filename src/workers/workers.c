#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "pqc.h"
#include "stdbool.h"
#include "ipc.h"
#include "workers/workers.h"

status_t setup_worker(worker_context_t *ctx, const char *woname, worker_type_t *wot, uint8_t *index, int *master_uds_fd) {
    ctx->pid = getpid();
    ctx->shutdown_requested = 0;
    ctx->async.async_fd = -1;
    ctx->heartbeat_timer_fd = -1;
    ctx->wot = wot;
    ctx->index = index;
    ctx->master_uds_fd = master_uds_fd;
//----------------------------------------------------------------------
// Inisialisasi seed dengan waktu saat ini untuk hasil yang berbeda setiap kali
// Seed untuk random() jitter
//----------------------------------------------------------------------
    srandom(time(NULL) ^ ctx->pid);
//----------------------------------------------------------------------
// Setup label
//----------------------------------------------------------------------
	int needed = snprintf(NULL, 0, "[%s %d]: ", woname, *ctx->index);
	ctx->label = malloc(needed + 1);
	snprintf(ctx->label, needed + 1, "[%s %d]: ", woname, *ctx->index);  
//----------------------------------------------------------------------
// Setup IPC security
//----------------------------------------------------------------------
    ctx->kem_privatekey = (uint8_t *)calloc(1, KEM_PRIVATEKEY_BYTES);
    ctx->kem_publickey = (uint8_t *)calloc(1, KEM_PUBLICKEY_BYTES);
    ctx->kem_ciphertext = (uint8_t *)calloc(1, KEM_CIPHERTEXT_BYTES);
    ctx->kem_sharedsecret = (uint8_t *)calloc(1, KEM_SHAREDSECRET_BYTES);
    ctx->aes_key = (uint8_t *)calloc(1, HASHES_BYTES);
    ctx->mac_key = (uint8_t *)calloc(1, HASHES_BYTES);
    ctx->local_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    ctx->remote_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    ctx->local_ctr = (uint32_t)0;
    ctx->remote_ctr = (uint32_t)0;
    ctx->hello1_sent = false;
    ctx->hello1_ack_rcvd = false;
    ctx->hello2_sent = false;
    ctx->hello2_ack_rcvd = false;
//----------------------------------------------------------------------
// Setup IPC rekeying
//----------------------------------------------------------------------
    ctx->is_rekeying = false;
    ctx->rekeying_queue = NULL;
//----------------------------------------------------------------------
	if (async_create(ctx->label, &ctx->async) != SUCCESS) return FAILURE;
	if (async_create_incoming_event_with_disconnect(ctx->label, &ctx->async, ctx->master_uds_fd) != SUCCESS) return FAILURE;
//----------------------------------------------------------------------
    return SUCCESS;
}

void cleanup_worker(worker_context_t *ctx) {
    memset(ctx->kem_privatekey, 0, KEM_PRIVATEKEY_BYTES);
    memset(ctx->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(ctx->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(ctx->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    memset(ctx->aes_key, 0, HASHES_BYTES);
    memset(ctx->mac_key, 0, HASHES_BYTES);
    memset(ctx->local_nonce, 0, AES_NONCE_BYTES);
    ctx->local_ctr = (uint32_t)0;
    memset(ctx->remote_nonce, 0, AES_NONCE_BYTES);
    ctx->remote_ctr = (uint32_t)0;
    free(ctx->kem_privatekey);
    free(ctx->kem_publickey);
    free(ctx->kem_ciphertext);
    free(ctx->kem_sharedsecret);
    free(ctx->aes_key);
    free(ctx->mac_key);
    free(ctx->local_nonce);
    free(ctx->remote_nonce);
    ctx->hello1_sent = false;
    ctx->hello1_ack_rcvd = false;
    ctx->hello2_sent = false;
    ctx->hello2_ack_rcvd = false;
    ctx->is_rekeying = false;
    ipc_cleanup_protocol_queue(&ctx->rekeying_queue);
    async_delete_event(ctx->label, &ctx->async, ctx->master_uds_fd);
    CLOSE_FD(ctx->master_uds_fd);
	async_delete_event(ctx->label, &ctx->async, &ctx->heartbeat_timer_fd);
    CLOSE_FD(&ctx->heartbeat_timer_fd);
    CLOSE_FD(&ctx->async.async_fd);
    free(ctx->label);
}
