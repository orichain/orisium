#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "pqc.h"
#include "stdbool.h"
#include "ipc/protocol.h"
#include "log.h"
#include "orilink/protocol.h"
#include "poly1305-donna.h"
#include "workers/ipc/master_ipc_cmds.h"

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

status_t retry_packet(worker_context_t *worker_ctx, cow_c_session_t *session, packet_t *packet) {
    orilink_identity_t *identity = &session->identity;
    orilink_security_t *security = &session->security;
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    packet->sent_try_count++;
    packet->sent_time = current_time.r_uint64_t;
    if (async_set_timerfd_time(worker_ctx->label, &packet->timer_fd,
        (time_t)packet->interval_timer_fd,
        (long)((packet->interval_timer_fd - (time_t)packet->interval_timer_fd) * 1e9),
        (time_t)packet->interval_timer_fd,
        (long)((packet->interval_timer_fd - (time_t)packet->interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
//======================================================================
    puint8_t_size_t_status_t udp_data;
    udp_data.status = SUCCESS;
    udp_data.r_size_t = packet->len;
    udp_data.r_puint8_t = (uint8_t *)calloc(1, packet->len);
    memcpy(udp_data.r_puint8_t, packet->data, packet->len);
//----------------------------------------------------------------------
// Update trycount
//----------------------------------------------------------------------
    memcpy(udp_data.r_puint8_t + AES_TAG_BYTES + sizeof(uint32_t), &packet->sent_try_count, sizeof(uint8_t));
    size_t data_4mac_len = packet->len - AES_TAG_BYTES;
    uint8_t *data_4mac = (uint8_t *)calloc(1, data_4mac_len);
    if (!data_4mac) {
        LOG_ERROR("%sError calloc data_4mac for mac: %s", worker_ctx->label, strerror(errno));
        free(packet->data);
        packet->data = NULL;
        packet->len = 0;
        return FAILURE_NOMEM;
    }
    memcpy(data_4mac, udp_data.r_puint8_t + AES_TAG_BYTES, data_4mac_len);
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context ctx;
    poly1305_init(&ctx, security->mac_key);
    poly1305_update(&ctx, data_4mac, data_4mac_len);
    poly1305_finish(&ctx, mac);
    memcpy(udp_data.r_puint8_t, mac, AES_TAG_BYTES);
    free(data_4mac);
//----------------------------------------------------------------------    
    free(packet->data);
    packet->data = NULL;
    packet->len = 0;
    if (udp_data.status != SUCCESS) {
        return FAILURE;
    }
    if (worker_master_udp_data(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &identity->remote_addr, &udp_data, packet) != SUCCESS) {
        return FAILURE;
    }
//======================================================================
    return SUCCESS;
}

status_t retry_packet_ack(worker_context_t *worker_ctx, sio_c_session_t *session, packet_ack_t *packet_ack) {
    orilink_identity_t *identity = &session->identity;
    orilink_security_t *security = &session->security;
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    packet_ack->ack_sent_try_count++;
    packet_ack->ack_sent_time = current_time.r_uint64_t;
//======================================================================
    puint8_t_size_t_status_t udp_data;
    udp_data.status = SUCCESS;
    udp_data.r_size_t = packet_ack->len;
    udp_data.r_puint8_t = (uint8_t *)calloc(1, packet_ack->len);
    memcpy(udp_data.r_puint8_t, packet_ack->data, packet_ack->len);
//----------------------------------------------------------------------
// Update trycount
//----------------------------------------------------------------------
    memcpy(udp_data.r_puint8_t + AES_TAG_BYTES + sizeof(uint32_t), &packet_ack->ack_sent_try_count, sizeof(uint8_t));
    size_t data_4mac_len = packet_ack->len - AES_TAG_BYTES;
    uint8_t *data_4mac = (uint8_t *)calloc(1, data_4mac_len);
    if (!data_4mac) {
        LOG_ERROR("%sError calloc data_4mac for mac: %s", worker_ctx->label, strerror(errno));
        free(packet_ack->data);
        packet_ack->data = NULL;
        packet_ack->len = 0;
        return FAILURE_NOMEM;
    }
    memcpy(data_4mac, udp_data.r_puint8_t + AES_TAG_BYTES, data_4mac_len);
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context ctx;
    poly1305_init(&ctx, security->mac_key);
    poly1305_update(&ctx, data_4mac, data_4mac_len);
    poly1305_finish(&ctx, mac);
    memcpy(udp_data.r_puint8_t, mac, AES_TAG_BYTES);
    free(data_4mac);
//----------------------------------------------------------------------
    free(packet_ack->data);
    packet_ack->data = NULL;
    packet_ack->len = 0;
    if (udp_data.status != SUCCESS) {
        return FAILURE;
    }
    if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &identity->remote_addr, &udp_data, packet_ack) != SUCCESS) {
        return FAILURE;
    }
//======================================================================
    return SUCCESS;
}
