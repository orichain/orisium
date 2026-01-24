#include "workers/workers.h"
#include "types.h"

status_t setup_worker(worker_context_t *ctx, const char *woname, worker_type_t *wot, uint8_t *index, int *master_uds_fd) {
    ctx->arena_buffer = (uint8_t *)calloc(1, WORKER_ARENA_SIZE);
    int result = oritlsf_setup_pool(&ctx->oritlsf_pool, ctx->arena_buffer, WORKER_ARENA_SIZE);
    if (result != 0) {
        LOG_ERROR("%sFailed To oritlsf_setup_pool", "[ORITLSF]: ");
        return FAILURE;
    }
    ctx->pid = getpid();
    ctx->shutdown_requested = 0;
    ctx->async.async_fd = -1;
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
    ctx->label = (char *)oritlsf_calloc(__FILE__, __LINE__,
                                        &ctx->oritlsf_pool,
                                        needed + 1,
                                        sizeof(char)
                                        );
	snprintf(ctx->label, needed + 1, "[%s %d]: ", woname, *ctx->index);
    //----------------------------------------------------------------------
    generate_uint64_t_id(ctx->label, &ctx->heartbeat_timer_id.id);
    ctx->heartbeat_timer_id.event = NULL;
    ctx->heartbeat_timer_id.delay_us = 0.0;
    ctx->heartbeat_timer_id.event_type = TE_HEARTBEAT;
    //----------------------------------------------------------------------
    ctx->buffer = (et_buffer_t *)oritlsf_calloc(__FILE__, __LINE__,
                                                &ctx->oritlsf_pool,
                                                1,
                                                sizeof(et_buffer_t)
                                                );
    et_buffer_t *buffer = ctx->buffer;
    buffer->read_step = 0;
    buffer->buffer_in = NULL;
    buffer->in_size_tb = 0;
    buffer->in_size_c = 0;
    buffer->buffer_out = NULL;
    buffer->out_size_tb = 0;
    buffer->out_size_c = 0;
    //----------------------------------------------------------------------
    // Setup IPC security
    //----------------------------------------------------------------------
    ctx->kem_privatekey = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__,
                                                    &ctx->oritlsf_pool,
                                                    KEM_PRIVATEKEY_BYTES,
                                                    sizeof(uint8_t)
                                                    );
    ctx->kem_publickey = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__,
                                                   &ctx->oritlsf_pool,
                                                   KEM_PUBLICKEY_BYTES,
                                                   sizeof(uint8_t)
                                                   );
    ctx->kem_ciphertext = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__,
                                                    &ctx->oritlsf_pool,
                                                    KEM_CIPHERTEXT_BYTES,
                                                    sizeof(uint8_t)
                                                    );
    ctx->kem_sharedsecret = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__,
                                                      &ctx->oritlsf_pool,
                                                      KEM_SHAREDSECRET_BYTES,
                                                      sizeof(uint8_t)
                                                      );
    ctx->aes_key = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__,
                                             &ctx->oritlsf_pool,
                                             HASHES_BYTES,
                                             sizeof(uint8_t)
                                             );
    ctx->mac_key = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__,
                                             &ctx->oritlsf_pool,
                                             HASHES_BYTES,
                                             sizeof(uint8_t)
                                             );
    ctx->local_nonce = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__,
                                                 &ctx->oritlsf_pool,
                                                 AES_NONCE_BYTES,
                                                 sizeof(uint8_t)
                                                 );
    ctx->remote_nonce = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__,
                                                  &ctx->oritlsf_pool,
                                                  AES_NONCE_BYTES,
                                                  sizeof(uint8_t)
                                                  );
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
    ctx->rekeying_queue_head = NULL;
    ctx->rekeying_queue_tail = NULL;
    //----------------------------------------------------------------------
	if (async_create(ctx->label, &ctx->async) != SUCCESS) return FAILURE;
	if (async_create_inout_event(ctx->label, &ctx->async, ctx->master_uds_fd, EIT_FD) != SUCCESS) return FAILURE;
    //----------------------------------------------------------------------
    if (oritw_setup(ctx->label, &ctx->oritlsf_pool, &ctx->async, &ctx->timer) != SUCCESS) return FAILURE;
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
    oritlsf_free(&ctx->oritlsf_pool, (void **)&ctx->kem_privatekey);
    oritlsf_free(&ctx->oritlsf_pool, (void **)&ctx->kem_publickey);
    oritlsf_free(&ctx->oritlsf_pool, (void **)&ctx->kem_ciphertext);
    oritlsf_free(&ctx->oritlsf_pool, (void **)&ctx->kem_sharedsecret);
    oritlsf_free(&ctx->oritlsf_pool, (void **)&ctx->aes_key);
    oritlsf_free(&ctx->oritlsf_pool, (void **)&ctx->mac_key);
    oritlsf_free(&ctx->oritlsf_pool, (void **)&ctx->local_nonce);
    oritlsf_free(&ctx->oritlsf_pool, (void **)&ctx->remote_nonce);
    ctx->hello1_sent = false;
    ctx->hello1_ack_rcvd = false;
    ctx->hello2_sent = false;
    ctx->hello2_ack_rcvd = false;
    ctx->is_rekeying = false;
    CLOSE_UDS(ctx->master_uds_fd);
    //----------------------------------------------------------------------
    if (ctx->heartbeat_timer_id.event) {
        oritw_remove_event(ctx->label, &ctx->oritlsf_pool, &ctx->async, &ctx->timer, &ctx->heartbeat_timer_id.event);
        ctx->heartbeat_timer_id.id = 0ULL;
        ctx->heartbeat_timer_id.delay_us = 0.0;
        ctx->heartbeat_timer_id.event_type = TE_UNKNOWN;
    }
    //----------------------------------------------------------------------
	int needed = strlen(ctx->label);
    char llabel[needed + 1];
    strlcpy(llabel, ctx->label, needed + 1);
    oritw_cleanup(ctx->label, &ctx->oritlsf_pool, &ctx->async, &ctx->timer);
    //----------------------------------------------------------------------
    CLOSE_FD(&ctx->async.async_fd);
    oritlsf_free(&ctx->oritlsf_pool, (void **)&ctx->label);
    //----------------------------------------------------------------------
    CLOSE_ET_BUFFER(&ctx->oritlsf_pool, &ctx->buffer);
    //----------------------------------------------------------------------
	void *reclaimed_buffer = oritlsf_cleanup_pool(llabel, &ctx->oritlsf_pool);
    if (reclaimed_buffer != ctx->arena_buffer) {
        LOG_ERROR("%sFailed To oritlsf_cleanup_pool.", llabel);
    }
    free(ctx->arena_buffer);
}
