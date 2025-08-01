#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <endian.h>

#include "log.h"
#include "ipc/protocol.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/master_ipc_cmds.h"
#include "workers/worker.h"
#include "pqc.h"
#include "poly1305-donna.h"
#include "aes.h"

void cleanup_sio_worker(sio_context_t *sio_ctx) {
	cleanup_worker(&sio_ctx->worker);
}

status_t setup_sio_worker(sio_context_t *sio_ctx, worker_type_t wot, int worker_idx, int master_uds_fd) {
    if (setup_worker(&sio_ctx->worker, "COW", wot, worker_idx, master_uds_fd) != SUCCESS) return FAILURE;
    return SUCCESS;
}

void run_sio_worker(worker_type_t wot, uint8_t worker_idx, long initial_delay_ms, int master_uds_fd) {
    sio_context_t sio_ctx;
    worker_context_t *ctx = &sio_ctx.worker;
    if (setup_sio_worker(&sio_ctx, wot, worker_idx, master_uds_fd) != SUCCESS) goto exit;
    while (!ctx->shutdown_requested) {
        int_status_t snfds = async_wait(ctx->label, &ctx->async);
		if (snfds.status != SUCCESS) continue;
        for (int n = 0; n < snfds.r_int; ++n) {
            if (ctx->shutdown_requested) {
				break;
			}
			int_status_t fd_status = async_getfd(ctx->label, &ctx->async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents(ctx->label, &ctx->async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;
            if (current_fd == ctx->heartbeat_timer_fd) {
				uint64_t u;
				read(ctx->heartbeat_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
//----------------------------------------------------------------------
// Heartbeat dengan jitter
//----------------------------------------------------------------------
				double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * HEARTBEAT_JITTER_PERCENTAGE * 2) - HEARTBEAT_JITTER_PERCENTAGE;
                double new_heartbeat_interval_double = WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * (1.0 + jitter_amount);
                if (new_heartbeat_interval_double < 0.1) {
                    new_heartbeat_interval_double = 0.1;
                }
                if (async_set_timerfd_time(ctx->label, &ctx->heartbeat_timer_fd,
					(time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9),
                    (time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9)) != SUCCESS)
                {
                    ctx->shutdown_requested = 1;
					LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", ctx->label);
					continue;
                }
                if (worker_master_heartbeat(&sio_ctx.worker, new_heartbeat_interval_double) != SUCCESS) {
                    continue;
                } else {
                    continue;
                }
//----------------------------------------------------------------------
			} else if (current_fd == master_uds_fd) {
                if (async_event_is_EPOLLHUP(current_events) ||
                    async_event_is_EPOLLERR(current_events) ||
                    async_event_is_EPOLLRDHUP(current_events))
                {
                    ctx->shutdown_requested = 1;
                    LOG_INFO("%sMaster disconnected. Initiating graceful shutdown...", ctx->label);
                    continue;
                }
                ipc_raw_protocol_t_status_t ircvdi = receive_ipc_raw_protocol_message(ctx->label, &master_uds_fd);
				if (ircvdi.status != SUCCESS) {
					LOG_ERROR("%sError receiving or deserializing IPC message from Master: %d", ctx->label, ircvdi.status);
					continue;
				}
                if (check_mac_ctr(
                        ctx->label, 
                        ctx->aes_key, 
                        ctx->mac_key, 
                        &ctx->remote_ctr, 
                        ircvdi.r_ipc_raw_protocol_t
                    ) != SUCCESS
                )
                {
                    CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                    continue;
                }
				if (ircvdi.r_ipc_raw_protocol_t->type == IPC_MASTER_WORKER_INFO) {
                    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(ctx->label,
                        ctx->aes_key, ctx->remote_nonce, &ctx->remote_ctr,
                        (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
                    );
                    if (deserialized_ircvdi.status != SUCCESS) {
                        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", ctx->label, deserialized_ircvdi.status);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    } else {
                        LOG_DEBUG("%sipc_deserialize BERHASIL.", ctx->label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                    }           
                    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
					ipc_master_worker_info_t *iinfoi = received_protocol->payload.ipc_master_worker_info;
                    if (iinfoi->flag == IT_SHUTDOWN) {
                        LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        ctx->shutdown_requested = 1;
                        continue;
                    } else if (iinfoi->flag == IT_READY) {
                        LOG_INFO("%sMaster Ready ...", ctx->label);
//----------------------------------------------------------------------
                        if (initial_delay_ms > 0) {
                            LOG_DEBUG("%sApplying initial delay of %ld ms...", ctx->label, initial_delay_ms);
                            sleep_ms(initial_delay_ms);
                        }
//----------------------------------------------------------------------
                        if (KEM_GENERATE_KEYPAIR(ctx->kem_publickey, ctx->kem_privatekey) != 0) {
                            LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", ctx->label);
                            ctx->shutdown_requested = 1;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
                            continue;
                        }
                        if (worker_master_hello1(&sio_ctx.worker) != SUCCESS) {
                            LOG_ERROR("%sWorker error. Initiating graceful shutdown...", ctx->label);
                            ctx->shutdown_requested = 1;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
                            continue;
                        }
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    } else if (iinfoi->flag == IT_REKEYING) {
                        LOG_INFO("%sMaster Rekeying ...", ctx->label);
//----------------------------------------------------------------------
                        if (initial_delay_ms > 0) {
                            LOG_DEBUG("%sApplying initial delay of %ld ms...", ctx->label, initial_delay_ms);
                            sleep_ms(initial_delay_ms);
                        }
//----------------------------------------------------------------------
                        if (KEM_GENERATE_KEYPAIR(ctx->kem_publickey, ctx->kem_privatekey) != 0) {
                            LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", ctx->label);
                            ctx->shutdown_requested = 1;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
                            continue;
                        }
                        if (async_delete_event(ctx->label, &ctx->async, &ctx->heartbeat_timer_fd) != SUCCESS) {		
                            LOG_INFO("%sGagal async_delete_event hb timer, Untuk Rekeying", ctx->label);
                            ctx->shutdown_requested = 1;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
                            continue;
                        }
                        CLOSE_FD(&ctx->heartbeat_timer_fd);
                        ctx->hello1_sent = false;
                        ctx->hello1_ack_rcvd = false;
                        ctx->hello2_sent = false;
                        ctx->hello2_ack_rcvd = false;
                        if (worker_master_hello1(&sio_ctx.worker) != SUCCESS) {
                            LOG_ERROR("%sWorker error. Initiating graceful shutdown...", ctx->label);
                            ctx->shutdown_requested = 1;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
                            continue;
                        }
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    } else {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
				} else if (ircvdi.r_ipc_raw_protocol_t->type == IPC_MASTER_WORKER_HELLO1_ACK) {
                    if (!ctx->hello1_sent) {
                        LOG_ERROR("%sBelum pernah mengirim HELLO1", ctx->label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    }
                    if (ctx->hello1_ack_rcvd) {
                        LOG_ERROR("%sSudah ada HELLO1_ACK", ctx->label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    }
					ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(ctx->label,
                        ctx->aes_key, ctx->remote_nonce, &ctx->remote_ctr,
                        (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
                    );
                    if (deserialized_ircvdi.status != SUCCESS) {
                        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", ctx->label, deserialized_ircvdi.status);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    } else {
                        LOG_DEBUG("%sipc_deserialize BERHASIL.", ctx->label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                    }           
                    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
					ipc_master_worker_hello1_ack_t *ihello1_acki = received_protocol->payload.ipc_master_worker_hello1_ack;
                    memcpy(ctx->kem_ciphertext, ihello1_acki->kem_ciphertext, KEM_CIPHERTEXT_BYTES);
                    if (KEM_DECODE_SHAREDSECRET(ctx->kem_sharedsecret, ctx->kem_ciphertext, ctx->kem_privatekey) != 0) {
                        LOG_ERROR("%sFailed to KEM_DECODE_SHAREDSECRET. Worker error. Initiating graceful shutdown...", ctx->label);
                        ctx->shutdown_requested = 1;
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    if (worker_master_hello2(&sio_ctx.worker) != SUCCESS) {
                        LOG_ERROR("%sFailed to worker_master_hello2. Worker error. Initiating graceful shutdown...", ctx->label);
                        ctx->shutdown_requested = 1;
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    memcpy(ctx->remote_nonce, ihello1_acki->nonce, AES_NONCE_BYTES);
                    ctx->hello1_ack_rcvd = true;
                    CLOSE_IPC_PROTOCOL(&received_protocol);
					continue;
				} else if (ircvdi.r_ipc_raw_protocol_t->type == IPC_MASTER_WORKER_HELLO2_ACK) {
                    if (!ctx->hello2_sent) {
                        LOG_ERROR("%sBelum pernah mengirim HELLO2", ctx->label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    }
                    if (ctx->hello2_ack_rcvd) {
                        LOG_ERROR("%sSudah ada HELLO2_ACK", ctx->label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    }
					ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(ctx->label,
                        ctx->aes_key, ctx->remote_nonce, &ctx->remote_ctr,
                        (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
                    );
                    if (deserialized_ircvdi.status != SUCCESS) {
                        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", ctx->label, deserialized_ircvdi.status);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    } else {
                        LOG_DEBUG("%sipc_deserialize BERHASIL.", ctx->label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                    }           
                    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
					ipc_master_worker_hello2_ack_t *ihello2_acki = received_protocol->payload.ipc_master_worker_hello2_ack;
//======================================================================
// Ambil remote_nonce
// Set remote_ctr = 0
// Ambil encrypter wot+index
// Ambil Mac
// Cocokkan MAc
// Decrypt wot dan index
//======================================================================
                    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
                    memcpy(encrypted_wot_index, ihello2_acki->encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
                    uint8_t data_mac[AES_TAG_BYTES];
                    memcpy(data_mac, ihello2_acki->encrypted_wot_index + sizeof(uint8_t) + sizeof(uint8_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// Tmp aes_key
//----------------------------------------------------------------------
                    uint8_t tmp_aes_key[HASHES_BYTES];
                    kdf1(ctx->kem_sharedsecret, tmp_aes_key);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
                    uint8_t mac[AES_TAG_BYTES];
                    poly1305_context mac_ctx;
                    poly1305_init(&mac_ctx, ctx->mac_key);
                    poly1305_update(&mac_ctx, encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
                    poly1305_finish(&mac_ctx, mac);
                    if (!poly1305_verify(mac, data_mac)) {
                        LOG_ERROR("%sFailed to Mac Tidak Sesuai. Worker error...", ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }            
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
                    uint8_t decrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
                    aes256ctx aes_ctx;
                    aes256_ctr_keyexp(&aes_ctx, tmp_aes_key);
//=========================================IV===========================    
                    uint8_t keystream_buffer[sizeof(uint8_t) + sizeof(uint8_t)];
                    uint8_t iv[AES_IV_BYTES];
                    memcpy(iv, ctx->remote_nonce, AES_NONCE_BYTES);
                    uint32_t remote_ctr_be = htobe32(ctx->remote_ctr);
                    memcpy(iv + AES_NONCE_BYTES, &remote_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
                    aes256_ctr(keystream_buffer, sizeof(uint8_t) + sizeof(uint8_t), iv, &aes_ctx);
                    for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t); i++) {
                        decrypted_wot_index[i] = encrypted_wot_index[i] ^ keystream_buffer[i];
                    }
                    aes256_ctx_release(&aes_ctx);
//----------------------------------------------------------------------
// Mencocokkan wot index
//----------------------------------------------------------------------
                    worker_type_t data_wot;
                    memcpy((uint8_t *)&data_wot, decrypted_wot_index, sizeof(uint8_t));
                    if (*(uint8_t *)&ctx->wot != *(uint8_t *)&data_wot) {
                        LOG_ERROR("%sberbeda wot. Worker error...", ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    uint8_t data_index;
                    memcpy(&data_index, decrypted_wot_index + sizeof(uint8_t), sizeof(uint8_t));
                    if (ctx->idx != data_index) {
                        LOG_ERROR("%sberbeda index. Worker error...", ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//----------------------------------------------------------------------
// Aktifkan Heartbeat Karna security/Enkripsi Sudah Ready
//---------------------------------------------------------------------- 
                    if (async_create_timerfd(ctx->label, &ctx->heartbeat_timer_fd) != SUCCESS) {
                        LOG_ERROR("%sWorker error async_create_timerfd...", ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    if (async_set_timerfd_time(ctx->label, &ctx->heartbeat_timer_fd,
                        WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0,
                        WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0) != SUCCESS)
                    {
                        LOG_ERROR("%sWorker error async_set_timerfd_time...", ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    if (async_create_incoming_event(ctx->label, &ctx->async, &ctx->heartbeat_timer_fd) != SUCCESS) {
                        LOG_ERROR("%sWorker error async_create_incoming_event...", ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//----------------------------------------------------------------------
// Menganggap data valid dengan integritas
//---------------------------------------------------------------------- 
                    memcpy(ctx->aes_key, tmp_aes_key, HASHES_BYTES);
                    memset (tmp_aes_key, 0, HASHES_BYTES);
                    ctx->remote_ctr = (uint32_t)0;
                    ctx->hello2_ack_rcvd = true;
//---------------------------------------------------------------------- 
                    CLOSE_IPC_PROTOCOL(&received_protocol);
					continue;
				} else {
                    LOG_ERROR("%sUnknown protocol type %d from Master. Ignoring.", ctx->label, ircvdi.r_ipc_raw_protocol_t->type);
                    CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                    continue;
                }
            } else {
//======================================================================
// Event yang belum ditangkap
//======================================================================                 
                LOG_ERROR("%sUnknown FD event %d.", ctx->label, current_fd);
//======================================================================
            }
        }
    }

exit:    
    cleanup_sio_worker(&sio_ctx);
}
