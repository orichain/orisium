#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
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
#include "stdbool.h"

void cleanup_dbr_worker(dbr_context_t *dbr_ctx) {
	cleanup_worker(&dbr_ctx->worker);
}

status_t setup_dbr_worker(dbr_context_t *dbr_ctx, worker_type_t wot, int worker_idx, int master_uds_fd) {
    if (setup_worker(&dbr_ctx->worker, "COW", wot, worker_idx, master_uds_fd) != SUCCESS) return FAILURE;
    return SUCCESS;
}

void run_dbr_worker(worker_type_t wot, uint8_t worker_idx, long initial_delay_ms, int master_uds_fd) {
    dbr_context_t dbr_ctx;
    if (setup_dbr_worker(&dbr_ctx, wot, worker_idx, master_uds_fd) != SUCCESS) goto exit;
    while (!dbr_ctx.worker.shutdown_requested) {
        int_status_t snfds = async_wait(dbr_ctx.worker.label, &dbr_ctx.worker.async);
		if (snfds.status != SUCCESS) continue;
        for (int n = 0; n < snfds.r_int; ++n) {
            if (dbr_ctx.worker.shutdown_requested) {
				break;
			}
			int_status_t fd_status = async_getfd(dbr_ctx.worker.label, &dbr_ctx.worker.async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents(dbr_ctx.worker.label, &dbr_ctx.worker.async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;
            if (current_fd == dbr_ctx.worker.heartbeat_timer_fd) {
				uint64_t u;
				read(dbr_ctx.worker.heartbeat_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
//----------------------------------------------------------------------
// Heartbeat dengan jitter
//----------------------------------------------------------------------
				double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * HEARTBEAT_JITTER_PERCENTAGE * 2) - HEARTBEAT_JITTER_PERCENTAGE;
                double new_heartbeat_interval_double = WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * (1.0 + jitter_amount);
                if (new_heartbeat_interval_double < 0.1) {
                    new_heartbeat_interval_double = 0.1;
                }
                if (async_set_timerfd_time(dbr_ctx.worker.label, &dbr_ctx.worker.heartbeat_timer_fd,
					(time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9),
                    (time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9)) != SUCCESS)
                {
                    dbr_ctx.worker.shutdown_requested = 1;
					LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", dbr_ctx.worker.label);
					continue;
                }
                if (worker_master_heartbeat(&dbr_ctx.worker, new_heartbeat_interval_double) != SUCCESS) {
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
                    dbr_ctx.worker.shutdown_requested = 1;
                    LOG_INFO("%sMaster disconnected. Initiating graceful shutdown...", dbr_ctx.worker.label);
                    continue;
                }
                ipc_raw_protocol_t_status_t ircvdi = receive_ipc_raw_protocol_message(dbr_ctx.worker.label, &master_uds_fd);
				if (ircvdi.status != SUCCESS) {
					LOG_ERROR("%sError receiving or deserializing IPC message from Master: %d", dbr_ctx.worker.label, ircvdi.status);
					continue;
				}
				if (ircvdi.r_ipc_raw_protocol_t->type == IPC_MASTER_WORKER_INFO) {
                    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(dbr_ctx.worker.label,
                        (const uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
                    );
                    if (deserialized_ircvdi.status != SUCCESS) {
                        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", dbr_ctx.worker.label, deserialized_ircvdi.status);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    } else {
                        LOG_DEBUG("%sipc_deserialize BERHASIL.", dbr_ctx.worker.label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                    }           
                    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
					ipc_master_worker_info_t *iinfoi = received_protocol->payload.ipc_master_worker_info;
                    if (iinfoi->flag == IT_SHUTDOWN) {
                        LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", dbr_ctx.worker.label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        dbr_ctx.worker.shutdown_requested = 1;
                        continue;
                    } else if (iinfoi->flag == IT_READY) {
                        LOG_INFO("%sMaster Ready ...", dbr_ctx.worker.label);
//----------------------------------------------------------------------
                        if (initial_delay_ms > 0) {
                            LOG_DEVEL_DEBUG("%sApplying initial delay of %ld ms...", dbr_ctx.worker.label, initial_delay_ms);
                            sleep_ms(initial_delay_ms);
                        }
//----------------------------------------------------------------------
                        if (worker_master_hello1(&dbr_ctx.worker) != SUCCESS) {
                            LOG_ERROR("%sWorker error. Initiating graceful shutdown...", dbr_ctx.worker.label);
                            dbr_ctx.worker.shutdown_requested = 1;
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
                    if (!dbr_ctx.worker.hello1_sent) {
                        LOG_ERROR("%sBelum pernah mengirim HELLO1", dbr_ctx.worker.label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    }
                    if (dbr_ctx.worker.hello1_ack_rcvd) {
                        LOG_ERROR("%sSudah ada HELLO1_ACK", dbr_ctx.worker.label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    }
					ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(dbr_ctx.worker.label,
                        (const uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
                    );
                    if (deserialized_ircvdi.status != SUCCESS) {
                        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", dbr_ctx.worker.label, deserialized_ircvdi.status);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    } else {
                        LOG_DEBUG("%sipc_deserialize BERHASIL.", dbr_ctx.worker.label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                    }           
                    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
					ipc_master_worker_hello1_ack_t *ihello1_acki = received_protocol->payload.ipc_master_worker_hello1_ack;
                    memcpy(dbr_ctx.worker.kem_ciphertext, ihello1_acki->kem_ciphertext, KEM_CIPHERTEXT_BYTES);
                    if (KEM_DECODE_SHAREDSECRET(dbr_ctx.worker.kem_sharedsecret, dbr_ctx.worker.kem_ciphertext, dbr_ctx.worker.kem_privatekey) != 0) {
                        LOG_ERROR("%sFailed to KEM_DECODE_SHAREDSECRET. Worker error. Initiating graceful shutdown...", dbr_ctx.worker.label);
                        dbr_ctx.worker.shutdown_requested = 1;
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    if (worker_master_hello2(&dbr_ctx.worker) != SUCCESS) {
                        LOG_ERROR("%sFailed to worker_master_hello2. Worker error. Initiating graceful shutdown...", dbr_ctx.worker.label);
                        dbr_ctx.worker.shutdown_requested = 1;
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    dbr_ctx.worker.hello1_ack_rcvd = true;
                    CLOSE_IPC_PROTOCOL(&received_protocol);
					continue;
				} else if (ircvdi.r_ipc_raw_protocol_t->type == IPC_MASTER_WORKER_HELLO2_ACK) {
                    if (!dbr_ctx.worker.hello2_sent) {
                        LOG_ERROR("%sBelum pernah mengirim HELLO2", dbr_ctx.worker.label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    }
                    if (dbr_ctx.worker.hello2_ack_rcvd) {
                        LOG_ERROR("%sSudah ada HELLO2_ACK", dbr_ctx.worker.label);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    }
					ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(dbr_ctx.worker.label,
                        (const uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
                    );
                    if (deserialized_ircvdi.status != SUCCESS) {
                        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", dbr_ctx.worker.label, deserialized_ircvdi.status);
                        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                        continue;
                    } else {
                        LOG_DEBUG("%sipc_deserialize BERHASIL.", dbr_ctx.worker.label);
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
                    memcpy(dbr_ctx.worker.remote_nonce, ihello2_acki->encrypted_wot_index, AES_NONCE_BYTES);
                    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
                    memcpy(encrypted_wot_index, ihello2_acki->encrypted_wot_index + AES_NONCE_BYTES, sizeof(uint8_t) + sizeof(uint8_t));
                    uint8_t data_mac[AES_TAG_BYTES];
                    memcpy(data_mac, ihello2_acki->encrypted_wot_index + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
                    uint8_t encrypted_wot_index1[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t)];
                    memcpy(encrypted_wot_index1, ihello2_acki->encrypted_wot_index, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
                    uint8_t mac[AES_TAG_BYTES];
                    poly1305_context mac_ctx;
                    poly1305_init(&mac_ctx, dbr_ctx.worker.kem_sharedsecret);
                    poly1305_update(&mac_ctx, encrypted_wot_index1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
                    poly1305_finish(&mac_ctx, mac);
                    if (!poly1305_verify(mac, data_mac)) {
                        LOG_ERROR("%sFailed to Mac Tidak Sesuai. Worker error. Initiating graceful shutdown...", dbr_ctx.worker.label);
                        dbr_ctx.worker.shutdown_requested = 1;
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }            
                    uint32_t temp_remote_ctr = (uint32_t)0;
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
                    uint8_t decrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
                    aes256ctx aes_ctx;
                    aes256_ctr_keyexp(&aes_ctx, dbr_ctx.worker.kem_sharedsecret);
//=========================================IV===========================    
                    uint8_t keystream_buffer[sizeof(uint8_t) + sizeof(uint8_t)];
                    uint8_t iv[AES_IV_BYTES];
                    memcpy(iv, dbr_ctx.worker.remote_nonce, AES_NONCE_BYTES);
                    uint32_t remote_ctr_be = htobe32(temp_remote_ctr);
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
                    if (*(uint8_t *)&dbr_ctx.worker.wot != *(uint8_t *)&data_wot) {
                        LOG_ERROR("%sberbeda wot. Worker error. Initiating graceful shutdown...", dbr_ctx.worker.label);
                        dbr_ctx.worker.shutdown_requested = 1;
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    uint8_t data_index;
                    memcpy(&data_index, decrypted_wot_index + sizeof(uint8_t), sizeof(uint8_t));
                    if (dbr_ctx.worker.idx != data_index) {
                        LOG_ERROR("%sberbeda index. Worker error. Initiating graceful shutdown...", dbr_ctx.worker.label);
                        dbr_ctx.worker.shutdown_requested = 1;
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//----------------------------------------------------------------------
// Aktifkan Heartbeat Karna security/Enkripsi Sudah Ready
//---------------------------------------------------------------------- 
                    if (async_create_incoming_event(dbr_ctx.worker.label, &dbr_ctx.worker.async, &dbr_ctx.worker.heartbeat_timer_fd) != SUCCESS) {
                        LOG_ERROR("%sWorker error. Initiating graceful shutdown...", dbr_ctx.worker.label);
                        dbr_ctx.worker.shutdown_requested = 1;
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//----------------------------------------------------------------------
// Menganggap data valid dengan integritas
//---------------------------------------------------------------------- 
                    dbr_ctx.worker.remote_ctr = (uint32_t)1;//sudah melakukan dekripsi data valid 1 kali
                    dbr_ctx.worker.hello2_ack_rcvd = true;
//---------------------------------------------------------------------- 
                    CLOSE_IPC_PROTOCOL(&received_protocol);
					continue;
				} else {
                    LOG_ERROR("%sUnknown protocol type %d from Master. Ignoring.", dbr_ctx.worker.label, ircvdi.r_ipc_raw_protocol_t->type);
                    CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                    continue;
                }
            } else {
//======================================================================
// Event yang belum ditangkap
//======================================================================                 
                LOG_ERROR("%sUnknown FD event %d.", dbr_ctx.worker.label, current_fd);
//======================================================================
            }
        }
    }

//======================================================================
// DBR Cleanup
//======================================================================    
exit:    
    cleanup_dbr_worker(&dbr_ctx);
}
