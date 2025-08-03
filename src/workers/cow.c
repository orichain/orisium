#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <endian.h>
#include <signal.h>

#include "log.h"
#include "ipc/protocol.h"
#include "orilink/protocol.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/master_ipc_cmds.h"
#include "workers/client_orilink_cmds.h"
#include "kalman.h"
#include "pqc.h"
#include "poly1305-donna.h"
#include "aes.h"

void setup_cow_session(cow_c_session_t *single_session) {
    single_session->in_use = false;
    memset(&single_session->identity.remote_addr, 0, sizeof(struct sockaddr_in6));
    memset(single_session->identity.kem_privatekey, 0, KEM_PRIVATEKEY_BYTES);
    memset(single_session->identity.kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(single_session->identity.kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(single_session->identity.kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    single_session->identity.client_id = 0ULL;
    single_session->identity.server_id = 0ULL;
    single_session->identity.port = 0x0000;
    memset(single_session->identity.local_nonce, 0, AES_NONCE_BYTES);
    single_session->identity.local_ctr = (uint32_t)0;
    memset(single_session->identity.remote_nonce, 0, AES_NONCE_BYTES);
    single_session->identity.remote_ctr = (uint32_t)0;
    memset(single_session->encrypted_server_id_port, 0, AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t) + AES_TAG_BYTES);
    memset(single_session->temp_kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    single_session->new_client_id = 0ULL;
    setup_oricle_double(&single_session->identity.rtt, (double)0);
    setup_oricle_double(&single_session->identity.retry, (double)0);
    CLOSE_FD(&single_session->sock_fd);
    setup_hello(&single_session->hello1);
    setup_hello(&single_session->hello2);
    setup_hello(&single_session->hello3);
    setup_hello(&single_session->hello_end);
}

void cleanup_cow_session(const char *label, async_type_t *cow_async, cow_c_session_t *single_session) {
    single_session->in_use = false;
    memset(&single_session->identity.remote_addr, 0, sizeof(struct sockaddr_in6));
    memset(single_session->identity.kem_privatekey, 0, KEM_PRIVATEKEY_BYTES);
    memset(single_session->identity.kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(single_session->identity.kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(single_session->identity.kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    single_session->identity.client_id = 0ULL;
    single_session->identity.server_id = 0ULL;
    single_session->identity.port = 0x0000;
    memset(single_session->identity.local_nonce, 0, AES_NONCE_BYTES);
    single_session->identity.local_ctr = (uint32_t)0;
    memset(single_session->identity.remote_nonce, 0, AES_NONCE_BYTES);
    single_session->identity.remote_ctr = (uint32_t)0;
    memset(single_session->encrypted_server_id_port, 0, AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t) + AES_TAG_BYTES);
    memset(single_session->temp_kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    single_session->new_client_id = 0ULL;
    cleanup_oricle_double(&single_session->identity.rtt);
    cleanup_oricle_double(&single_session->identity.retry);
    async_delete_event(label, cow_async, &single_session->sock_fd);
    CLOSE_FD(&single_session->sock_fd);
    cleanup_hello(label, cow_async, &single_session->hello1);
    cleanup_hello(label, cow_async, &single_session->hello2);
    cleanup_hello(label, cow_async, &single_session->hello3);
    cleanup_hello(label, cow_async, &single_session->hello_end);
}

bool server_disconnected(worker_context_t *ctx, int session_index, cow_c_session_t *single_session, uint8_t try_count) {
    if (try_count > (uint8_t)MAX_RETRY) {
        LOG_DEBUG("%s single_session %d: disconnect => try count %d.", ctx->label, session_index, try_count);
        cow_master_connection(ctx, &single_session->identity.remote_addr, CANNOTCONNECT);
        cleanup_cow_session(ctx->label, &ctx->async, single_session);
        return true;
    }
    return false;
}

status_t send_hello1(worker_context_t *ctx, cow_c_session_t *single_session) {
    uint64_t_status_t rt = get_realtime_time_ns(ctx->label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    single_session->hello1.sent = true;
    single_session->hello1.sent_try_count++;
    single_session->hello1.sent_time = rt.r_uint64_t;
    if (hello1(ctx->label, single_session) != SUCCESS) {
        printf("Error hello1\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(ctx->label, &single_session->hello1.timer_fd,
        (time_t)single_session->hello1.interval_timer_fd,
        (long)((single_session->hello1.interval_timer_fd - (time_t)single_session->hello1.interval_timer_fd) * 1e9),
        (time_t)single_session->hello1.interval_timer_fd,
        (long)((single_session->hello1.interval_timer_fd - (time_t)single_session->hello1.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

status_t send_hello2(worker_context_t *ctx, cow_c_session_t *single_session) {
    uint64_t_status_t rt = get_realtime_time_ns(ctx->label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    single_session->hello2.sent = true;
    single_session->hello2.sent_try_count++;
    single_session->hello2.sent_time = rt.r_uint64_t;
    if (hello2(ctx->label, single_session) != SUCCESS) {
        printf("Error hello2\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(ctx->label, &single_session->hello2.timer_fd,
        (time_t)single_session->hello2.interval_timer_fd,
        (long)((single_session->hello2.interval_timer_fd - (time_t)single_session->hello2.interval_timer_fd) * 1e9),
        (time_t)single_session->hello2.interval_timer_fd,
        (long)((single_session->hello2.interval_timer_fd - (time_t)single_session->hello2.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

status_t send_hello3(worker_context_t *ctx, cow_c_session_t *single_session) {
    uint64_t_status_t rt = get_realtime_time_ns(ctx->label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    single_session->hello3.sent = true;
    single_session->hello3.sent_try_count++;
    single_session->hello3.sent_time = rt.r_uint64_t;
    if (hello3(ctx->label, single_session) != SUCCESS) {
        printf("Error hello3\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(ctx->label, &single_session->hello3.timer_fd,
        (time_t)single_session->hello3.interval_timer_fd,
        (long)((single_session->hello3.interval_timer_fd - (time_t)single_session->hello3.interval_timer_fd) * 1e9),
        (time_t)single_session->hello3.interval_timer_fd,
        (long)((single_session->hello3.interval_timer_fd - (time_t)single_session->hello3.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

status_t send_hello_end(worker_context_t *ctx, cow_c_session_t *single_session) {
    uint64_t_status_t rt = get_realtime_time_ns(ctx->label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    single_session->hello_end.sent = true;
    single_session->hello_end.sent_try_count++;
    single_session->hello_end.sent_time = rt.r_uint64_t;
    if (hello_end(ctx->label, single_session) != SUCCESS) {
        printf("Error hello_end\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(ctx->label, &single_session->hello_end.timer_fd,
        (time_t)single_session->hello_end.interval_timer_fd,
        (long)((single_session->hello_end.interval_timer_fd - (time_t)single_session->hello_end.interval_timer_fd) * 1e9),
        (time_t)single_session->hello_end.interval_timer_fd,
        (long)((single_session->hello_end.interval_timer_fd - (time_t)single_session->hello_end.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

void cow_calculate_retry(worker_context_t *ctx, cow_c_session_t *single_session, int session_index, double try_count) {
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => RETRY %d", session_index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => RETRY %d", session_index);
    calculate_oricle_double(ctx->label, desc, &single_session->identity.retry, try_count, ((double)MAX_RETRY * (double)2));
    free(desc);
}

void cow_calculate_rtt(worker_context_t *ctx, cow_c_session_t *single_session, int session_index, double rtt_value) {
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => RTT %d", session_index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => RTT %d", session_index);
    calculate_oricle_double(ctx->label, desc, &single_session->identity.rtt, rtt_value, ((double)MAX_RTT_SEC * (double)1e9 * (double)2));
    free(desc);
}

void cleanup_cow_worker(worker_context_t *ctx, cow_c_session_t *sessions) {
    for (int i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
        cow_c_session_t *single_session;
        single_session = &sessions[i];
        if (single_session->in_use) {
            cleanup_cow_session(ctx->label, &ctx->async, single_session);
        }
    }
	cleanup_worker(ctx);
}

status_t setup_cow_worker(worker_context_t *ctx, cow_c_session_t *sessions, worker_type_t *wot, uint8_t *index, int *master_uds_fd) {
    if (setup_worker(ctx, "COW", wot, index, master_uds_fd) != SUCCESS) return FAILURE;
    for (int i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
        cow_c_session_t *single_session;
        single_session = &sessions[i];
        setup_cow_session(single_session);
    }
    return SUCCESS;
}

volatile sig_atomic_t cow_sigterm_requested = 0;

void cow_sigterm_handler(int sig) {
    cow_sigterm_requested = 1;
}

void run_cow_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd) {
    worker_context_t x_ctx;
    worker_context_t *ctx = &x_ctx;
    cow_c_session_t sessions[MAX_CONNECTION_PER_COW_WORKER];
    if (setup_cow_worker(ctx, sessions, wot, index, master_uds_fd) != SUCCESS) goto exit;
    signal(SIGTERM, cow_sigterm_handler);
    while (!ctx->shutdown_requested && !cow_sigterm_requested) {
        int_status_t snfds = async_wait(ctx->label, &ctx->async);
		if (snfds.status != SUCCESS) {
            if (snfds.status == FAILURE_EBADF) {
                ctx->shutdown_requested = 1;
            }
            continue;
        }
        for (int n = 0; n < snfds.r_int; ++n) {
            if (ctx->shutdown_requested || cow_sigterm_requested) {
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
                if (worker_master_heartbeat(ctx, new_heartbeat_interval_double) != SUCCESS) {
                    continue;
                } else {
                    continue;
                }
//----------------------------------------------------------------------
			} else if (current_fd == *ctx->master_uds_fd) {
                if (async_event_is_EPOLLHUP(current_events) ||
                    async_event_is_EPOLLERR(current_events) ||
                    async_event_is_EPOLLRDHUP(current_events))
                {
                    ctx->shutdown_requested = 1;
                    LOG_INFO("%sMaster disconnected. Initiating graceful shutdown...", ctx->label);
                    continue;
                }
                ipc_raw_protocol_t_status_t ircvdi = receive_ipc_raw_protocol_message(ctx->label, ctx->master_uds_fd);
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
                        if (*initial_delay_ms > 0) {
                            LOG_DEBUG("%sApplying initial delay of %ld ms...", ctx->label, *initial_delay_ms);
                            sleep_ms(*initial_delay_ms);
                        }
//----------------------------------------------------------------------
                        if (KEM_GENERATE_KEYPAIR(ctx->kem_publickey, ctx->kem_privatekey) != 0) {
                            LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", ctx->label);
                            ctx->shutdown_requested = 1;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
                            continue;
                        }
                        if (worker_master_hello1(ctx) != SUCCESS) {
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
                        if (*initial_delay_ms > 0) {
                            LOG_DEBUG("%sApplying initial delay of %ld ms...", ctx->label, *initial_delay_ms);
                            sleep_ms(*initial_delay_ms);
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
                        if (worker_master_hello1(ctx) != SUCCESS) {
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
                    if (worker_master_hello2(ctx) != SUCCESS) {
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
                    if (*(uint8_t *)ctx->wot != *(uint8_t *)&data_wot) {
                        LOG_ERROR("%sberbeda wot. Worker error...", ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    uint8_t data_index;
                    memcpy(&data_index, decrypted_wot_index + sizeof(uint8_t), sizeof(uint8_t));
                    if (*ctx->index != data_index) {
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
				} else if (ircvdi.r_ipc_raw_protocol_t->type == IPC_MASTER_COW_CONNECT) {                    
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
					ipc_master_cow_connect_t *cc = received_protocol->payload.ipc_master_cow_connect;
                    int slot_found = -1;
                    for (int i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
                        if (!sessions[i].in_use) {
                            sessions[i].in_use = true;
                            memcpy(&sessions[i].identity.remote_addr, &cc->server_addr, sizeof(struct sockaddr_in6));
                            slot_found = i;
                            break;
                        }
                    }
                    if (slot_found == -1) {
                        LOG_INFO("%sNO SLOT. master_cow_session_t <> cow_c_session_t. Tidak singkron. Worker error. Initiating graceful shutdown...", ctx->label);
                        ctx->shutdown_requested = 1;
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    cow_c_session_t *single_session;
                    single_session = &sessions[slot_found];
//======================================================================
// Setup sock_fd and connect to server
//======================================================================
                    struct addrinfo hints, *res, *rp;
                    memset(&hints, 0, sizeof(hints));
                    hints.ai_family = AF_UNSPEC;
                    hints.ai_socktype = SOCK_DGRAM;
                    hints.ai_protocol = IPPROTO_UDP;
                    char host_str[NI_MAXHOST];
                    char port_str[NI_MAXSERV];
                    int getname_res = getnameinfo((struct sockaddr *)&single_session->identity.remote_addr, sizeof(struct sockaddr_in6),
                                        host_str, NI_MAXHOST,
                                        port_str, NI_MAXSERV,
                                        NI_NUMERICHOST | NI_NUMERICSERV
                                      );
                    if (getname_res != 0) {
                        LOG_ERROR("%sgetnameinfo failed. %s", ctx->label, strerror(errno));
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    int gai_err = getaddrinfo(host_str, port_str, &hints, &res);
                    if (gai_err != 0) {
                        LOG_ERROR("%sgetaddrinfo error for UDP %s:%s: %s", ctx->label, host_str, port_str, gai_strerror(gai_err));
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    for (rp = res; rp != NULL; rp = rp->ai_next) {
                        single_session->sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                        if (single_session->sock_fd == -1) {
                            LOG_ERROR("%sUDP Socket creation failed: %s", ctx->label, strerror(errno));
                            CLOSE_IPC_PROTOCOL(&received_protocol);
                            continue;
                        }
                        LOG_DEBUG("%sUDP Socket FD %d created.", ctx->label, single_session->sock_fd);
                        status_t r_snbkg = set_nonblocking(ctx->label, single_session->sock_fd);
                        if (r_snbkg != SUCCESS) {
                            LOG_ERROR("%sset_nonblocking failed.", ctx->label);
                            CLOSE_IPC_PROTOCOL(&received_protocol);
                            continue;
                        }
                        LOG_DEBUG("%sUDP Socket FD %d set to non-blocking.", ctx->label, single_session->sock_fd);
                        int conn_res = connect(single_session->sock_fd, rp->ai_addr, rp->ai_addrlen);
                        if (conn_res == 0) {
                            LOG_INFO("%sUDP socket 'connected' to %s:%s (FD %d).", ctx->label, host_str, port_str, single_session->sock_fd);
                            CLOSE_IPC_PROTOCOL(&received_protocol);
                            break;
                        } else {
                            LOG_ERROR("%sUDP 'connect' failed for %s:%s (FD %d): %s", ctx->label, host_str, port_str, single_session->sock_fd, strerror(errno));
                            CLOSE_IPC_PROTOCOL(&received_protocol);
                            CLOSE_FD(&single_session->sock_fd);
                            continue;
                        }
                    }
                    freeaddrinfo(res);
                    if (single_session->sock_fd == -1) {
                        LOG_ERROR("%sFailed to set up any UDP socket for %s:%s.", ctx->label, host_str, port_str);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    if (async_create_incoming_event(ctx->label, &ctx->async, &single_session->sock_fd) != SUCCESS) {
                        LOG_ERROR("%sFailed to async_create_incoming_event for %s:%s.", ctx->label, host_str, port_str);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//======================================================================
// Generate Identity                    
//======================================================================
                    if (generate_connection_id(ctx->label, &single_session->identity.client_id) != SUCCESS) {
                        LOG_ERROR("%sFailed to generate_connection_id for %s:%s.", ctx->label, host_str, port_str);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    if (KEM_GENERATE_KEYPAIR(single_session->identity.kem_publickey, single_session->identity.kem_privatekey) != 0) {
                        LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR for %s:%s.", ctx->label, host_str, port_str);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//======================================================================
// Send HELLO1                    
//======================================================================           
                    if (async_create_timerfd(ctx->label, &single_session->hello1.timer_fd) != SUCCESS) {
                        LOG_ERROR("%sFailed to async_create_timerfd for %s:%s.", ctx->label, host_str, port_str);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//----------------------------------------------------------------------
                    if (send_hello1(ctx, single_session) != SUCCESS) {
                        LOG_ERROR("%sFailed to send_hello1 for %s:%s.", ctx->label, host_str, port_str);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//----------------------------------------------------------------------
                    if (async_create_incoming_event(ctx->label, &ctx->async, &single_session->hello1.timer_fd) != SUCCESS) {
                        LOG_ERROR("%sFailed to async_create_incoming_event for %s:%s.", ctx->label, host_str, port_str);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }        
//======================================================================    
                    CLOSE_IPC_PROTOCOL(&received_protocol);
					continue;
				} else {
                    LOG_ERROR("%sUnknown protocol type %d from Master. Ignoring.", ctx->label, ircvdi.r_ipc_raw_protocol_t->type);
                    CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                    continue;
                }
            } else {
                bool event_founded_in_session = false;
                for (int i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
                    cow_c_session_t *single_session;
                    single_session = &sessions[i];
                    if (single_session->in_use) {
                        if (current_fd == single_session->sock_fd) {
                            struct sockaddr_in6 server_addr;
                            char host_str[NI_MAXHOST];
                            char port_str[NI_MAXSERV];
                            
                            orilink_raw_protocol_t_status_t orcvdo = receive_orilink_raw_protocol_packet(
                                ctx->label,
                                &single_session->sock_fd,
                                (struct sockaddr *)&server_addr
                            );
                            if (orcvdo.status != SUCCESS) {
                                event_founded_in_session = true;
                                break;
                            }
                            int getname_res = getnameinfo((struct sockaddr *)&server_addr, sizeof(struct sockaddr_in6),
                                                host_str, NI_MAXHOST,
                                                port_str, NI_MAXSERV,
                                                NI_NUMERICHOST | NI_NUMERICSERV
                                              );
                            if (getname_res != 0) {
                                LOG_ERROR("%sgetnameinfo failed. %s", ctx->label, strerror(errno));
                                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                event_founded_in_session = true;
                                break;
                            }
                            size_t host_str_len = strlen(host_str);
                            if (host_str_len >= INET6_ADDRSTRLEN) {
                                LOG_ERROR("%sKoneksi ditolak dari IP %s. IP terlalu panjang.", ctx->label, host_str);
                                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                event_founded_in_session = true;
                                break;
                            }
                            char *endptr;
                            long port_num = strtol(port_str, &endptr, 10);
                            if (*endptr != '\0' || port_num <= 0 || port_num > 65535) {
                                LOG_ERROR("%sKoneksi ditolak dari IP %s. PORT di luar rentang (1-65535).", ctx->label, host_str);
                                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                event_founded_in_session = true;
                                break;
                            }
                            if (orcvdo.r_orilink_raw_protocol_t->type == ORILINK_HELLO1_ACK) {
                                if (
                                        sockaddr_equal((const struct sockaddr *)&single_session->identity.remote_addr, (const struct sockaddr *)&server_addr) &&
                                        single_session->hello1.sent
                                   )
                                {
                                    orilink_protocol_t_status_t deserialized_orcvdo = orilink_deserialize(ctx->label,
                                        single_session->identity.kem_sharedsecret, single_session->identity.remote_nonce, single_session->identity.remote_ctr,
                                        (const uint8_t*)orcvdo.r_orilink_raw_protocol_t->recv_buffer, orcvdo.r_orilink_raw_protocol_t->n
                                    );
                                    if (deserialized_orcvdo.status != SUCCESS) {
                                        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", ctx->label, deserialized_orcvdo.status);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                        event_founded_in_session = true;
                                        break;
                                    } else {
                                        LOG_DEBUG("%sorilink_deserialize BERHASIL.", ctx->label);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                    }  
                                    orilink_protocol_t* received_protocol = deserialized_orcvdo.r_orilink_protocol_t;
                                    orilink_hello1_ack_t *ohello1_ack = received_protocol->payload.orilink_hello1_ack;
                                    if (single_session->identity.client_id != ohello1_ack->client_id) {
                                        LOG_WARN("%sHELLO1_ACK ditolak dari IP %s. client_id berbeda.", ctx->label, host_str);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//======================================================================
// Send HELLO2                   
//======================================================================           
                                    if (async_create_timerfd(ctx->label, &single_session->hello2.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_timerfd.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
// Hitung rtt retry sebelum kirim data
//----------------------------------------------------------------------
                                    double try_count = (double)single_session->hello1.sent_try_count-(double)1;
                                    cow_calculate_retry(ctx, single_session, i, try_count);
                                    uint64_t_status_t rt = get_realtime_time_ns(ctx->label);
                                    if (rt.status != SUCCESS) {
                                        LOG_ERROR("%sFailed to get_realtime_time_ns.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
                                    single_session->hello1.ack_rcvd = true;
                                    single_session->hello1.ack_rcvd_time = rt.r_uint64_t;
                                    uint64_t interval_ull = single_session->hello1.ack_rcvd_time - single_session->hello1.sent_time;
                                    double rtt_value = (double)interval_ull;
                                    cow_calculate_rtt(ctx, single_session, i, rtt_value);
//----------------------------------------------------------------------
                                    if (send_hello2(ctx, single_session) != SUCCESS) {
                                        LOG_ERROR("%sFailed to send_hello2.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
                                    if (async_create_incoming_event(ctx->label, &ctx->async, &single_session->hello2.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_incoming_event.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }        
//----------------------------------------------------------------------
// Semua sudah bersih
//----------------------------------------------------------------------
                                    cleanup_hello(ctx->label, &ctx->async, &single_session->hello1);
//======================================================================  
                                    CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                    event_founded_in_session = true;
                                    break;
                                } else {
                                    LOG_ERROR("%sKoneksi ditolak Tidak pernah mengirim HELLO1 ke IP %s.", ctx->label, host_str);
                                    CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                    event_founded_in_session = true;
                                    break;
                                }
                            } else if (orcvdo.r_orilink_raw_protocol_t->type == ORILINK_HELLO2_ACK) {
                                if (
                                        sockaddr_equal((const struct sockaddr *)&single_session->identity.remote_addr, (const struct sockaddr *)&server_addr) &&
                                        single_session->hello1.sent &&
                                        single_session->hello2.sent
                                   )
                                {
                                    orilink_protocol_t_status_t deserialized_orcvdo = orilink_deserialize(ctx->label,
                                        single_session->identity.kem_sharedsecret, single_session->identity.remote_nonce, single_session->identity.remote_ctr,
                                        (const uint8_t*)orcvdo.r_orilink_raw_protocol_t->recv_buffer, orcvdo.r_orilink_raw_protocol_t->n
                                    );
                                    if (deserialized_orcvdo.status != SUCCESS) {
                                        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", ctx->label, deserialized_orcvdo.status);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                        event_founded_in_session = true;
                                        break;
                                    } else {
                                        LOG_DEBUG("%sorilink_deserialize BERHASIL.", ctx->label);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                    }  
                                    orilink_protocol_t* received_protocol = deserialized_orcvdo.r_orilink_protocol_t;
                                    orilink_hello2_ack_t *ohello2_ack = received_protocol->payload.orilink_hello2_ack;
                                    if (single_session->identity.client_id != ohello2_ack->client_id) {
                                        LOG_WARN("%HELLO2_ACK ditolak dari IP %s. client_id berbeda.", ctx->label, host_str);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
                                    memcpy(single_session->identity.kem_ciphertext, ohello2_ack->ciphertext1, KEM_CIPHERTEXT_BYTES / 2);
//======================================================================
// Send HELLO3
//======================================================================           
                                    if (async_create_timerfd(ctx->label, &single_session->hello3.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_timerfd.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
// Hitung rtt retry sebelum kirim data
//----------------------------------------------------------------------
                                    double try_count = (double)single_session->hello2.sent_try_count-(double)1;
                                    cow_calculate_retry(ctx, single_session, i, try_count);
                                    uint64_t_status_t rt = get_realtime_time_ns(ctx->label);
                                    if (rt.status != SUCCESS) {
                                        LOG_ERROR("%sFailed to get_realtime_time_ns.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
                                    single_session->hello2.ack_rcvd = true;
                                    single_session->hello2.ack_rcvd_time = rt.r_uint64_t;
                                    uint64_t interval_ull = single_session->hello2.ack_rcvd_time - single_session->hello2.sent_time;
                                    double rtt_value = (double)interval_ull;
                                    cow_calculate_rtt(ctx, single_session, i, rtt_value);
//----------------------------------------------------------------------
                                    if (send_hello3(ctx, single_session) != SUCCESS) {
                                        LOG_ERROR("%sFailed to send_hello3.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
                                    if (async_create_incoming_event(ctx->label, &ctx->async, &single_session->hello3.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_incoming_event.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }        
//----------------------------------------------------------------------
// Semua sudah bersih
//----------------------------------------------------------------------
                                    cleanup_hello(ctx->label, &ctx->async, &single_session->hello2);
//======================================================================  
                                    CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                    event_founded_in_session = true;
                                    break;
                                } else {
                                    LOG_ERROR("%sKoneksi ditolak Tidak pernah mengirim HELLO1 dan atau HELLO2 ke IP %s.", ctx->label, host_str);
                                    CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                    event_founded_in_session = true;
                                    break;
                                }
                            } else if (orcvdo.r_orilink_raw_protocol_t->type == ORILINK_HELLO3_ACK) {
                                if (
                                        sockaddr_equal((const struct sockaddr *)&single_session->identity.remote_addr, (const struct sockaddr *)&server_addr) &&
                                        single_session->hello1.sent &&
                                        single_session->hello2.sent &&
                                        single_session->hello3.sent
                                   )
                                {
                                    orilink_protocol_t_status_t deserialized_orcvdo = orilink_deserialize(ctx->label,
                                        single_session->identity.kem_sharedsecret, single_session->identity.remote_nonce, single_session->identity.remote_ctr,
                                        (const uint8_t*)orcvdo.r_orilink_raw_protocol_t->recv_buffer, orcvdo.r_orilink_raw_protocol_t->n
                                    );
                                    if (deserialized_orcvdo.status != SUCCESS) {
                                        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", ctx->label, deserialized_orcvdo.status);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                        event_founded_in_session = true;
                                        break;
                                    } else {
                                        LOG_DEBUG("%sorilink_deserialize BERHASIL.", ctx->label);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                    }  
                                    orilink_protocol_t* received_protocol = deserialized_orcvdo.r_orilink_protocol_t;
                                    orilink_hello3_ack_t *ohello3_ack = received_protocol->payload.orilink_hello3_ack;
                                    if (single_session->identity.client_id != ohello3_ack->client_id) {
                                        LOG_WARN("%HELLO3_ACK ditolak dari IP %s. client_id berbeda.", ctx->label, host_str);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
                                    memcpy(single_session->identity.kem_ciphertext + (KEM_CIPHERTEXT_BYTES / 2), ohello3_ack->ciphertext2, KEM_CIPHERTEXT_BYTES / 2);
//----------------------------------------------------------------------
// data heloo_end belum terenkripsi karena berisi nonce
// namun sudah ada pengecekan mac menggunakan sharedsecret
// simpan shared_secret di temporary
// jika mac sesuai segera pindah
// temp_kem_sharedsecret ke identity
//----------------------------------------------------------------------
                                    if (KEM_DECODE_SHAREDSECRET(single_session->temp_kem_sharedsecret, single_session->identity.kem_ciphertext, single_session->identity.kem_privatekey) != 0) {
                                        LOG_ERROR("%sFailed to KEM_DECODE_SHAREDSECRET.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }                                    
                                    memcpy(single_session->identity.remote_nonce, ohello3_ack->encrypted_server_id_port, AES_NONCE_BYTES);
                                    uint8_t encrypted_server_id_port[sizeof(uint64_t) + sizeof(uint16_t)];
                                    memcpy(encrypted_server_id_port, ohello3_ack->encrypted_server_id_port + AES_NONCE_BYTES, sizeof(uint64_t) + sizeof(uint16_t));
                                    uint8_t data_mac[AES_TAG_BYTES];
                                    memcpy(data_mac, ohello3_ack->encrypted_server_id_port + AES_NONCE_BYTES + (sizeof(uint64_t) + sizeof(uint16_t)), AES_TAG_BYTES);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
                                    uint8_t encrypted_server_id_port1[AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t)];
                                    memcpy(encrypted_server_id_port1, ohello3_ack->encrypted_server_id_port, AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t));
                                    uint8_t mac[AES_TAG_BYTES];
                                    poly1305_context mac_ctx;
                                    poly1305_init(&mac_ctx, single_session->temp_kem_sharedsecret);
                                    poly1305_update(&mac_ctx, encrypted_server_id_port1, AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t));
                                    poly1305_finish(&mac_ctx, mac);
                                    if (!poly1305_verify(mac, data_mac)) {
                                        LOG_ERROR("%sFailed to Mac Tidak Sesuai.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
// Pindahkan temp_kem_sharedsecret ke identity
// Menganggap data valid dengan integritas
//---------------------------------------------------------------------- 
                                    single_session->identity.remote_ctr = (uint32_t)0;
                                    memcpy(single_session->identity.kem_sharedsecret, single_session->temp_kem_sharedsecret, KEM_SHAREDSECRET_BYTES);
                                    memset(single_session->temp_kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
                                    uint8_t decrypted_server_id_port[sizeof(uint64_t) + sizeof(uint16_t)];
                                    aes256ctx aes_ctx;
                                    aes256_ctr_keyexp(&aes_ctx, single_session->identity.kem_sharedsecret);
//=========================================IV===========================    
                                    uint8_t keystream_buffer[sizeof(uint64_t) + sizeof(uint16_t)];
                                    uint8_t iv[AES_IV_BYTES];
                                    memcpy(iv, single_session->identity.remote_nonce, AES_NONCE_BYTES);
                                    uint32_t remote_ctr_be = htobe32(single_session->identity.remote_ctr);
                                    memcpy(iv + AES_NONCE_BYTES, &remote_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
                                    aes256_ctr(keystream_buffer, sizeof(uint64_t) + sizeof(uint16_t), iv, &aes_ctx);
                                    for (size_t i = 0; i < sizeof(uint64_t) + sizeof(uint16_t); i++) {
                                        decrypted_server_id_port[i] = encrypted_server_id_port[i] ^ keystream_buffer[i];
                                    }
                                    aes256_ctx_release(&aes_ctx);
                                    increment_ctr(&single_session->identity.remote_ctr, single_session->identity.remote_nonce);
//---------------------------------------------------------------------- 
// Mengisi identity
//---------------------------------------------------------------------- 
                                    uint64_t server_id_be;
                                    memcpy(&server_id_be, decrypted_server_id_port, sizeof(uint64_t));
                                    single_session->identity.server_id = be64toh(server_id_be);
                                    uint16_t port_be;
                                    memcpy(&port_be, decrypted_server_id_port + sizeof(uint64_t), sizeof(uint16_t));
                                    single_session->identity.port = be16toh(port_be);
//======================================================================
// Send HELLO_END
//======================================================================   
                                    if (async_create_timerfd(ctx->label, &single_session->hello_end.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_timerfd.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
// Hitung rtt retry sebelum kirim data
//----------------------------------------------------------------------
                                    double try_count = (double)single_session->hello3.sent_try_count-(double)1;
                                    cow_calculate_retry(ctx, single_session, i, try_count);
                                    uint64_t_status_t rt = get_realtime_time_ns(ctx->label);
                                    if (rt.status != SUCCESS) {
                                        LOG_ERROR("%sFailed to get_realtime_time_ns.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
                                    single_session->hello3.ack_rcvd = true;
                                    single_session->hello3.ack_rcvd_time = rt.r_uint64_t;
                                    uint64_t interval_ull = single_session->hello3.ack_rcvd_time - single_session->hello3.sent_time;
                                    double rtt_value = (double)interval_ull;
                                    cow_calculate_rtt(ctx, single_session, i, rtt_value);
//----------------------------------------------------------------------
                                    if (send_hello_end(ctx, single_session) != SUCCESS) {
                                        LOG_ERROR("%sFailed to send_hello_end.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
                                    if (async_create_incoming_event(ctx->label, &ctx->async, &single_session->hello_end.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_incoming_event.", ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }    
//----------------------------------------------------------------------
// Semua sudah bersih
//----------------------------------------------------------------------
                                    cleanup_hello(ctx->label, &ctx->async, &single_session->hello3);
//======================================================================  
                                    CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                    event_founded_in_session = true;
                                    break;
                                } else {
                                    LOG_ERROR("%sKoneksi ditolak Tidak pernah mengirim HELLO1 dan atau HELLO2 dan atau HELLO3 ke IP %s.", ctx->label, host_str);
                                    CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                    event_founded_in_session = true;
                                    break;
                                }
                            } else {
                                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                event_founded_in_session = true;
                                break;
                            }
                        } else if (current_fd == single_session->hello1.timer_fd) {
                            uint64_t u;
                            read(single_session->hello1.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                            if (server_disconnected(ctx, i, single_session, single_session->hello1.sent_try_count)) {
                                event_founded_in_session = true;
                                break;
                            }
                            LOG_DEBUG("%s single_session %d: interval = %lf.", ctx->label, i, single_session->hello1.interval_timer_fd);
                            double try_count = (double)single_session->hello1.sent_try_count;
                            cow_calculate_retry(ctx, single_session, i, try_count);
                            single_session->hello1.interval_timer_fd = pow((double)2, (double)single_session->identity.retry.value_prediction);
                            send_hello1(ctx, single_session);
                            event_founded_in_session = true;
                            break;
                        } else if (current_fd == single_session->hello2.timer_fd) {
                            uint64_t u;
                            read(single_session->hello2.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                            if (server_disconnected(ctx, i, single_session, single_session->hello2.sent_try_count)) {
                                event_founded_in_session = true;
                                break;
                            }
                            LOG_DEBUG("%s single_session %d: interval = %lf.", ctx->label, i, single_session->hello2.interval_timer_fd);
                            double try_count = (double)single_session->hello2.sent_try_count;
                            cow_calculate_retry(ctx, single_session, i, try_count);
                            single_session->hello2.interval_timer_fd = pow((double)2, (double)single_session->identity.retry.value_prediction);
                            send_hello2(ctx, single_session);
                            event_founded_in_session = true;
                            break;
                        } else if (current_fd == single_session->hello3.timer_fd) {
                            uint64_t u;
                            read(single_session->hello3.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                            if (server_disconnected(ctx, i, single_session, single_session->hello3.sent_try_count)) {
                                event_founded_in_session = true;
                                break;
                            }
                            LOG_DEBUG("%s single_session %d: interval = %lf.", ctx->label, i, single_session->hello3.interval_timer_fd);
                            double try_count = (double)single_session->hello3.sent_try_count;
                            cow_calculate_retry(ctx, single_session, i, try_count);
                            single_session->hello3.interval_timer_fd = pow((double)2, (double)single_session->identity.retry.value_prediction);
                            send_hello3(ctx, single_session);
                            event_founded_in_session = true;
                            break;
                        } else if (current_fd == single_session->hello_end.timer_fd) {
                            uint64_t u;
                            read(single_session->hello_end.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                            if (server_disconnected(ctx, i, single_session, single_session->hello_end.sent_try_count)) {
                                event_founded_in_session = true;
                                break;
                            }
                            LOG_DEBUG("%s single_session %d: interval = %lf.", ctx->label, i, single_session->hello_end.interval_timer_fd);
                            double try_count = (double)single_session->hello_end.sent_try_count;
                            cow_calculate_retry(ctx, single_session, i, try_count);
                            single_session->hello_end.interval_timer_fd = pow((double)2, (double)single_session->identity.retry.value_prediction);
                            send_hello_end(ctx, single_session);
                            event_founded_in_session = true;
                            break;
                        }
                    }
                }
                if (event_founded_in_session) continue;
//======================================================================
// Event yang belum ditangkap
//======================================================================                 
                LOG_ERROR("%sUnknown FD event %d.", ctx->label, current_fd);
//======================================================================
            }
        }
    }

exit:    
    cleanup_cow_worker(ctx, sessions);
}
