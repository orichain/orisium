#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <endian.h>
#include <signal.h>

#include "log.h"
#include "orilink/protocol.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc.h"
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

bool server_disconnected(worker_context_t *worker_ctx, int session_index, cow_c_session_t *single_session, uint8_t try_count) {
    if (try_count > (uint8_t)MAX_RETRY) {
        LOG_DEBUG("%s single_session %d: disconnect => try count %d.", worker_ctx->label, session_index, try_count);
        cow_master_connection(worker_ctx, &single_session->identity.remote_addr, CANNOTCONNECT);
        cleanup_cow_session(worker_ctx->label, &worker_ctx->async, single_session);
        return true;
    }
    return false;
}

status_t send_hello1(worker_context_t *worker_ctx, cow_c_session_t *single_session) {
    uint64_t_status_t rt = get_realtime_time_ns(worker_ctx->label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    single_session->hello1.sent = true;
    single_session->hello1.sent_try_count++;
    single_session->hello1.sent_time = rt.r_uint64_t;
    if (hello1(worker_ctx->label, single_session) != SUCCESS) {
        printf("Error hello1\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(worker_ctx->label, &single_session->hello1.timer_fd,
        (time_t)single_session->hello1.interval_timer_fd,
        (long)((single_session->hello1.interval_timer_fd - (time_t)single_session->hello1.interval_timer_fd) * 1e9),
        (time_t)single_session->hello1.interval_timer_fd,
        (long)((single_session->hello1.interval_timer_fd - (time_t)single_session->hello1.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

status_t send_hello2(worker_context_t *worker_ctx, cow_c_session_t *single_session) {
    uint64_t_status_t rt = get_realtime_time_ns(worker_ctx->label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    single_session->hello2.sent = true;
    single_session->hello2.sent_try_count++;
    single_session->hello2.sent_time = rt.r_uint64_t;
    if (hello2(worker_ctx->label, single_session) != SUCCESS) {
        printf("Error hello2\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(worker_ctx->label, &single_session->hello2.timer_fd,
        (time_t)single_session->hello2.interval_timer_fd,
        (long)((single_session->hello2.interval_timer_fd - (time_t)single_session->hello2.interval_timer_fd) * 1e9),
        (time_t)single_session->hello2.interval_timer_fd,
        (long)((single_session->hello2.interval_timer_fd - (time_t)single_session->hello2.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

status_t send_hello3(worker_context_t *worker_ctx, cow_c_session_t *single_session) {
    uint64_t_status_t rt = get_realtime_time_ns(worker_ctx->label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    single_session->hello3.sent = true;
    single_session->hello3.sent_try_count++;
    single_session->hello3.sent_time = rt.r_uint64_t;
    if (hello3(worker_ctx->label, single_session) != SUCCESS) {
        printf("Error hello3\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(worker_ctx->label, &single_session->hello3.timer_fd,
        (time_t)single_session->hello3.interval_timer_fd,
        (long)((single_session->hello3.interval_timer_fd - (time_t)single_session->hello3.interval_timer_fd) * 1e9),
        (time_t)single_session->hello3.interval_timer_fd,
        (long)((single_session->hello3.interval_timer_fd - (time_t)single_session->hello3.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

status_t send_hello_end(worker_context_t *worker_ctx, cow_c_session_t *single_session) {
    uint64_t_status_t rt = get_realtime_time_ns(worker_ctx->label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    single_session->hello_end.sent = true;
    single_session->hello_end.sent_try_count++;
    single_session->hello_end.sent_time = rt.r_uint64_t;
    if (hello_end(worker_ctx->label, single_session) != SUCCESS) {
        printf("Error hello_end\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(worker_ctx->label, &single_session->hello_end.timer_fd,
        (time_t)single_session->hello_end.interval_timer_fd,
        (long)((single_session->hello_end.interval_timer_fd - (time_t)single_session->hello_end.interval_timer_fd) * 1e9),
        (time_t)single_session->hello_end.interval_timer_fd,
        (long)((single_session->hello_end.interval_timer_fd - (time_t)single_session->hello_end.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

void cow_calculate_retry(worker_context_t *worker_ctx, cow_c_session_t *single_session, int session_index, double try_count) {
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => RETRY %d", session_index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => RETRY %d", session_index);
    calculate_oricle_double(worker_ctx->label, desc, &single_session->identity.retry, try_count, ((double)MAX_RETRY * (double)2));
    free(desc);
}

void cow_calculate_rtt(worker_context_t *worker_ctx, cow_c_session_t *single_session, int session_index, double rtt_value) {
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => RTT %d", session_index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => RTT %d", session_index);
    calculate_oricle_double(worker_ctx->label, desc, &single_session->identity.rtt, rtt_value, ((double)MAX_RTT_SEC * (double)1e9 * (double)2));
    free(desc);
}

void cleanup_cow_worker(worker_context_t *worker_ctx, cow_c_session_t *sessions) {
    for (int i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
        cow_c_session_t *single_session;
        single_session = &sessions[i];
        if (single_session->in_use) {
            cleanup_cow_session(worker_ctx->label, &worker_ctx->async, single_session);
        }
    }
	cleanup_worker(worker_ctx);
}

status_t setup_cow_worker(worker_context_t *worker_ctx, cow_c_session_t *sessions, worker_type_t *wot, uint8_t *index, int *master_uds_fd) {
    if (setup_worker(worker_ctx, "COW", wot, index, master_uds_fd) != SUCCESS) return FAILURE;
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
    worker_context_t *worker_ctx = &x_ctx;
    cow_c_session_t sessions[MAX_CONNECTION_PER_COW_WORKER];
    if (setup_cow_worker(worker_ctx, sessions, wot, index, master_uds_fd) != SUCCESS) goto exit;
    signal(SIGTERM, cow_sigterm_handler);
    while (!worker_ctx->shutdown_requested && !cow_sigterm_requested) {
        int_status_t snfds = async_wait(worker_ctx->label, &worker_ctx->async);
		if (snfds.status != SUCCESS) {
            if (snfds.status == FAILURE_EBADF) {
                worker_ctx->shutdown_requested = 1;
            }
            continue;
        }
        for (int n = 0; n < snfds.r_int; ++n) {
            if (worker_ctx->shutdown_requested || cow_sigterm_requested) {
				break;
			}
			int_status_t fd_status = async_getfd(worker_ctx->label, &worker_ctx->async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents(worker_ctx->label, &worker_ctx->async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;
            if (current_fd == worker_ctx->heartbeat_timer_fd) {
				uint64_t u;
				read(worker_ctx->heartbeat_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
//----------------------------------------------------------------------
// Heartbeat dengan jitter
//----------------------------------------------------------------------
				double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * HEARTBEAT_JITTER_PERCENTAGE * 2) - HEARTBEAT_JITTER_PERCENTAGE;
                double new_heartbeat_interval_double = WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * (1.0 + jitter_amount);
                if (new_heartbeat_interval_double < 0.1) {
                    new_heartbeat_interval_double = 0.1;
                }
                if (async_set_timerfd_time(worker_ctx->label, &worker_ctx->heartbeat_timer_fd,
					(time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9),
                    (time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9)) != SUCCESS)
                {
                    worker_ctx->shutdown_requested = 1;
					LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", worker_ctx->label);
					continue;
                }
                if (worker_master_heartbeat(worker_ctx, new_heartbeat_interval_double) != SUCCESS) {
                    continue;
                } else {
                    continue;
                }
//----------------------------------------------------------------------
			} else if (current_fd == *worker_ctx->master_uds_fd) {
                if (async_event_is_EPOLLHUP(current_events) ||
                    async_event_is_EPOLLERR(current_events) ||
                    async_event_is_EPOLLRDHUP(current_events))
                {
                    handle_workers_ipc_closed_event(worker_ctx);
                    continue;
                } else {
                    handle_workers_ipc_event(worker_ctx, initial_delay_ms);
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
                                worker_ctx->label,
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
                                LOG_ERROR("%sgetnameinfo failed. %s", worker_ctx->label, strerror(errno));
                                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                event_founded_in_session = true;
                                break;
                            }
                            size_t host_str_len = strlen(host_str);
                            if (host_str_len >= INET6_ADDRSTRLEN) {
                                LOG_ERROR("%sKoneksi ditolak dari IP %s. IP terlalu panjang.", worker_ctx->label, host_str);
                                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                event_founded_in_session = true;
                                break;
                            }
                            char *endptr;
                            long port_num = strtol(port_str, &endptr, 10);
                            if (*endptr != '\0' || port_num <= 0 || port_num > 65535) {
                                LOG_ERROR("%sKoneksi ditolak dari IP %s. PORT di luar rentang (1-65535).", worker_ctx->label, host_str);
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
                                    orilink_protocol_t_status_t deserialized_orcvdo = orilink_deserialize(worker_ctx->label,
                                        single_session->identity.kem_sharedsecret, single_session->identity.remote_nonce, single_session->identity.remote_ctr,
                                        (const uint8_t*)orcvdo.r_orilink_raw_protocol_t->recv_buffer, orcvdo.r_orilink_raw_protocol_t->n
                                    );
                                    if (deserialized_orcvdo.status != SUCCESS) {
                                        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_orcvdo.status);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                        event_founded_in_session = true;
                                        break;
                                    } else {
                                        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                    }  
                                    orilink_protocol_t* received_protocol = deserialized_orcvdo.r_orilink_protocol_t;
                                    orilink_hello1_ack_t *ohello1_ack = received_protocol->payload.orilink_hello1_ack;
                                    if (single_session->identity.client_id != ohello1_ack->client_id) {
                                        LOG_WARN("%sHELLO1_ACK ditolak dari IP %s. client_id berbeda.", worker_ctx->label, host_str);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//======================================================================
// Send HELLO2                   
//======================================================================           
                                    if (async_create_timerfd(worker_ctx->label, &single_session->hello2.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_timerfd.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
// Hitung rtt retry sebelum kirim data
//----------------------------------------------------------------------
                                    double try_count = (double)single_session->hello1.sent_try_count-(double)1;
                                    cow_calculate_retry(worker_ctx, single_session, i, try_count);
                                    uint64_t_status_t rt = get_realtime_time_ns(worker_ctx->label);
                                    if (rt.status != SUCCESS) {
                                        LOG_ERROR("%sFailed to get_realtime_time_ns.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
                                    single_session->hello1.ack_rcvd = true;
                                    single_session->hello1.ack_rcvd_time = rt.r_uint64_t;
                                    uint64_t interval_ull = single_session->hello1.ack_rcvd_time - single_session->hello1.sent_time;
                                    double rtt_value = (double)interval_ull;
                                    cow_calculate_rtt(worker_ctx, single_session, i, rtt_value);
//----------------------------------------------------------------------
                                    if (send_hello2(worker_ctx, single_session) != SUCCESS) {
                                        LOG_ERROR("%sFailed to send_hello2.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
                                    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &single_session->hello2.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_incoming_event.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }        
//----------------------------------------------------------------------
// Semua sudah bersih
//----------------------------------------------------------------------
                                    cleanup_hello(worker_ctx->label, &worker_ctx->async, &single_session->hello1);
//======================================================================  
                                    CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                    event_founded_in_session = true;
                                    break;
                                } else {
                                    LOG_ERROR("%sKoneksi ditolak Tidak pernah mengirim HELLO1 ke IP %s.", worker_ctx->label, host_str);
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
                                    orilink_protocol_t_status_t deserialized_orcvdo = orilink_deserialize(worker_ctx->label,
                                        single_session->identity.kem_sharedsecret, single_session->identity.remote_nonce, single_session->identity.remote_ctr,
                                        (const uint8_t*)orcvdo.r_orilink_raw_protocol_t->recv_buffer, orcvdo.r_orilink_raw_protocol_t->n
                                    );
                                    if (deserialized_orcvdo.status != SUCCESS) {
                                        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_orcvdo.status);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                        event_founded_in_session = true;
                                        break;
                                    } else {
                                        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                    }  
                                    orilink_protocol_t* received_protocol = deserialized_orcvdo.r_orilink_protocol_t;
                                    orilink_hello2_ack_t *ohello2_ack = received_protocol->payload.orilink_hello2_ack;
                                    if (single_session->identity.client_id != ohello2_ack->client_id) {
                                        LOG_WARN("%HELLO2_ACK ditolak dari IP %s. client_id berbeda.", worker_ctx->label, host_str);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
                                    memcpy(single_session->identity.kem_ciphertext, ohello2_ack->ciphertext1, KEM_CIPHERTEXT_BYTES / 2);
//======================================================================
// Send HELLO3
//======================================================================           
                                    if (async_create_timerfd(worker_ctx->label, &single_session->hello3.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_timerfd.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
// Hitung rtt retry sebelum kirim data
//----------------------------------------------------------------------
                                    double try_count = (double)single_session->hello2.sent_try_count-(double)1;
                                    cow_calculate_retry(worker_ctx, single_session, i, try_count);
                                    uint64_t_status_t rt = get_realtime_time_ns(worker_ctx->label);
                                    if (rt.status != SUCCESS) {
                                        LOG_ERROR("%sFailed to get_realtime_time_ns.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
                                    single_session->hello2.ack_rcvd = true;
                                    single_session->hello2.ack_rcvd_time = rt.r_uint64_t;
                                    uint64_t interval_ull = single_session->hello2.ack_rcvd_time - single_session->hello2.sent_time;
                                    double rtt_value = (double)interval_ull;
                                    cow_calculate_rtt(worker_ctx, single_session, i, rtt_value);
//----------------------------------------------------------------------
                                    if (send_hello3(worker_ctx, single_session) != SUCCESS) {
                                        LOG_ERROR("%sFailed to send_hello3.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
                                    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &single_session->hello3.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_incoming_event.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }        
//----------------------------------------------------------------------
// Semua sudah bersih
//----------------------------------------------------------------------
                                    cleanup_hello(worker_ctx->label, &worker_ctx->async, &single_session->hello2);
//======================================================================  
                                    CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                    event_founded_in_session = true;
                                    break;
                                } else {
                                    LOG_ERROR("%sKoneksi ditolak Tidak pernah mengirim HELLO1 dan atau HELLO2 ke IP %s.", worker_ctx->label, host_str);
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
                                    orilink_protocol_t_status_t deserialized_orcvdo = orilink_deserialize(worker_ctx->label,
                                        single_session->identity.kem_sharedsecret, single_session->identity.remote_nonce, single_session->identity.remote_ctr,
                                        (const uint8_t*)orcvdo.r_orilink_raw_protocol_t->recv_buffer, orcvdo.r_orilink_raw_protocol_t->n
                                    );
                                    if (deserialized_orcvdo.status != SUCCESS) {
                                        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_orcvdo.status);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                        event_founded_in_session = true;
                                        break;
                                    } else {
                                        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
                                        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                                    }  
                                    orilink_protocol_t* received_protocol = deserialized_orcvdo.r_orilink_protocol_t;
                                    orilink_hello3_ack_t *ohello3_ack = received_protocol->payload.orilink_hello3_ack;
                                    if (single_session->identity.client_id != ohello3_ack->client_id) {
                                        LOG_WARN("%HELLO3_ACK ditolak dari IP %s. client_id berbeda.", worker_ctx->label, host_str);
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
                                        LOG_ERROR("%sFailed to KEM_DECODE_SHAREDSECRET.", worker_ctx->label);
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
                                        LOG_ERROR("%sFailed to Mac Tidak Sesuai.", worker_ctx->label);
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
                                    if (async_create_timerfd(worker_ctx->label, &single_session->hello_end.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_timerfd.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
// Hitung rtt retry sebelum kirim data
//----------------------------------------------------------------------
                                    double try_count = (double)single_session->hello3.sent_try_count-(double)1;
                                    cow_calculate_retry(worker_ctx, single_session, i, try_count);
                                    uint64_t_status_t rt = get_realtime_time_ns(worker_ctx->label);
                                    if (rt.status != SUCCESS) {
                                        LOG_ERROR("%sFailed to get_realtime_time_ns.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
                                    single_session->hello3.ack_rcvd = true;
                                    single_session->hello3.ack_rcvd_time = rt.r_uint64_t;
                                    uint64_t interval_ull = single_session->hello3.ack_rcvd_time - single_session->hello3.sent_time;
                                    double rtt_value = (double)interval_ull;
                                    cow_calculate_rtt(worker_ctx, single_session, i, rtt_value);
//----------------------------------------------------------------------
                                    if (send_hello_end(worker_ctx, single_session) != SUCCESS) {
                                        LOG_ERROR("%sFailed to send_hello_end.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
//----------------------------------------------------------------------
                                    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &single_session->hello_end.timer_fd) != SUCCESS) {
                                        LOG_ERROR("%sFailed to async_create_incoming_event.", worker_ctx->label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }    
//----------------------------------------------------------------------
// Semua sudah bersih
//----------------------------------------------------------------------
                                    cleanup_hello(worker_ctx->label, &worker_ctx->async, &single_session->hello3);
//======================================================================  
                                    CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                    event_founded_in_session = true;
                                    break;
                                } else {
                                    LOG_ERROR("%sKoneksi ditolak Tidak pernah mengirim HELLO1 dan atau HELLO2 dan atau HELLO3 ke IP %s.", worker_ctx->label, host_str);
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
                            if (server_disconnected(worker_ctx, i, single_session, single_session->hello1.sent_try_count)) {
                                event_founded_in_session = true;
                                break;
                            }
                            LOG_DEBUG("%s single_session %d: interval = %lf.", worker_ctx->label, i, single_session->hello1.interval_timer_fd);
                            double try_count = (double)single_session->hello1.sent_try_count;
                            cow_calculate_retry(worker_ctx, single_session, i, try_count);
                            single_session->hello1.interval_timer_fd = pow((double)2, (double)single_session->identity.retry.value_prediction);
                            send_hello1(worker_ctx, single_session);
                            event_founded_in_session = true;
                            break;
                        } else if (current_fd == single_session->hello2.timer_fd) {
                            uint64_t u;
                            read(single_session->hello2.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                            if (server_disconnected(worker_ctx, i, single_session, single_session->hello2.sent_try_count)) {
                                event_founded_in_session = true;
                                break;
                            }
                            LOG_DEBUG("%s single_session %d: interval = %lf.", worker_ctx->label, i, single_session->hello2.interval_timer_fd);
                            double try_count = (double)single_session->hello2.sent_try_count;
                            cow_calculate_retry(worker_ctx, single_session, i, try_count);
                            single_session->hello2.interval_timer_fd = pow((double)2, (double)single_session->identity.retry.value_prediction);
                            send_hello2(worker_ctx, single_session);
                            event_founded_in_session = true;
                            break;
                        } else if (current_fd == single_session->hello3.timer_fd) {
                            uint64_t u;
                            read(single_session->hello3.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                            if (server_disconnected(worker_ctx, i, single_session, single_session->hello3.sent_try_count)) {
                                event_founded_in_session = true;
                                break;
                            }
                            LOG_DEBUG("%s single_session %d: interval = %lf.", worker_ctx->label, i, single_session->hello3.interval_timer_fd);
                            double try_count = (double)single_session->hello3.sent_try_count;
                            cow_calculate_retry(worker_ctx, single_session, i, try_count);
                            single_session->hello3.interval_timer_fd = pow((double)2, (double)single_session->identity.retry.value_prediction);
                            send_hello3(worker_ctx, single_session);
                            event_founded_in_session = true;
                            break;
                        } else if (current_fd == single_session->hello_end.timer_fd) {
                            uint64_t u;
                            read(single_session->hello_end.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                            if (server_disconnected(worker_ctx, i, single_session, single_session->hello_end.sent_try_count)) {
                                event_founded_in_session = true;
                                break;
                            }
                            LOG_DEBUG("%s single_session %d: interval = %lf.", worker_ctx->label, i, single_session->hello_end.interval_timer_fd);
                            double try_count = (double)single_session->hello_end.sent_try_count;
                            cow_calculate_retry(worker_ctx, single_session, i, try_count);
                            single_session->hello_end.interval_timer_fd = pow((double)2, (double)single_session->identity.retry.value_prediction);
                            send_hello_end(worker_ctx, single_session);
                            event_founded_in_session = true;
                            break;
                        }
                    }
                }
                if (event_founded_in_session) continue;
//======================================================================
// Event yang belum ditangkap
//======================================================================                 
                LOG_ERROR("%sUnknown FD event %d.", worker_ctx->label, current_fd);
//======================================================================
            }
        }
    }

exit:    
    cleanup_cow_worker(worker_ctx, sessions);
}
