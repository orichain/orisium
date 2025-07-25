#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <bits/types/sig_atomic_t.h>
#include <math.h>
#include <netinet/in.h>

#include "log.h"
#include "ipc/protocol.h"
#include "orilink/protocol.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "sessions/workers_session.h"
#include "workers/master_ipc_cmds.h"
#include "workers/client_orilink_cmds.h"
#include "kalman.h"
#include "pqc.h"
#include "stdbool.h"

void setup_session(cow_c_session_t *session) {
    session->in_use = false;
    memset(&session->old_server_addr, 0, sizeof(struct sockaddr_in6));
    memset(&session->server_addr, 0, sizeof(struct sockaddr_in6));
    memset(session->identity.kem_privatekey, 0, KEM_PRIVATEKEY_BYTES);
    memset(session->identity.kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(session->identity.kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(session->identity.kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    session->identity.client_id = 0ULL;
    session->identity.server_id = 0ULL;
    session->identity.port = 0x0000;
    setup_oricle_double(&session->rtt, (double)0);
    setup_oricle_double(&session->retry, (double)0);
    CLOSE_FD(&session->sock_fd);
    setup_hello(&session->hello1);
    setup_hello(&session->hello2);
    setup_hello(&session->hello3);
    setup_hello(&session->hello_end);
}

void cleanup_session(const char *label, async_type_t *cow_async, cow_c_session_t *session) {
    session->in_use = false;
    memset(&session->old_server_addr, 0, sizeof(struct sockaddr_in6));
    memset(&session->server_addr, 0, sizeof(struct sockaddr_in6));
    memset(session->identity.kem_privatekey, 0, KEM_PRIVATEKEY_BYTES);
    memset(session->identity.kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(session->identity.kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(session->identity.kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    session->identity.client_id = 0ULL;
    session->identity.server_id = 0ULL;
    session->identity.port = 0x0000;
    cleanup_oricle_double(&session->rtt);
    cleanup_oricle_double(&session->retry);
    async_delete_event(label, cow_async, &session->sock_fd);
    CLOSE_FD(&session->sock_fd);
    cleanup_hello(label, cow_async, &session->hello1);
    cleanup_hello(label, cow_async, &session->hello2);
    cleanup_hello(label, cow_async, &session->hello3);
    cleanup_hello(label, cow_async, &session->hello_end);
}

bool must_be_disconnected(const char *label, worker_type_t wot, int worker_idx, int session_index, async_type_t *cow_async, cow_c_session_t *session, int *master_uds_fd) {
    if (session->hello1.sent_try_count > MAX_RETRY) {
        LOG_DEVEL_DEBUG("%s session %d: disconnect => try count %d.", label, session_index, session->hello1.sent_try_count);
        cow_master_connection(label, wot, worker_idx, &session->old_server_addr, CANNOTCONNECT, master_uds_fd);
        cleanup_session(label, cow_async, session);
        return true;
    }
    return false;
}

status_t send_hello1(const char *label, cow_c_session_t *session) {
    uint64_t_status_t rt = get_realtime_time_ns(label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    session->hello1.sent = true;
    session->hello1.sent_try_count++;
    session->hello1.sent_time = rt.r_uint64_t;
    if (hello1(label, session) != SUCCESS) {
        printf("Error hello1\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(label, &session->hello1.timer_fd,
        (time_t)session->hello1.interval_timer_fd,
        (long)((session->hello1.interval_timer_fd - (time_t)session->hello1.interval_timer_fd) * 1e9),
        (time_t)session->hello1.interval_timer_fd,
        (long)((session->hello1.interval_timer_fd - (time_t)session->hello1.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

status_t send_hello2(const char *label, cow_c_session_t *session) {
    uint64_t_status_t rt = get_realtime_time_ns(label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    session->hello2.sent = true;
    session->hello2.sent_try_count++;
    session->hello2.sent_time = rt.r_uint64_t;
    if (hello2(label, session) != SUCCESS) {
        printf("Error hello2\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(label, &session->hello2.timer_fd,
        (time_t)session->hello2.interval_timer_fd,
        (long)((session->hello2.interval_timer_fd - (time_t)session->hello2.interval_timer_fd) * 1e9),
        (time_t)session->hello2.interval_timer_fd,
        (long)((session->hello2.interval_timer_fd - (time_t)session->hello2.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

void calculate_retry(const char *label, cow_c_session_t *session, int session_index, double try_count) {
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => RETRY %d", session_index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => RETRY %d", session_index);
    calculate_oricle_double(label, desc, &session->retry, try_count, ((double)MAX_RETRY * (double)2));
    free(desc);
}

void calculate_rtt(const char *label, cow_c_session_t *session, int session_index, double rtt_value) {
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => RTT %d", session_index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => RTT %d", session_index);
    calculate_oricle_double(label, desc, &session->rtt, rtt_value, ((double)MAX_RTT_SEC * (double)1e9 * (double)2));
    free(desc);
}

void run_cow_worker(worker_type_t wot, int worker_idx, long initial_delay_ms, int master_uds_fd) {
    volatile sig_atomic_t cow_shutdown_requested = 0;
    cow_c_session_t cow_c_session[MAX_CONNECTION_PER_COW_WORKER];
    async_type_t cow_async;
    cow_async.async_fd = -1;
    int cow_timer_fd = -1;
    srandom(time(NULL) ^ getpid());
    
//======================================================================
// Setup Logic
//======================================================================
	char *label;
	int needed = snprintf(NULL, 0, "[COW %d]: ", worker_idx);
	label = malloc(needed + 1);
	snprintf(label, needed + 1, "[COW %d]: ", worker_idx);  
//======================================================================	
	if (async_create(label, &cow_async) != SUCCESS) goto exit;
	if (async_create_incoming_event_with_disconnect(label, &cow_async, &master_uds_fd) != SUCCESS) goto exit;
//======================================================================
	if (initial_delay_ms > 0) {
        LOG_DEVEL_DEBUG("%sApplying initial delay of %ld ms...", label, initial_delay_ms);
        sleep_ms(initial_delay_ms);
    }
//======================================================================
	if (async_create_timerfd(label, &cow_timer_fd) != SUCCESS) {
		 goto exit;
	}
	if (async_set_timerfd_time(label, &cow_timer_fd,
		WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0,
        WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0) != SUCCESS)
    {
		 goto exit;
	}
	if (async_create_incoming_event(label, &cow_async, &cow_timer_fd) != SUCCESS) goto exit;
//======================================================================
    for (int i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
        cow_c_session_t *session;
        session = &cow_c_session[i];
        setup_session(session);
    }    
    while (!cow_shutdown_requested) {
        int_status_t snfds = async_wait(label, &cow_async);
		if (snfds.status != SUCCESS) continue;
        for (int n = 0; n < snfds.r_int; ++n) {
            if (cow_shutdown_requested) {
				break;
			}
			int_status_t fd_status = async_getfd(label, &cow_async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents(label, &cow_async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;
            if (current_fd == cow_timer_fd) {
				uint64_t u;
				read(cow_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
//======================================================				
				double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * HEARTBEAT_JITTER_PERCENTAGE * 2) - HEARTBEAT_JITTER_PERCENTAGE;
                double new_heartbeat_interval_double = WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * (1.0 + jitter_amount);
                if (new_heartbeat_interval_double < 0.1) {
                    new_heartbeat_interval_double = 0.1;
                }
                if (async_set_timerfd_time(label, &cow_timer_fd,
					(time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9),
                    (time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9)) != SUCCESS)
                {
                    cow_shutdown_requested = 1;
					LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", label);
					continue;
                }
                if (worker_master_heartbeat(label, wot, worker_idx, new_heartbeat_interval_double, &master_uds_fd) != SUCCESS) continue;
			} else if (current_fd == master_uds_fd) {
				ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(label, &master_uds_fd);
				if (deserialized_result.status != SUCCESS) {
					if (async_event_is_EPOLLHUP(current_events) ||
						async_event_is_EPOLLERR(current_events) ||
						async_event_is_EPOLLRDHUP(current_events))
					{
						cow_shutdown_requested = 1;
						LOG_INFO("%sMaster disconnected. Initiating graceful shutdown...", label);
						continue;
					}
					LOG_ERROR("%sError receiving or deserializing IPC message from Master: %d", label, deserialized_result.status);
					continue;
				}
				ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;
				LOG_DEVEL_DEBUG("%sReceived message type: 0x%02x", label, received_protocol->type);		
                if (received_protocol->type == IPC_MASTER_WORKER_SHUTDOWN) {
					LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", label);
					cow_shutdown_requested = 1;
					CLOSE_IPC_PROTOCOL(&received_protocol);
					continue;
				} else if (received_protocol->type == IPC_MASTER_COW_CONNECT) {
					ipc_master_cow_connect_t *cc = received_protocol->payload.ipc_master_cow_connect;
                    int slot_found = -1;
                    for (int i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
                        if (!cow_c_session[i].in_use) {
                            cow_c_session[i].in_use = true;
                            memcpy(&cow_c_session[i].old_server_addr, &cc->server_addr, sizeof(struct sockaddr_in6));
                            slot_found = i;
                            break;
                        }
                    }
                    if (slot_found == -1) {
                        LOG_INFO("%sNO SLOT. master_cow_session_t <> cow_c_session_t. Tidak singkron. Worker error. Initiating graceful shutdown...", label);
                        cow_shutdown_requested = 1;
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    cow_c_session_t *session;
                    session = &cow_c_session[slot_found];
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
                    int getname_res = getnameinfo((struct sockaddr *)&session->old_server_addr, sizeof(struct sockaddr_in6),
                                        host_str, NI_MAXHOST,
                                        port_str, NI_MAXSERV,
                                        NI_NUMERICHOST | NI_NUMERICSERV
                                      );
                    if (getname_res != 0) {
                        LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    int gai_err = getaddrinfo(host_str, port_str, &hints, &res);
                    if (gai_err != 0) {
                        LOG_ERROR("%sgetaddrinfo error for UDP %s:%s: %s", label, host_str, port_str, gai_strerror(gai_err));
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    for (rp = res; rp != NULL; rp = rp->ai_next) {
                        session->sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                        if (session->sock_fd == -1) {
                            LOG_ERROR("%sUDP Socket creation failed: %s", label, strerror(errno));
                            continue;
                        }
                        LOG_DEVEL_DEBUG("%sUDP Socket FD %d created.", label, session->sock_fd);
                        status_t r_snbkg = set_nonblocking(label, session->sock_fd);
                        if (r_snbkg != SUCCESS) {
                            LOG_ERROR("%sset_nonblocking failed.", label);
                            continue;
                        }
                        LOG_DEVEL_DEBUG("%sUDP Socket FD %d set to non-blocking.", label, session->sock_fd);
                        int conn_res = connect(session->sock_fd, rp->ai_addr, rp->ai_addrlen);
                        if (conn_res == 0) {
                            LOG_INFO("%sUDP socket 'connected' to %s:%s (FD %d).", label, host_str, port_str, session->sock_fd);
                            break;
                        } else {
                            LOG_ERROR("%sUDP 'connect' failed for %s:%s (FD %d): %s", label, host_str, port_str, session->sock_fd, strerror(errno));
                            CLOSE_FD(&session->sock_fd);
                            continue;
                        }
                    }
                    freeaddrinfo(res);
                    if (session->sock_fd == -1) {
                        LOG_ERROR("%sFailed to set up any UDP socket for %s:%s.", label, host_str, port_str);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    if (async_create_incoming_event(label, &cow_async, &session->sock_fd) != SUCCESS) {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//======================================================================
// Send HELLO                    
//======================================================================
                    uint64_t client_id;
                    generate_connection_id(label, &client_id);
                    session->identity.client_id = client_id;
                    if (KEM_GENERATE_KEYPAIR(session->identity.kem_publickey, session->identity.kem_privatekey) != 0) {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//======================================================================                    
                    if (async_create_timerfd(label, &session->hello1.timer_fd) != SUCCESS) {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//======================================================================
                    if (send_hello1(label, session) != SUCCESS) {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//======================================================================
                    if (async_create_incoming_event(label, &cow_async, &session->hello1.timer_fd) != SUCCESS) {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }        
//======================================================================    
                    CLOSE_IPC_PROTOCOL(&received_protocol);
					continue;
				}
				CLOSE_IPC_PROTOCOL(&received_protocol);
            } else {
                bool event_founded_in_session = false;
                for (int i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
                    cow_c_session_t *session;
                    session = &cow_c_session[i];
                    if (session->in_use) {
                        if (current_fd == session->sock_fd) {
                            struct sockaddr_in6 server_addr;
                            char host_str[NI_MAXHOST];
                            char port_str[NI_MAXSERV];
                            orilink_protocol_t_status_t rcvd = receive_and_deserialize_orilink_packet(
                                label,
                                &session->sock_fd,
                                (struct sockaddr *)&server_addr
                            );
                            if (rcvd.status != SUCCESS) {
                                event_founded_in_session = true;
                                break;
                            }
                            orilink_protocol_t* received_protocol = rcvd.r_orilink_protocol_t;
                            int getname_res = getnameinfo((struct sockaddr *)&server_addr, sizeof(struct sockaddr_in6),
                                                host_str, NI_MAXHOST,
                                                port_str, NI_MAXSERV,
                                                NI_NUMERICHOST | NI_NUMERICSERV
                                              );
                            if (getname_res != 0) {
                                LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
                                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                event_founded_in_session = true;
                                break;
                            }
                            size_t host_str_len = strlen(host_str);
                            if (host_str_len >= INET6_ADDRSTRLEN) {
                                LOG_ERROR("%sKoneksi ditolak dari IP %s. IP terlalu panjang.", label, host_str);
                                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                event_founded_in_session = true;
                                break;
                            }
                            char *endptr;
                            long port_num = strtol(port_str, &endptr, 10);
                            if (*endptr != '\0' || port_num <= 0 || port_num > 65535) {
                                LOG_ERROR("%sKoneksi ditolak dari IP %s. PORT di luar rentang (1-65535).", label, host_str);
                                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                event_founded_in_session = true;
                                break;
                            }
                            if (received_protocol->type == ORILINK_HELLO1_ACK) {
                                orilink_hello1_ack_t *ohello1_ack = received_protocol->payload.orilink_hello1_ack;
                                if (
                                        sockaddr_equal((const struct sockaddr *)&session->old_server_addr, (const struct sockaddr *)&server_addr) &&
                                        (session->identity.client_id == ohello1_ack->client_id) &&
                                        session->hello1.sent
                                   )
                                {
                                    double try_count = (double)session->hello1.sent_try_count-(double)1;
                                    calculate_retry(label, session, i, try_count);
                                    uint64_t_status_t rt = get_realtime_time_ns(label);
                                    if (rt.status != SUCCESS) {
                                        LOG_ERROR("%sFailed to get_realtime_time_ns.", label);
                                        CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                        event_founded_in_session = true;
                                        break;
                                    }
                                    session->hello1.ack_rcvd = true;
                                    session->hello1.ack_rcvd_time = rt.r_uint64_t;
                                    uint64_t interval_ull = session->hello1.ack_rcvd_time - session->hello1.sent_time;
                                    double rtt_value = (double)interval_ull;
                                    calculate_rtt(label, session, i, rtt_value);
                                    cleanup_hello(label, &cow_async, &session->hello1);
                                    CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                    event_founded_in_session = true;
                                } else {
                                    LOG_ERROR("%sKoneksi ditolak Tidak pernah mengirim hello1 ke IP %s.", label, host_str);
                                    CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                    event_founded_in_session = true;
                                }
                                break;
                            } else {
                                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                                event_founded_in_session = true;
                                break;
                            }
                        } else if (current_fd == session->hello1.timer_fd) {
                            uint64_t u;
                            read(session->hello1.timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                            if (must_be_disconnected(label, wot, worker_idx, i, &cow_async, session, &master_uds_fd)) {
                                event_founded_in_session = true;
                                break;
                            }
                            LOG_DEVEL_DEBUG("%s session %d: interval = %lf.", label, i, session->hello1.interval_timer_fd);
                            double try_count = (double)session->hello1.sent_try_count;
                            calculate_retry(label, session, i, try_count);
                            session->hello1.interval_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                            send_hello1(label, session);
                            event_founded_in_session = true;
                            break;
                        }
                    }
                }
                if (event_founded_in_session) continue;
//======================================================================
// Event yang belum ditangkap
//======================================================================                 
                LOG_ERROR("%sUnknown FD event %d.", label, current_fd);
//======================================================================
            }
        }
    }

//======================================================================
// COW Cleanup
//======================================================================    
exit:    
    for (int i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
        cow_c_session_t *session;
        session = &cow_c_session[i];
        if (session->in_use) {
            cleanup_session(label, &cow_async, session);
        }
    }
	async_delete_event(label, &cow_async, &master_uds_fd);
    CLOSE_FD(&master_uds_fd);
	async_delete_event(label, &cow_async, &cow_timer_fd);
    CLOSE_FD(&cow_timer_fd);
    CLOSE_FD(&cow_async.async_fd);
    free(label);
}
