#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "log.h"
#include "ipc/protocol.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "sessions/workers_session.h"
#include "ipc/worker_master_heartbeat.h"
#include "workers/master_ipc_cmds.h"
#include "workers/master_orilink_cmds.h"

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
        LOG_DEBUG("%sApplying initial delay of %ld ms...", label, initial_delay_ms);
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
        cow_c_session[i].in_use = false;
        CLOSE_FD(&cow_c_session[i].sock_fd);
        memset(&cow_c_session[i].server_addr, 0, sizeof(struct sockaddr_in6));
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
                if (master_heartbeat(label, wot, worker_idx, new_heartbeat_interval_double, &master_uds_fd) != SUCCESS) continue;
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
				LOG_DEBUG("%sReceived message type: 0x%02x", label, received_protocol->type);		
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
                            memcpy(&cow_c_session[i].server_addr, &cc->server_addr, sizeof(cc->server_addr));
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
                    //uint64_t id;
                    //generate_connection_id(label, &id);
                    cow_c_session_t *session;
                    session = &cow_c_session[slot_found];
                    //session->id = id;
//======================================================================
// Init All FD                    
//======================================================================
                    session->sock_fd = -1;
                    session->hello1_timer_fd = -1;
                    session->hello2_timer_fd = -1;
                    session->hello3_timer_fd = -1;
                    session->hello_end_timer_fd = -1;
                    session->syn_timer_fd = -1;
                    session->heartbeat.ping_timer_fd = -1;
                    session->heartbeat.pong_ack_timer_fd = -1;
                    session->fin_timer_fd = -1;
//======================================================================
                    struct addrinfo hints, *res, *rp;
                    memset(&hints, 0, sizeof(hints));
                    hints.ai_family = AF_UNSPEC;
                    hints.ai_socktype = SOCK_DGRAM;
                    hints.ai_protocol = IPPROTO_UDP;
                    char host_str[NI_MAXHOST];
                    char port_str[NI_MAXSERV];
                    int getname_res = getnameinfo((struct sockaddr *)&session->server_addr, sizeof(struct sockaddr_in6),
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
                        LOG_DEBUG("%sUDP Socket FD %d created.", label, session->sock_fd);
                        status_t r_snbkg = set_nonblocking(label, session->sock_fd);
                        if (r_snbkg != SUCCESS) {
                            LOG_ERROR("%sset_nonblocking failed.", label);
                            continue;
                        }
                        LOG_DEBUG("%sUDP Socket FD %d set to non-blocking.", label, session->sock_fd);
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
// Init HELLO Timeout
//======================================================================
                    session->interval_hello1_timer_fd = (double)1;
//======================================================================
                    if (async_create_timerfd(label, &session->hello1_timer_fd) != SUCCESS) {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    if (async_set_timerfd_time(label, &session->hello1_timer_fd,
                        (time_t)session->interval_hello1_timer_fd,
                        (long)((session->interval_hello1_timer_fd - (time_t)session->interval_hello1_timer_fd) * 1e9),
                        (time_t)session->interval_hello1_timer_fd,
                        (long)((session->interval_hello1_timer_fd - (time_t)session->interval_hello1_timer_fd) * 1e9)) != SUCCESS)
                    {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    if (async_create_incoming_event(label, &cow_async, &session->hello1_timer_fd) != SUCCESS) {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//======================================================================
// Send HELLO                    
//======================================================================
                    uint64_t_status_t rt = get_realtime_time_ns(label);
                    if (rt.status != SUCCESS) {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
                    session->syn_sent_try_count = 1;
                    session->syn_sent_time = rt.r_uint64_t;
                    if (master_hello1(label, session) != SUCCESS) {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        continue;
                    }
//======================================================================                    
                    CLOSE_IPC_PROTOCOL(&received_protocol);
					continue;
				}
				CLOSE_IPC_PROTOCOL(&received_protocol);
            } else {
                LOG_ERROR("%sUnknown FD event %d.", label, current_fd);
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
            session->in_use = false;
            memset(&session->server_addr, 0, sizeof(struct sockaddr_in6));
            if (session->rtt_kalman_calibration_samples) free(session->rtt_kalman_calibration_samples);
            if (session->retry_kalman_calibration_samples) free(session->retry_kalman_calibration_samples);
            async_delete_event(label, &cow_async, &session->sock_fd);
            async_delete_event(label, &cow_async, &session->hello1_timer_fd);
            async_delete_event(label, &cow_async, &session->hello2_timer_fd);
            async_delete_event(label, &cow_async, &session->hello3_timer_fd);
            async_delete_event(label, &cow_async, &session->hello_end_timer_fd);
            async_delete_event(label, &cow_async, &session->syn_timer_fd);
            async_delete_event(label, &cow_async, &session->heartbeat.ping_timer_fd);
            async_delete_event(label, &cow_async, &session->heartbeat.pong_ack_timer_fd);
            async_delete_event(label, &cow_async, &session->fin_timer_fd);
            CLOSE_FD(&session->sock_fd);
            CLOSE_FD(&session->hello1_timer_fd);
            CLOSE_FD(&session->hello2_timer_fd);
            CLOSE_FD(&session->hello3_timer_fd);
            CLOSE_FD(&session->hello_end_timer_fd);
            CLOSE_FD(&session->syn_timer_fd);
            CLOSE_FD(&session->heartbeat.ping_timer_fd);
            CLOSE_FD(&session->heartbeat.pong_ack_timer_fd);
            CLOSE_FD(&session->fin_timer_fd);
        }
    }
	async_delete_event(label, &cow_async, &master_uds_fd);
    CLOSE_FD(&master_uds_fd);
	async_delete_event(label, &cow_async, &cow_timer_fd);
    CLOSE_FD(&cow_timer_fd);
    CLOSE_FD(&cow_async.async_fd);
    free(label);
}
