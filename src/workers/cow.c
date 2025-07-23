#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
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
        memset(&cow_c_session[i].addr, 0, sizeof(struct sockaddr_in6));
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
                            memcpy(&cow_c_session[i].addr, &cc->addr, sizeof(cc->addr));
                            cow_c_session[i].addr_len = sizeof(cow_c_session[i].addr);
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
                    uint64_t id;
                    generate_connection_id(label, &id);
                    cow_c_session[slot_found].syn_fd = -1;
                    cow_c_session[slot_found].syn_timer_fd = -1;
                    cow_c_session[slot_found].heartbeat.ping_fd = -1;
                    cow_c_session[slot_found].heartbeat.ping_timer_fd = -1;
                    cow_c_session[slot_found].heartbeat.pong_ack_fd = -1;
                    cow_c_session[slot_found].heartbeat.pong_ack_timer_fd = -1;
                    cow_c_session[slot_found].fin_fd = -1;
                    cow_c_session[slot_found].fin_timer_fd = -1;
                    
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
        if (cow_c_session[i].in_use) {
            cow_c_session[i].in_use = false;
            memset(&cow_c_session[i].addr, 0, sizeof(struct sockaddr_in6));
            if (cow_c_session[i].rtt_kalman_calibration_samples) free(cow_c_session[i].rtt_kalman_calibration_samples);
            if (cow_c_session[i].retry_kalman_calibration_samples) free(cow_c_session[i].retry_kalman_calibration_samples);
            async_delete_event(label, &cow_async, &cow_c_session[i].syn_fd);
            async_delete_event(label, &cow_async, &cow_c_session[i].syn_timer_fd);
            async_delete_event(label, &cow_async, &cow_c_session[i].heartbeat.ping_fd);
            async_delete_event(label, &cow_async, &cow_c_session[i].heartbeat.ping_timer_fd);
            async_delete_event(label, &cow_async, &cow_c_session[i].heartbeat.pong_ack_fd);
            async_delete_event(label, &cow_async, &cow_c_session[i].heartbeat.pong_ack_timer_fd);
            async_delete_event(label, &cow_async, &cow_c_session[i].fin_fd);
            async_delete_event(label, &cow_async, &cow_c_session[i].fin_timer_fd);
            CLOSE_FD(&cow_c_session[i].syn_fd);
            CLOSE_FD(&cow_c_session[i].syn_timer_fd);
            CLOSE_FD(&cow_c_session[i].heartbeat.ping_fd);
            CLOSE_FD(&cow_c_session[i].heartbeat.ping_timer_fd);
            CLOSE_FD(&cow_c_session[i].heartbeat.pong_ack_fd);
            CLOSE_FD(&cow_c_session[i].heartbeat.pong_ack_timer_fd);
            CLOSE_FD(&cow_c_session[i].fin_fd);
            CLOSE_FD(&cow_c_session[i].fin_timer_fd);
        }
    }
	async_delete_event(label, &cow_async, &master_uds_fd);
    CLOSE_FD(&master_uds_fd);
	async_delete_event(label, &cow_async, &cow_timer_fd);
    CLOSE_FD(&cow_timer_fd);
    CLOSE_FD(&cow_async.async_fd);
    free(label);
}
