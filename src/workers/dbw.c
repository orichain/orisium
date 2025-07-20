#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "log.h"
#include "ipc/protocol.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "ipc/heartbeat.h"

void run_dbw_worker(worker_type_t wot, int worker_idx, long initial_delay_ms, int master_uds_fd) {
    volatile sig_atomic_t dbw_shutdown_requested = 0;
    async_type_t dbw_async;
    dbw_async.async_fd = -1;
    int dbw_timer_fd = -1;
    srandom(time(NULL) ^ getpid());
    
//======================================================================
// Setup Logic
//======================================================================
	char *label;
	int needed = snprintf(NULL, 0, "[DBW %d]: ", worker_idx);
	label = malloc(needed + 1);
	snprintf(label, needed + 1, "[DBW %d]: ", worker_idx);  
//======================================================================	
	if (async_create(label, &dbw_async) != SUCCESS) goto exit;
	if (async_create_incoming_event_with_disconnect(label, &dbw_async, &master_uds_fd) != SUCCESS) goto exit;
//======================================================================
	if (initial_delay_ms > 0) {
        LOG_DEBUG("%sApplying initial delay of %ld ms...", label, initial_delay_ms);
        sleep_ms(initial_delay_ms);
    }
//======================================================================
	if (async_create_timerfd(label, &dbw_timer_fd) != SUCCESS) {
		 goto exit;
	}
	if (async_set_timerfd_time(label, &dbw_timer_fd,
		WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0,
        WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0) != SUCCESS)
    {
		 goto exit;
	}
	if (async_create_incoming_event(label, &dbw_async, &dbw_timer_fd) != SUCCESS) goto exit;
//======================================================================
    while (!dbw_shutdown_requested) {
        int_status_t snfds = async_wait(label, &dbw_async);
		if (snfds.status != SUCCESS) continue;
        for (int n = 0; n < snfds.r_int; ++n) {
            if (dbw_shutdown_requested) {
				break;
			}
			int_status_t fd_status = async_getfd(label, &dbw_async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents(label, &dbw_async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;
            if (current_fd == dbw_timer_fd) {
				uint64_t u;
				read(dbw_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
//======================================================				
				double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * HEARTBEAT_JITTER_PERCENTAGE * 2) - HEARTBEAT_JITTER_PERCENTAGE;
                double new_heartbeat_interval_double = WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * (1.0 + jitter_amount);
                if (new_heartbeat_interval_double < 0.1) {
                    new_heartbeat_interval_double = 0.1;
                }
                if (async_set_timerfd_time(label, &dbw_timer_fd,
					(time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9),
                    (time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9)) != SUCCESS)
                {
                    dbw_shutdown_requested = 1;
					LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", label);
					continue;
                }
//======================================================================
// 1. if => "piggybacking"/"implicit heartbeat" kalau sudah ada ipc lain yang dikirim < interval. lewati pengiriman heartbeat.
// 2. Kirim IPC Hertbeat ke Master
//======================================================================
                int not_used_fd = -1;
                ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_heartbeat(label, &not_used_fd, wot, worker_idx, new_heartbeat_interval_double);
                if (cmd_result.status != SUCCESS) {
                    continue;
                }
                ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_uds_fd, cmd_result.r_ipc_protocol_t, &not_used_fd);
                if (send_result.status != SUCCESS) {
                    LOG_ERROR("%sFailed to sent heartbeat to Master.", label);
                } else {
                    LOG_DEBUG("%sSent heartbeat to Master.", label);
                }
                CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
//======================================================================
			} else if (current_fd == master_uds_fd) {
                int received_client_fd = -1;
				ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(label, &master_uds_fd, &received_client_fd);
				if (deserialized_result.status != SUCCESS) {
					if (async_event_is_EPOLLHUP(current_events) ||
						async_event_is_EPOLLERR(current_events) ||
						async_event_is_EPOLLRDHUP(current_events))
					{
						dbw_shutdown_requested = 1;
						LOG_INFO("%sMaster disconnected. Initiating graceful shutdown...", label);
						continue;
					}
					LOG_ERROR("%sError receiving or deserializing IPC message from Master: %d", label, deserialized_result.status);
					continue;
				}
				ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;
				LOG_DEBUG("%sReceived message type: 0x%02x", label, received_protocol->type);
				LOG_DEBUG("%sReceived FD: %d", label, received_client_fd);			
                if (received_protocol->type == IPC_SHUTDOWN) {
					LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", label);
					dbw_shutdown_requested = 1;
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
	async_delete_event(label, &dbw_async, &master_uds_fd);
    CLOSE_FD(&master_uds_fd);
	async_delete_event(label, &dbw_async, &dbw_timer_fd);
    CLOSE_FD(&dbw_timer_fd);
    CLOSE_FD(&dbw_async.async_fd);
    free(label);
}
