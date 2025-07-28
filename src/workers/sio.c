#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <unistd.h>      // for close, fork, getpid
#include <stdint.h>
#include <time.h>
#include <bits/types/sig_atomic_t.h>

#include "log.h"
#include "async.h"
#include "constants.h"
#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "workers/master_ipc_cmds.h"

void run_sio_worker(worker_type_t wot, int worker_idx, long initial_delay_ms, int master_uds_fd) {
    volatile sig_atomic_t sio_shutdown_requested = 0;
    async_type_t sio_async;
    sio_async.async_fd = -1;
    int sio_timer_fd = -1;
//----------------------------------------------------------------------
// Inisialisasi seed dengan waktu saat ini untuk hasil yang berbeda setiap kali
// Seed untuk random() jitter
//----------------------------------------------------------------------
    srandom(time(NULL) ^ getpid());
//----------------------------------------------------------------------
    
//======================================================================
// SIO Setup
//======================================================================
	char *label;
	int needed = snprintf(NULL, 0, "[SIO %d]: ", worker_idx);
	label = malloc(needed + 1);
	snprintf(label, needed + 1, "[SIO %d]: ", worker_idx);  
//======================================================================	
	if (async_create(label, &sio_async) != SUCCESS) goto exit;
	if (async_create_incoming_event_with_disconnect(label, &sio_async, &master_uds_fd) != SUCCESS) goto exit;
//======================================================================
    if (initial_delay_ms > 0) {
        LOG_DEBUG("%sApplying initial delay of %ld ms...", label, initial_delay_ms);
        sleep_ms(initial_delay_ms);
    }
//======================================================================
	if (async_create_timerfd(label, &sio_timer_fd) != SUCCESS) {
		 goto exit;
	}
	if (async_set_timerfd_time(label, &sio_timer_fd,
		WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0,
        WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0) != SUCCESS)
    {
		 goto exit;
	}
	if (async_create_incoming_event(label, &sio_async, &sio_timer_fd) != SUCCESS) goto exit;
//======================================================================	    
    while (!sio_shutdown_requested) {
		int_status_t snfds = async_wait(label, &sio_async);
		if (snfds.status != SUCCESS) continue;
        for (int n = 0; n < snfds.r_int; ++n) {
			if (sio_shutdown_requested) {
				break;
			}
			int_status_t fd_status = async_getfd(label, &sio_async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents(label, &sio_async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;
			if (current_fd == sio_timer_fd) {
				uint64_t u;
				read(sio_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
//======================================================				
				double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * HEARTBEAT_JITTER_PERCENTAGE * 2) - HEARTBEAT_JITTER_PERCENTAGE;
                double new_heartbeat_interval_double = WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * (1.0 + jitter_amount);
                if (new_heartbeat_interval_double < 0.1) {
                    new_heartbeat_interval_double = 0.1;
                }
                if (async_set_timerfd_time(label, &sio_timer_fd,
					(time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9),
                    (time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9)) != SUCCESS)
                {
                    sio_shutdown_requested = 1;
					LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", label);
					continue;
                }
                if (worker_master_heartbeat(label, wot, worker_idx, new_heartbeat_interval_double, &master_uds_fd) != SUCCESS) {
                    continue;
                } else {
                    continue;
                }
//======================================================================
// 1. Tutup koneksi dr sio_c_session yang tidak ada aktifitas > WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT detik
//======================================================================
			} else if (current_fd == master_uds_fd) {
                if (async_event_is_EPOLLHUP(current_events) ||
                    async_event_is_EPOLLERR(current_events) ||
                    async_event_is_EPOLLRDHUP(current_events))
                {
                    sio_shutdown_requested = 1;
                    LOG_INFO("%sMaster disconnected. Initiating graceful shutdown...", label);
                    continue;
                }
				ipc_raw_protocol_t_status_t ircvdi = receive_ipc_raw_protocol_message(label, &master_uds_fd);
				if (ircvdi.status != SUCCESS) {
					LOG_ERROR("%sError receiving or deserializing IPC message from Master: %d", label, ircvdi.status);
					continue;
				}
				if (ircvdi.r_ipc_raw_protocol_t->type == IPC_MASTER_WORKER_SHUTDOWN) {
					LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", label);
                    CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
					sio_shutdown_requested = 1;
					continue;
				} else {
                    LOG_ERROR("%sUnknown protocol type %d from Master. Ignoring.", label, ircvdi.r_ipc_raw_protocol_t->type);
                    CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                    continue;
                }
            } else {
                LOG_ERROR("%sUnknown FD event %d.", label, current_fd);
            }
        }
    }

//======================================================================
// SIO Cleanup
//======================================================================    
exit:
	async_delete_event(label, &sio_async, &master_uds_fd);
    CLOSE_FD(&master_uds_fd);
	async_delete_event(label, &sio_async, &sio_timer_fd);
    CLOSE_FD(&sio_timer_fd);
    CLOSE_FD(&sio_async.async_fd);
    free(label);
}
