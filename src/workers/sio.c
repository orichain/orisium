#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <stdbool.h>     // for false, bool, true
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <string.h>      // for memset, strncpy
#include <sys/types.h>   // for pid_t, ssize_t
#include <unistd.h>      // for close, fork, getpid
#include <stdint.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>

#include "log.h"
#include "async.h"
#include "constants.h"
#include "utilities.h"
#include "ipc/protocol.h"
#include "sessions/workers_session.h"
#include "types.h"
#include "ipc/client_disconnect_info.h"
#include "ipc/client_request_task.h"

void run_server_io_worker(worker_type_t wot, int worker_idx, int master_uds_fd) {
    volatile sig_atomic_t sio_shutdown_requested = 0;
    sio_c_state_t sio_c_state[MAX_CLIENTS_PER_SIO_WORKER];
    async_type_t sio_async;
    sio_async.async_fd = -1;
    int sio_timer_fd = -1;
    srandom(time(NULL) ^ getpid());
    int worker_type_id = (int)wot;
    
//======================================================================
// SIO Setup
//======================================================================
	char *label;
	int needed = snprintf(NULL, 0, "[SIO %d]: ", worker_idx);
	label = malloc(needed + 1);
	snprintf(label, needed + 1, "[SIO %d]: ", worker_idx);  
//======================================================================	
	if (async_create(label, &sio_async) != SUCCESS) goto exit;
	LOG_INFO("%s==============================Worker side: %d).", label, master_uds_fd);
	if (async_create_incoming_event_with_disconnect(label, &sio_async, &master_uds_fd) != SUCCESS) goto exit;
//======================================================================
	const int HEARTBEAT_BASE_SEC = WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT;
    const int MILISECONDS_PER_UNIT = INITIAL_MILISECONDS_PER_UNIT;
    const long MAX_INITIAL_DELAY_MS = WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * 1000;
    long initial_delay_ms = (long)worker_type_id * worker_idx * MILISECONDS_PER_UNIT;
    if (initial_delay_ms > MAX_INITIAL_DELAY_MS) {
        initial_delay_ms = MAX_INITIAL_DELAY_MS;
    }
    if (initial_delay_ms > 0) {
        LOG_INFO("%sApplying initial delay of %ld ms...", label, initial_delay_ms);
        sleep_ms(initial_delay_ms);
    }
//======================================================================
	if (async_create_timerfd(label, &sio_timer_fd) != SUCCESS) {
		 goto exit;
	}
	if (async_set_timerfd_time(label, &sio_timer_fd,
		HEARTBEAT_BASE_SEC, 0,
        HEARTBEAT_BASE_SEC, 0) != SUCCESS)
    {
		 goto exit;
	}
	if (async_create_incoming_event(label, &sio_async, &sio_timer_fd) != SUCCESS) goto exit;
//======================================================================	    
    for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
        sio_c_state[i].in_use = false;
        sio_c_state[i].client_fd = -1;
        memset(sio_c_state[i].ip, 0, IP_ADDRESS_LEN);
    }    
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
                double new_heartbeat_interval_double = HEARTBEAT_BASE_SEC * (1.0 + jitter_amount);
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
                LOG_DEBUG("%s===============HEARTBEAT============", label);
//======================================================
// 1. Tutup koneksi dr sio_c_state yang tidak ada aktifitas > WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT detik
// 2. Kirim IPC Hertbeat ke Master
// 3. "piggybacking"/"implicit heartbeat" kalau sudah ada ipc lain yang dikirim < interval. lewati pengiriman heartbeat.
//======================================================
			} else if (current_fd == master_uds_fd) {
				int received_client_fd = -1;
				ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(&master_uds_fd, &received_client_fd);
				if (deserialized_result.status != SUCCESS) {
					if (async_event_is_EPOLLHUP(current_events) ||
						async_event_is_EPOLLERR(current_events) ||
						async_event_is_EPOLLRDHUP(current_events))
					{
						sio_shutdown_requested = 1;
						LOG_INFO("%sMaster disconnected. Initiating graceful shutdown...", label);
						continue;
					}
					LOG_ERROR("%sError receiving or deserializing IPC message from Master: %d", label, deserialized_result.status);
					continue;
				}
				ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;
				LOG_INFO("%sReceived message type: 0x%02x", label, received_protocol->type);
				LOG_INFO("%sReceived FD: %d", label, received_client_fd);
				if (received_protocol->type == IPC_SHUTDOWN) {
					LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", label);
					sio_shutdown_requested = 1;
					CLOSE_IPC_PROTOCOL(&received_protocol);
					continue;
				} else if (received_protocol->type == IPC_CLIENT_REQUEST_TASK) {
					ipc_client_request_task_t *req = received_protocol->payload.ipc_client_request_task;
					char ip_str[INET6_ADDRSTRLEN];
					convert_ipv6_bin_to_str(req->ip, ip_str);
	
					if (received_client_fd == -1) {
						LOG_ERROR("%sError: No client FD received with IPC_CLIENT_REQUEST_TASK for IP %s. Skipping.", label, ip_str);
						CLOSE_FD(&received_client_fd);
						CLOSE_IPC_PROTOCOL(&received_protocol);
						continue;
					}
					if (set_nonblocking(label, received_client_fd) != SUCCESS) {
						LOG_ERROR("%sFailed to set non-blocking for FD %d. Closing.", label, received_client_fd);
						CLOSE_FD(&received_client_fd);
						CLOSE_IPC_PROTOCOL(&received_protocol);
						continue;
					}
					if (async_create_incoming_event_with_disconnect(label, &sio_async, &received_client_fd) != SUCCESS) {
						continue;
					}
					int slot_found = -1;
					for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
						if (!sio_c_state[i].in_use) {
							sio_c_state[i].in_use = true;
							sio_c_state[i].client_fd = received_client_fd;
							memcpy(sio_c_state[i].ip, req->ip, IP_ADDRESS_LEN);
							slot_found = i;
							break;
						}
					}
					if (slot_found != -1) {
						char ip_str[INET6_ADDRSTRLEN];
						convert_ipv6_bin_to_str(req->ip, ip_str);
						
						LOG_INFO("%sReceived client FD %d (IP %s) from Master and added to epoll. Slot %d.",
							   label, received_client_fd, ip_str, slot_found);
					} else {
						LOG_ERROR("%sNo free slots for new client FD %d. Closing.", label, received_client_fd);
						CLOSE_FD(&received_client_fd);
						CLOSE_IPC_PROTOCOL(&received_protocol);
						continue;
					}
				} else {
					 LOG_ERROR("%sUnknown message type %d from Master.", label, received_protocol->type);
				}
				CLOSE_IPC_PROTOCOL(&received_protocol);
            } else {
                char client_buffer[MAX_DATA_BUFFER_IN_STRUCT];
                ssize_t bytes_read = read(current_fd, client_buffer, sizeof(client_buffer) - 1);
                if (bytes_read <= 0) {
                    if (bytes_read == 0 ||
						async_event_is_EPOLLHUP(current_events) ||
						async_event_is_EPOLLERR(current_events) ||
						async_event_is_EPOLLRDHUP(current_events))
					{
                        uint8_t disconnected_client_ip[IP_ADDRESS_LEN];
                        memset(disconnected_client_ip, 0, IP_ADDRESS_LEN);

                        int client_slot_idx = -1;
                        for(int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                            if(sio_c_state[i].in_use && sio_c_state[i].client_fd == current_fd) {
                                memcpy(disconnected_client_ip, sio_c_state[i].ip, IP_ADDRESS_LEN);
                                client_slot_idx = i;
                                break;
                            }
                        }
                        async_delete_event(label, &sio_async, &current_fd);                        
                        CLOSE_FD(&current_fd);
                        if (sio_c_state[client_slot_idx].in_use) {
							sio_c_state[client_slot_idx].in_use = false;
							sio_c_state[client_slot_idx].client_fd = -1;
							memset(sio_c_state[client_slot_idx].ip, 0, IP_ADDRESS_LEN);
							
							ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_client_disconnect_info(&current_fd, disconnected_client_ip);
							if (cmd_result.status != SUCCESS) {
								continue;
							}
							int not_used_fd = -1;				
							ssize_t_status_t send_result = send_ipc_protocol_message(&master_uds_fd, cmd_result.r_ipc_protocol_t, &not_used_fd);
							if (send_result.status != SUCCESS) {
								LOG_INFO("%sFailed to sent client disconnect signal for (IP %s) to Master.", label, disconnected_client_ip);
							} else {
								LOG_INFO("%sSent client disconnect signal for (IP %s) to Master.", label, disconnected_client_ip);
							}
							CLOSE_FD(&current_fd);
							CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
                        }
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("read from client (SIO)");
                    }
                    continue;
                }
                client_buffer[bytes_read] = '\0';
                int client_idx = -1;
                uint8_t client_ip_for_request[IP_ADDRESS_LEN];
                memset(client_ip_for_request, 0, IP_ADDRESS_LEN);

                for(int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                    if(sio_c_state[i].in_use && sio_c_state[i].client_fd == current_fd) {
                        client_idx = i;
                        memcpy(client_ip_for_request, sio_c_state[i].ip, IP_ADDRESS_LEN);
                        break;
                    }
                }
                if (client_idx == -1) {
                    LOG_ERROR("[Server IO Worker %d]: Received data from unknown client FD %d. Ignoring.", worker_idx, current_fd);
                    continue;
                }
                
                int not_used_fd = -1;
                ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_client_request_task(&not_used_fd, client_ip_for_request, (uint16_t)bytes_read, (uint8_t *)client_buffer);
                if (cmd_result.status != SUCCESS) {
					continue;
				}	
				ssize_t_status_t send_result = send_ipc_protocol_message(&master_uds_fd, cmd_result.r_ipc_protocol_t, &not_used_fd);
				char ip_str[INET6_ADDRSTRLEN];
				convert_ipv6_bin_to_str(client_ip_for_request, ip_str);
				if (send_result.status != SUCCESS) {
					LOG_INFO("[Server IO Worker %d]: Failed to sent client request IP %s to Master for Logic Worker.",
                       worker_idx, ip_str);
				} else {
					LOG_INFO("[Server IO Worker %d]: Sent client request IP %s to Master for Logic Worker.",
                       worker_idx, ip_str);
				}
				CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            }
        }
    }

//======================================================================
// SIO Cleanup
//======================================================================    
exit:
	for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) { // Kebiasaann bagus = harus selalu ingat "CLOSE FD + HAPUS event"
		if (sio_c_state[i].in_use) {
			CLOSE_FD(&sio_c_state[i].client_fd);
		}
	}
	async_delete_event(label, &sio_async, &master_uds_fd);
    CLOSE_FD(&master_uds_fd);
	async_delete_event(label, &sio_async, &sio_timer_fd);
    CLOSE_FD(&sio_timer_fd);
    CLOSE_FD(&sio_async.async_fd);
    free(label);
}
