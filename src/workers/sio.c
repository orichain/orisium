#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdbool.h>     // for false, bool, true
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <string.h>      // for memset, strncpy
#include <sys/types.h>   // for pid_t, ssize_t
#include <unistd.h>      // for close, fork, getpid
#include <stdint.h>
#include <bits/types/sig_atomic_t.h>

#include "log.h"
#include "async.h"
#include "constants.h"
#include "commons.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "sessions/sio_client_conn_state.h"
#include "types.h"
#include "ipc/client_disconnect_info.h"
#include "ipc/client_request_task.h"

void run_server_io_worker(int worker_idx, int master_uds_fd) {
    volatile sig_atomic_t sio_shutdown_requested = 0;
    sio_client_conn_state_t client_connections[MAX_CLIENTS_PER_SIO_WORKER];
    async_type_t sio_async;
    sio_async.async_fd = -1;
    
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
    for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
        client_connections[i].in_use = false;
        client_connections[i].client_fd = -1;
        client_connections[i].correlation_id = -1;
        memset(client_connections[i].ip, 0, INET6_ADDRSTRLEN);
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
            if (current_fd == master_uds_fd) {
				int received_client_fd = -1;
				ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(&master_uds_fd, &received_client_fd);
				if (deserialized_result.status != SUCCESS) {
					if (async_event_is_EPOLLHUP(current_events) ||
						async_event_is_EPOLLERR(current_events) ||
						async_event_is_EPOLLRDHUP(current_events))
					{
						async_delete_event(label, &sio_async, &current_fd);
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
					CLOSE_IPC_PROTOCOL(received_protocol);
					continue;
				} else if (received_protocol->type == IPC_CLIENT_REQUEST_TASK) {
					ipc_client_request_task_t *req = received_protocol->payload.ipc_client_request_task;
					if (received_client_fd == -1) {
						LOG_ERROR("%sError: No client FD received with IPC_CLIENT_REQUEST_TASK for ID %ld. Skipping.", label, req->correlation_id);
						CLOSE_FD(received_client_fd);
						CLOSE_IPC_PROTOCOL(received_protocol);
						continue;
					}
					if (set_nonblocking(label, received_client_fd) != SUCCESS) {
						LOG_ERROR("%sFailed to set non-blocking for FD %d. Closing.", label, received_client_fd);
						CLOSE_FD(received_client_fd);
						CLOSE_IPC_PROTOCOL(received_protocol);
						continue;
					}
					if (async_create_incoming_event_with_disconnect(label, &sio_async, &received_client_fd) != SUCCESS) {
						continue;
					}
					int slot_found = -1;
					for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
						if (!client_connections[i].in_use) {
							client_connections[i].in_use = true;
							client_connections[i].client_fd = received_client_fd;
							client_connections[i].correlation_id = req->correlation_id;
							memcpy(client_connections[i].ip, req->ip, INET6_ADDRSTRLEN);
							slot_found = i;
							break;
						}
					}
					if (slot_found != -1) {
						LOG_INFO("%sReceived client FD %d (ID %ld, IP %s) from Master and added to epoll. Slot %d.",
							   label, received_client_fd, req->correlation_id, req->ip, slot_found);
					} else {
						LOG_ERROR("%sNo free slots for new client FD %d. Closing.", label, received_client_fd);
						CLOSE_FD(received_client_fd);
						CLOSE_IPC_PROTOCOL(received_protocol);
						continue;
					}
				} else {
					 LOG_ERROR("%sUnknown message type %d from Master.", label, received_protocol->type);
				}
				CLOSE_IPC_PROTOCOL(received_protocol);
            } else {
                char client_buffer[MAX_DATA_BUFFER_IN_STRUCT];
                ssize_t bytes_read = read(current_fd, client_buffer, sizeof(client_buffer) - 1);
                if (bytes_read <= 0) {
                    if (bytes_read == 0 ||
						async_event_is_EPOLLHUP(current_events) ||
						async_event_is_EPOLLERR(current_events) ||
						async_event_is_EPOLLRDHUP(current_events))
					{
                        uint64_t disconnected_client_id = 0ULL;
                        uint8_t disconnected_client_ip[INET6_ADDRSTRLEN];
                        memset(disconnected_client_ip, 0, INET6_ADDRSTRLEN);

                        int client_slot_idx = -1;
                        for(int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                            if(client_connections[i].in_use && client_connections[i].client_fd == current_fd) {
                                disconnected_client_id = client_connections[i].correlation_id;
                                memcpy(disconnected_client_ip, client_connections[i].ip, INET6_ADDRSTRLEN);
                                client_slot_idx = i;
                                break;
                            }
                        }
                        async_delete_event(label, &sio_async, &current_fd);                        
                        if (disconnected_client_id != 0ULL && client_connections[client_slot_idx].in_use) {
							client_connections[client_slot_idx].in_use = false;
							client_connections[client_slot_idx].client_fd = -1;
							client_connections[client_slot_idx].correlation_id = -1;
							memset(client_connections[client_slot_idx].ip, 0, INET6_ADDRSTRLEN);
							
							ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_client_disconnect_info(&current_fd, &disconnected_client_id, disconnected_client_ip);
							if (cmd_result.status != SUCCESS) {
								continue;
							}
							int not_used_fd = -1;				
							ssize_t_status_t send_result = send_ipc_protocol_message(&master_uds_fd, cmd_result.r_ipc_protocol_t, &not_used_fd);
							if (send_result.status != SUCCESS) {
								LOG_INFO("%sFailed to sent client disconnect signal for ID %ld (IP %s) to Master.", label, disconnected_client_id, disconnected_client_ip);
							} else {
								LOG_INFO("%sSent client disconnect signal for ID %ld (IP %s) to Master.", label, disconnected_client_id, disconnected_client_ip);
							}
							CLOSE_FD(current_fd);
							CLOSE_IPC_PROTOCOL(cmd_result.r_ipc_protocol_t);
                        }
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("read from client (SIO)");
                    }
                    continue;
                }
                client_buffer[bytes_read] = '\0';
                uint64_t client_id_for_request = 0ULL;
                int client_idx = -1;
                uint8_t client_ip_for_request[INET6_ADDRSTRLEN];
                memset(client_ip_for_request, 0, INET6_ADDRSTRLEN);

                for(int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                    if(client_connections[i].in_use && client_connections[i].client_fd == current_fd) {
                        client_id_for_request = client_connections[i].correlation_id;
                        client_idx = i;
                        memcpy(client_ip_for_request, client_connections[i].ip, INET6_ADDRSTRLEN);
                        break;
                    }
                }
                if (client_id_for_request == 0ULL || client_idx == -1) {
                    LOG_ERROR("[Server IO Worker %d]: Received data from unknown client FD %d. Ignoring.", worker_idx, current_fd);
                    continue;
                }
                
                int not_used_fd = -1;
                ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_client_request_task(&not_used_fd, &client_id_for_request, client_ip_for_request, (uint16_t)bytes_read, (uint8_t *)client_buffer);
                if (cmd_result.status != SUCCESS) {
					continue;
				}	
				ssize_t_status_t send_result = send_ipc_protocol_message(&master_uds_fd, cmd_result.r_ipc_protocol_t, &not_used_fd);
				if (send_result.status != SUCCESS) {
					LOG_INFO("[Server IO Worker %d]: Failed to sent client request (ID %ld) to Master for Logic Worker.",
                       worker_idx, client_id_for_request);
				} else {
					LOG_INFO("[Server IO Worker %d]: Sent client request (ID %ld) to Master for Logic Worker.",
                       worker_idx, client_id_for_request);
				}
				CLOSE_IPC_PROTOCOL(cmd_result.r_ipc_protocol_t);
            }
        }
    }

//======================================================================
// SIO Cleanup
//======================================================================    
exit:    
	CLOSE_FD(master_uds_fd);
    CLOSE_FD(sio_async.async_fd);
    free(label);
}
