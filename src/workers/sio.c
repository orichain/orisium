#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdbool.h>     // for false, bool, true
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <string.h>      // for memset, strncpy
#include <sys/epoll.h>   // for epoll_event, epoll_ctl, EPOLLET, EPOLLIN
#include <sys/types.h>   // for pid_t, ssize_t
#include <unistd.h>      // for close, fork, getpid
#include <stdint.h>

#include "log.h"
#include "constants.h"
#include "commons.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "sessions/sio_client_conn_state.h"
#include "types.h"
#include "ipc/client_disconnect_info.h"
#include "ipc/client_request_task.h"

void run_server_io_worker(int worker_idx, int master_uds_fd) {
    LOG_INFO("[Server IO Worker %d, PID %d]: Started.", worker_idx, getpid());
    
    sio_client_conn_state_t client_connections[MAX_CLIENTS_PER_SIO_WORKER];
    
    for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
        client_connections[i].in_use = false;
        client_connections[i].client_fd = -1;
        client_connections[i].correlation_id = -1;
        memset(client_connections[i].ip, 0, INET6_ADDRSTRLEN);
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        LOG_ERROR("epoll_create1 (SIO Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET; // Edge-triggered
    event.data.fd = master_uds_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_uds_fd, &event) == -1) {
        LOG_ERROR("epoll_ctl: add master_uds_fd (SIO Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }
    LOG_INFO("[Server IO Worker %d]: Master UDS %d added to epoll.", worker_idx, master_uds_fd);
    LOG_INFO("[Server IO Worker %d]: Entering event loop.", worker_idx);

    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait (SIO)");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            int current_fd = events[n].data.fd;

            // Handle UDS from Master
            if (current_fd == master_uds_fd) {
                int received_client_fd = -1;
                ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(&master_uds_fd, &received_client_fd);
                if (deserialized_result.status != SUCCESS) {
                    fprintf(stderr, "[Server IO Worker %d]: Error receiving or deserializing IPC message from Master: %d\n", worker_idx, deserialized_result.status);
                    continue;
                }
                ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;
                printf("[Server IO Worker %d]: Received message type: 0x%02x\n", worker_idx, received_protocol->type);
                printf("[Server IO Worker %d]: Received FD: %d\n", worker_idx, received_client_fd);
                

                if (received_protocol->type == IPC_CLIENT_REQUEST_TASK) {
                    ipc_client_request_task_t *req = received_protocol->payload.ipc_client_request_task;

                    if (received_client_fd == -1) {
                        LOG_ERROR("[Server IO Worker %d]: Error: No client FD received with IPC_CLIENT_REQUEST_TASK for ID %ld. Skipping.", worker_idx, req->correlation_id);
                        CLOSE_FD(received_client_fd);
                        CLOSE_IPC_PROTOCOL(received_protocol);
						continue;
                    }

                    if (set_nonblocking("[SIO Worker]: ", received_client_fd) != SUCCESS) {
                        LOG_ERROR("[Server IO Worker %d]: Failed to set non-blocking for FD %d. Closing.", worker_idx, received_client_fd);
                        CLOSE_FD(received_client_fd);
                        CLOSE_IPC_PROTOCOL(received_protocol);
						continue;
                    }

                    event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                    event.data.fd = received_client_fd;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, received_client_fd, &event) == -1) {
                        LOG_ERROR("epoll_ctl: add client FD to SIO worker %d epoll: %s", worker_idx, strerror(errno));
                        CLOSE_FD(received_client_fd);
                        CLOSE_IPC_PROTOCOL(received_protocol);
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
                        LOG_INFO("[Server IO Worker %d]: Received client FD %d (ID %ld, IP %s) from Master and added to epoll. Slot %d.",
                               worker_idx, received_client_fd, req->correlation_id, req->ip, slot_found);
                    } else {
                        LOG_ERROR("[Server IO Worker %d]: No free slots for new client FD %d. Closing.", worker_idx, received_client_fd);
                        CLOSE_FD(received_client_fd);
                        CLOSE_IPC_PROTOCOL(received_protocol);
						continue;
                    }

                }
                else {
                     LOG_ERROR("[Server IO Worker %d]: Unknown message type %d from Master.", worker_idx, received_protocol->type);
                }
                CLOSE_IPC_PROTOCOL(received_protocol);
            } else { // Handle client TCP connections
                char client_buffer[MAX_DATA_BUFFER_IN_STRUCT];
                ssize_t bytes_read = read(current_fd, client_buffer, sizeof(client_buffer) - 1);

                if (bytes_read <= 0) {
                    if (bytes_read == 0 || (events[n].events & (EPOLLHUP | EPOLLERR))) {
                        // Client disconnected or error
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
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, NULL);
                        close(current_fd);
                        LOG_INFO("[Server IO Worker %d]: Client FD %d (ID %ld, IP %s) disconnected.", worker_idx, current_fd, disconnected_client_id, disconnected_client_ip);

                        // Only send disconnect to Master if the session wasn't already completed by a response
                        // (Master already handles marking session as unused on successful response)
                        if (disconnected_client_id != 0ULL && client_connections[client_slot_idx].in_use) { // Check in_use before marking
							client_connections[client_slot_idx].in_use = false; // Mark as not in use here
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
								LOG_INFO("[Server IO Worker %d]: Failed to sent client disconnect signal for ID %ld (IP %s) to Master.", worker_idx, disconnected_client_id, disconnected_client_ip);
							} else {
								LOG_INFO("[Server IO Worker %d]: Sent client disconnect signal for ID %ld (IP %s) to Master.", worker_idx, disconnected_client_id, disconnected_client_ip);
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
    close(epoll_fd);
    close(master_uds_fd);
}
