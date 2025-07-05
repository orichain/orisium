#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
#include <pthread.h> // for pthread_t
#endif
#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdbool.h>     // for false, bool, true
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <string.h>      // for memset, strncpy
#include <sys/epoll.h>   // for epoll_event, epoll_ctl, EPOLLET, EPOLLIN
#include <sys/socket.h>  // for socketpair, SOCK_STREAM, AF_UNIX, AF_INET, accept
#include <sys/types.h>   // for pid_t, ssize_t
#include <unistd.h>      // for close, fork, getpid
#include <signal.h>      // for sig_atomic_t, sigaction, SIGINT
#include <arpa/inet.h>   // for inet_ntop, inet_pton
#include <sys/wait.h>    // for waitpid
#include <bits/types/sig_atomic_t.h>
#include <stdint.h>

#include "log.h"
#include "constants.h"
#include "commons.h"
#include "node.h"
#include "async.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "sessions.h"
#include "under_refinement_and_will_be_delete_after_finished.h"
#include "types.h"

volatile sig_atomic_t shutdown_requested = 0;
node_config_t node_config;
master_client_session_t master_client_sessions[MAX_MASTER_CONCURRENT_SESSIONS];

void run_server_io_worker(int worker_idx, int master_uds_fd) {
    LOG_INFO("[Server IO Worker %d, PID %d]: Started.", worker_idx, getpid());
    
    client_conn_state_t client_connections[MAX_CLIENTS_PER_SIO_WORKER];
    
    for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
        client_connections[i].in_use = false;
        client_connections[i].client_fd = -1;
        client_connections[i].correlation_id = -1;
        memset(client_connections[i].ip, 0, INET6_ADDRSTRLEN);
        client_connections[i].awaiting_challenge_response = false;
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
                ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(master_uds_fd, &received_client_fd);
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
                        CLOSE_PAYLOAD(received_protocol->payload.ipc_client_request_task);
						CLOSE_PROTOCOL(received_protocol);
						continue;
                    }

                    if (set_nonblocking("[SIO Worker]: ", received_client_fd) != SUCCESS) {
                        LOG_ERROR("[Server IO Worker %d]: Failed to set non-blocking for FD %d. Closing.", worker_idx, received_client_fd);
                        CLOSE_FD(received_client_fd);
                        CLOSE_PAYLOAD(received_protocol->payload.ipc_client_request_task);
						CLOSE_PROTOCOL(received_protocol);
						continue;
                    }

                    event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                    event.data.fd = received_client_fd;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, received_client_fd, &event) == -1) {
                        LOG_ERROR("epoll_ctl: add client FD to SIO worker %d epoll: %s", worker_idx, strerror(errno));
                        CLOSE_FD(received_client_fd);
                        CLOSE_PAYLOAD(received_protocol->payload.ipc_client_request_task);
						CLOSE_PROTOCOL(received_protocol);
						continue;
                    }

                    int slot_found = -1;
                    for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                        if (!client_connections[i].in_use) {
                            client_connections[i].in_use = true;
                            client_connections[i].client_fd = received_client_fd;
                            client_connections[i].correlation_id = req->correlation_id;
                            memcpy(client_connections[i].ip, req->ip, INET6_ADDRSTRLEN);
                            client_connections[i].awaiting_challenge_response = false;
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
                        CLOSE_PAYLOAD(received_protocol->payload.ipc_client_request_task);
						CLOSE_PROTOCOL(received_protocol);
						continue;
                    }

                }
                else {
                     LOG_ERROR("[Server IO Worker %d]: Unknown message type %d from Master.", worker_idx, received_protocol->type);
                }
                CLOSE_PAYLOAD(received_protocol->payload.ipc_client_request_task);
				CLOSE_PROTOCOL(received_protocol);
            } else { // Handle client TCP connections
                char client_buffer[MAX_DATA_BUFFER_IN_STRUCT];
                ssize_t bytes_read = read(current_fd, client_buffer, sizeof(client_buffer) - 1);

                if (bytes_read <= 0) {
                    if (bytes_read == 0 || (events[n].events & (EPOLLHUP | EPOLLERR))) {
                        // Client disconnected or error
                        uint64_t disconnected_client_id = 0xffffffff;
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
                        if (disconnected_client_id != 0xffffffff && client_connections[client_slot_idx].in_use) { // Check in_use before marking
							client_connections[client_slot_idx].in_use = false; // Mark as not in use here
							client_connections[client_slot_idx].client_fd = -1;
							client_connections[client_slot_idx].correlation_id = -1;
							memset(client_connections[client_slot_idx].ip, 0, INET6_ADDRSTRLEN);

							ipc_protocol_t *p = (ipc_protocol_t *)malloc(sizeof(ipc_protocol_t));
							if (!p) {
								perror("Failed to allocate ipc_protocol_t protocol");
								//CLOSE_FD(client_sock);
								CLOSE_FD(current_fd);
								continue;
							}
							memset(p, 0, sizeof(ipc_protocol_t)); // Inisialisasi dengan nol
							p->version[0] = VERSION_MAJOR;
							p->version[1] = VERSION_MINOR;
							p->type = IPC_CLIENT_DISCONNECTED;
							ipc_client_disconnect_info_t *payload = (ipc_client_disconnect_info_t *)calloc(1, sizeof(ipc_client_disconnect_info_t));
							if (!payload) {
								perror("Failed to allocate ipc_client_disconnect_info_t payload");
								//CLOSE_FD(client_sock);
								CLOSE_FD(current_fd);
								CLOSE_PAYLOAD(p->payload.ipc_client_disconnect_info);
								CLOSE_PROTOCOL(p);
								continue;
							}
							payload->correlation_id = (uint64_t)disconnected_client_id; // Cast ke uint64_t
							memcpy(payload->ip, disconnected_client_ip, INET6_ADDRSTRLEN);				
							p->payload.ipc_client_disconnect_info = payload;				
							ssize_t_status_t send_result = send_ipc_protocol_message(master_uds_fd, p, -1);
							if (send_result.status != SUCCESS) {
								LOG_INFO("[Server IO Worker %d]: Failed to sent client disconnect signal for ID %ld (IP %s) to Master.", worker_idx, disconnected_client_id, disconnected_client_ip);
							} else {
								LOG_INFO("[Server IO Worker %d]: Sent client disconnect signal for ID %ld (IP %s) to Master.", worker_idx, disconnected_client_id, disconnected_client_ip);
							}
							CLOSE_FD(current_fd);
							CLOSE_PAYLOAD(p->payload.ipc_client_disconnect_info);
							CLOSE_PROTOCOL(p);
                        }


                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("read from client (SIO)");
                    }
                    continue;
                }

                client_buffer[bytes_read] = '\0';

                uint64_t client_id_for_request = 0xffffffff;
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

                if (client_id_for_request == 0xffffffff || client_idx == -1) {
                    LOG_ERROR("[Server IO Worker %d]: Received data from unknown client FD %d. Ignoring.", worker_idx, current_fd);
                    continue;
                }
                
                ipc_protocol_t *p = (ipc_protocol_t *)malloc(sizeof(ipc_protocol_t));
                if (!p) {
					perror("Failed to allocate ipc_protocol_t protocol");
					//CLOSE_FD(client_sock);
					continue;
				}
				memset(p, 0, sizeof(ipc_protocol_t)); // Inisialisasi dengan nol
				p->version[0] = VERSION_MAJOR;
				p->version[1] = VERSION_MINOR;
				p->type = IPC_CLIENT_REQUEST_TASK;
				ipc_client_request_task_t *payload = (ipc_client_request_task_t *)calloc(1, sizeof(ipc_client_request_task_t));
				if (!payload) {
					perror("Failed to allocate ipc_client_request_task_t payload");
					//CLOSE_FD(client_sock);
					CLOSE_PROTOCOL(p);
					continue;
				}
				payload->correlation_id = (uint64_t)client_id_for_request; // Cast ke uint64_t				
				memcpy(payload->ip, client_ip_for_request, INET6_ADDRSTRLEN);
				payload->len = (uint16_t)bytes_read;
				memcpy(payload->data, &client_buffer, (uint16_t)bytes_read);
				p->payload.ipc_client_request_task = payload;				
				ssize_t_status_t send_result = send_ipc_protocol_message(master_uds_fd, p, -1);
				if (send_result.status != SUCCESS) {
					LOG_INFO("[Server IO Worker %d]: Failed to sent client request (ID %ld) to Master for Logic Worker.",
                       worker_idx, client_id_for_request);
				} else {
					LOG_INFO("[Server IO Worker %d]: Sent client request (ID %ld) to Master for Logic Worker.",
                       worker_idx, client_id_for_request);
				}
				CLOSE_PAYLOAD(p->payload.ipc_client_request_task);
				CLOSE_PROTOCOL(p);
            }
        }
    }
    close(epoll_fd);
    close(master_uds_fd);
}

// Logic Worker (processes client requests, decides what to do)
void run_logic_worker(int worker_idx, int master_uds_fd) {
    LOG_INFO("[Logic Worker %d, PID %d]: Started.", worker_idx, getpid());

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        LOG_ERROR("epoll_create1 (Logic Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET; // Edge-triggered
    event.data.fd = master_uds_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_uds_fd, &event) == -1) {
        LOG_ERROR("epoll_ctl: add master_uds_fd (Logic Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }
    LOG_INFO("[Logic Worker %d]: Master UDS %d added to epoll.", worker_idx, master_uds_fd);
    LOG_INFO("[Logic Worker %d]: Entering event loop.", worker_idx);

    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait (Logic)");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            int current_fd = events[n].data.fd;

            if (current_fd == master_uds_fd) {
				/*
                ipc_msg_header_t master_msg_header;
                char master_msg_data[sizeof(client_request_task_t) > sizeof(outbound_response_t) ?
                                     sizeof(client_request_task_t) : sizeof(outbound_response_t)];
                int received_fd = -1;
                */
                int received_fd = -1;
                ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(master_uds_fd, &received_fd);
                if (deserialized_result.status != SUCCESS) {
                    fprintf(stderr, "[Server IO Worker %d]: Error receiving or deserializing IPC message from Master: %d\n", worker_idx, deserialized_result.status);
                    continue;
                }
                ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;
                printf("[Server IO Worker %d]: Received message type: 0x%02x\n", worker_idx, received_protocol->type);
                printf("[Server IO Worker %d]: Received FD: %d\n", worker_idx, received_fd);
                /*
                ssize_t bytes_read = recv_ipc_message(master_uds_fd, &master_msg_header, master_msg_data, sizeof(master_msg_data), &received_fd);
                if (bytes_read == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recv_ipc_message from master (Logic)");
                    }
                    continue;
                }
                */
                if (received_protocol->type == IPC_LOGIC_TASK) {
					
					/*
                    client_request_task_t *task = (client_request_task_t *)master_msg_data;
                    LOG_INFO("[Logic Worker %d]: Received client request (ID %ld) from Master. Data: '%.*s'",
                           worker_idx, task->client_correlation_id, (int)task->request_data_len, task->request_data);

                    logic_response_t response;
                    response.client_correlation_id = task->client_correlation_id;

                    if (task->request_data_len > 0 && task->request_data[task->request_data_len - 1] == '\n') {
                        task->request_data[task->request_data_len - 1] = '\0';
                        task->request_data_len--;
                    }


                    if (strstr(task->request_data, "Halo saya adalah") != NULL) {
                        snprintf(response.response_data, sizeof(response.response_data),
                                 "Logic Worker %d received: '%.*s'. Thanks for the greeting!",
                                 worker_idx, (int)task->request_data_len, task->request_data);
                        response.response_data_len = strlen(response.response_data);
                        send_ipc_message(master_uds_fd, IPC_LOGIC_RESPONSE_TO_SIO, &response, sizeof(response), -1);
                        LOG_INFO("[Logic Worker %d]: Sending direct response for client ID %ld to Master for SIO.",
                               worker_idx, task->client_correlation_id);
                    }
                    else if (strstr(task->request_data, "Kirim pesan ke node lain") != NULL) {
                        LOG_INFO("[Logic Worker %d]: Client ID %ld requested sending message to node node. Preparing outbound task.",
                               worker_idx, task->client_correlation_id);

                        char node_message[MAX_DATA_BUFFER_IN_STRUCT];
                        snprintf(node_message, sizeof(node_message), "Halo ini dari Node1 ke %s:%d\n",
                                 node_config.bootstrap_nodes[0].ip, node_config.bootstrap_nodes[0].port); // Use first bootstrap node
                        
                        node_message[sizeof(node_message) - 1] = '\0';

                        LOG_INFO("[Logic Worker %d]: Prepared node message: '%s'", worker_idx, node_message);

                        outbound_task_t *outbound_task = malloc(sizeof(outbound_task_t));
                        if (!outbound_task) {
                            perror("malloc outbound_task");
                            snprintf(response.response_data, sizeof(response.response_data),
                                     "ERROR: Failed to allocate outbound task memory.");
                            response.response_data_len = strlen(response.response_data);
                            send_ipc_message(master_uds_fd, IPC_LOGIC_RESPONSE_TO_SIO, &response, sizeof(response), -1);
                            continue;
                        }
                        outbound_task->client_correlation_id = task->client_correlation_id;
                        strncpy(outbound_task->node_ip, node_config.bootstrap_nodes[0].ip, sizeof(outbound_task->node_ip) - 1);
                        outbound_task->node_ip[sizeof(outbound_task->node_ip) - 1] = '\0';
                        outbound_task->node_port = node_config.bootstrap_nodes[0].port;
                        strncpy(outbound_task->request_data, node_message, sizeof(outbound_task->request_data) - 1);
                        outbound_task->request_data[sizeof(outbound_task->request_data) - 1] = '\0';
                        outbound_task->request_data_len = strlen(outbound_task->request_data);

                        send_ipc_message(master_uds_fd, IPC_OUTBOUND_TASK, outbound_task, sizeof(outbound_task_t), -1);
                        free(outbound_task);
                        LOG_INFO("[Logic Worker %d]: Sent outbound task for client ID %ld to Master for COW.",
                               worker_idx, task->client_correlation_id);

                    } else {
                        snprintf(response.response_data, sizeof(response.response_data),
                                 "Echo from Logic Worker %d for Client ID %ld: '%.*s'",
                                 worker_idx, task->client_correlation_id,
                                 (int)task->request_data_len, task->request_data);
                        response.response_data_len = strlen(response.response_data);
                        send_ipc_message(master_uds_fd, IPC_LOGIC_RESPONSE_TO_SIO, &response, sizeof(response), -1);
                        LOG_INFO("[Logic Worker %d]: Sending echo response for client ID %ld to Master for SIO.",
                               worker_idx, task->client_correlation_id);
                    }
                    */
                } else if (received_protocol->type == IPC_OUTBOUND_RESPONSE) {
					/*
                    outbound_response_t *resp = (outbound_response_t *)master_msg_data;
                    LOG_INFO("[Logic Worker %d]: Received outbound response for client ID %ld. Success: %s, Data: '%.*s'",
                           worker_idx, resp->client_correlation_id, resp->success ? "true" : "false",
                           (int)resp->response_data_len, resp->response_data);

                    logic_response_t response_to_sio;
                    response_to_sio.client_correlation_id = resp->client_correlation_id;
                    if (resp->success) {
                        snprintf(response_to_sio.response_data, sizeof(response_to_sio.response_data),
                                 "Node responded: '%.*s'", (int)resp->response_data_len, resp->response_data);
                    } else {
                        snprintf(response_to_sio.response_data, sizeof(response_to_sio.response_data),
                                 "Node communication failed: '%.*s'", (int)resp->response_data_len, resp->response_data);
                    }
                    response_to_sio.response_data_len = strlen(response_to_sio.response_data);
                    send_ipc_message(master_uds_fd, IPC_LOGIC_RESPONSE_TO_SIO, &response_to_sio, sizeof(response_to_sio), -1);
                    LOG_INFO("[Logic Worker %d]: Notifying original client ID %ld (via SIO) about outbound communication result.",
                           worker_idx, resp->client_correlation_id);
                    */
                } else {
                    LOG_ERROR("[Logic Worker %d]: Unknown message type %d from Master.", worker_idx, received_protocol->type);
                }
                CLOSE_PAYLOAD(received_protocol->payload.ipc_client_request_task);
				CLOSE_PROTOCOL(received_protocol);
            }
        }
    }
    close(epoll_fd);
    close(master_uds_fd);
}

// Client Outbound Worker (makes outgoing TCP connections to other nodes)
void run_client_outbound_worker(int worker_idx, int master_uds_fd) {
    LOG_INFO("[Client Outbound Worker %d, PID %d]: Started.", worker_idx, getpid());

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        LOG_ERROR("epoll_create1 (COW Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET; // Edge-triggered
    event.data.fd = master_uds_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_uds_fd, &event) == -1) {
        LOG_ERROR("epoll_ctl: add master_uds_fd (COW Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }
    LOG_INFO("[Client Outbound Worker %d]: Master UDS %d added to epoll.", worker_idx, master_uds_fd);
    LOG_INFO("[Client Outbound Worker %d]: Entering event loop.", worker_idx);

    struct epoll_event events[MAX_EVENTS];

    // State for the single active outbound connection this worker manages at a time
    int active_outbound_fd = -1;
    long active_outbound_correlation_id = -1;
    char active_outbound_target_ip[INET6_ADDRSTRLEN];
    int active_outbound_target_port;
    char active_outbound_request_data[MAX_DATA_BUFFER_IN_STRUCT];
    size_t active_outbound_request_data_len = 0;

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait (COW)");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            int current_fd = events[n].data.fd;

            // Handle UDS from Master
            if (current_fd == master_uds_fd) {
                ipc_msg_header_t master_msg_header;
                char master_msg_data[sizeof(outbound_task_t)];
                int received_fd = -1;

                ssize_t bytes_read = recv_ipc_message(master_uds_fd, &master_msg_header, master_msg_data, sizeof(master_msg_data), &received_fd);
                if (bytes_read == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recv_ipc_message from master (COW)");
                    }
                    continue;
                }

                if (master_msg_header.type == IPC_OUTBOUND_TASK) {
                    if (active_outbound_fd != -1) {
                        LOG_WARN("[Client Outbound Worker %d]: WARNING: Received new outbound task but one is already active (FD %d). Ignoring.", worker_idx, active_outbound_fd);
                        outbound_response_t busy_resp;
                        busy_resp.client_correlation_id = ((outbound_task_t *)master_msg_data)->client_correlation_id;
                        busy_resp.success = false;
                        snprintf(busy_resp.response_data, sizeof(busy_resp.response_data), "COW busy.");
                        busy_resp.response_data_len = strlen(busy_resp.response_data);
                        send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &busy_resp, sizeof(busy_resp), -1);
                        active_outbound_fd = -1;
                        continue;
                    }

                    outbound_task_t *outbound_task = (outbound_task_t *)master_msg_data;
                    
                    active_outbound_correlation_id = outbound_task->client_correlation_id;
                    strncpy(active_outbound_target_ip, outbound_task->node_ip, sizeof(active_outbound_target_ip) - 1);
                    active_outbound_target_ip[sizeof(active_outbound_target_ip) - 1] = '\0';
                    active_outbound_target_port = outbound_task->node_port;
                    strncpy(active_outbound_request_data, outbound_task->request_data, sizeof(active_outbound_request_data) - 1);
                    active_outbound_request_data[sizeof(active_outbound_request_data) - 1] = '\0';
                    active_outbound_request_data_len = outbound_task->request_data_len;

                    LOG_INFO("[Client Outbound Worker %d]: Received outbound task (ID %ld): Connect to %s:%d, Send: '%.*s'",
                           worker_idx, active_outbound_correlation_id, active_outbound_target_ip, active_outbound_target_port,
                           (int)active_outbound_request_data_len, active_outbound_request_data);

                    int new_fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (new_fd == -1) {
                        perror("socket (COW)");
                        outbound_response_t fail_resp;
                        fail_resp.client_correlation_id = active_outbound_correlation_id;
                        fail_resp.success = false;
                        snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Socket creation failed.");
                        fail_resp.response_data_len = strlen(fail_resp.response_data);
                        send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                        active_outbound_fd = -1;
                        continue;
                    }

                    set_nonblocking("[COW Worker]: ", new_fd);

                    struct sockaddr_in server_addr;
                    memset(&server_addr, 0, sizeof(server_addr));
                    server_addr.sin_family = AF_INET;
                    server_addr.sin_port = htons(active_outbound_target_port);
                    if (inet_pton(AF_INET, active_outbound_target_ip, &server_addr.sin_addr) <= 0) {
                        perror("inet_pton (COW)");
                        close(new_fd);
                        outbound_response_t fail_resp;
                        fail_resp.client_correlation_id = active_outbound_correlation_id;
                        fail_resp.success = false;
                        snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Invalid node IP.");
                        fail_resp.response_data_len = strlen(fail_resp.response_data);
                        send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                        active_outbound_fd = -1;
                        continue;
                    }

                    LOG_INFO("[Client Outbound Worker %d]: Initiated connection to %s:%d (FD %d) for ID %ld.",
                           worker_idx, active_outbound_target_ip, active_outbound_target_port, new_fd, active_outbound_correlation_id);

                    if (connect(new_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
                        if (errno != EINPROGRESS) {
                            perror("connect (COW)");
                            close(new_fd);
                            outbound_response_t fail_resp;
                            fail_resp.client_correlation_id = active_outbound_correlation_id;
                            fail_resp.success = false;
                            snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Connect failed: %s", strerror(errno));
                            fail_resp.response_data_len = strlen(fail_resp.response_data);
                            send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                            active_outbound_fd = -1;
                            continue;
                        }
                        LOG_INFO("[Client Outbound Worker %d]: Connecting to %s:%d (EINPROGRESS) for ID %ld. Waiting for EPOLLOUT.",
                               worker_idx, active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);
                        active_outbound_fd = new_fd;
                        event.events = EPOLLOUT | EPOLLET | EPOLLRDHUP;
                        event.data.fd = active_outbound_fd;
                        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, active_outbound_fd, &event);
                    } else {
                        LOG_INFO("[Client Outbound Worker %d]: Connected immediately to %s:%d for ID %ld. Sending data.",
                               worker_idx, active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);
                        active_outbound_fd = new_fd;
                        LOG_INFO("[Client Outbound Worker %d]: Attempting to send '%.*s' to node %s:%d for ID %ld.",
                               worker_idx, (int)active_outbound_request_data_len, active_outbound_request_data,
                               active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);
                        ssize_t bytes_sent_immediate = write(active_outbound_fd, active_outbound_request_data, active_outbound_request_data_len);
                        if (bytes_sent_immediate == -1) {
                            perror("write to node (COW)");
                            close(active_outbound_fd);
                            outbound_response_t fail_resp;
                            fail_resp.client_correlation_id = active_outbound_correlation_id;
                            fail_resp.success = false;
                            snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Write to node failed: %s", strerror(errno));
                            fail_resp.response_data_len = strlen(fail_resp.response_data);
                            send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                            active_outbound_fd = -1;
                        } else {
                            LOG_INFO("[Client Outbound Worker %d]: Sent %zd bytes to node %s:%d for ID %ld. Waiting for response.",
                                   worker_idx, bytes_sent_immediate, active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);
                            event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                            event.data.fd = active_outbound_fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, active_outbound_fd, &event);
                        }
                    }
                } else {
                    LOG_ERROR("[Client Outbound Worker %d]: Unknown message type %d from Master.", worker_idx, master_msg_header.type);
                }
            }
            // Handle active outbound TCP connection
            else if (current_fd == active_outbound_fd) {
                ssize_t bytes_sent = 0;

                if (events[n].events & EPOLLOUT) {
                    int so_error;
                    socklen_t len = sizeof(so_error);
                    if (getsockopt(current_fd, SOL_SOCKET, SO_ERROR, &so_error, &len) == -1) {
                        perror("getsockopt SO_ERROR (COW)");
                        so_error = EIO;
                    }

                    if (so_error == 0) {
                        LOG_INFO("[Client Outbound Worker %d]: Connection to %s:%d established. Sending data for ID %ld.",
                               worker_idx, active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);

                        LOG_INFO("[Client Outbound Worker %d]: Attempting to send '%.*s' to node %s:%d for ID %ld.",
                               worker_idx, (int)active_outbound_request_data_len, active_outbound_request_data,
                               active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);

                        bytes_sent = write(current_fd, active_outbound_request_data, active_outbound_request_data_len);
                        if (bytes_sent == -1) {
                            perror("write to node (COW)");
                            outbound_response_t fail_resp;
                            fail_resp.client_correlation_id = active_outbound_correlation_id;
                            fail_resp.success = false;
                            snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Write to node failed after connect: %s", strerror(errno));
                            fail_resp.response_data_len = strlen(fail_resp.response_data);
                            send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                        } else {
                            LOG_INFO("[Client Outbound Worker %d]: Sent %zd bytes to node %s:%d for ID %ld. Waiting for response.",
                                   worker_idx, bytes_sent, active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);
                            event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                            event.data.fd = current_fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, current_fd, &event);
                        }
                    } else {
                        LOG_ERROR("[Client Outbound Worker %d]: Connect error to %s:%d: %s (FD %d).",
                                worker_idx, active_outbound_target_ip, active_outbound_target_port, strerror(so_error), current_fd);
                        outbound_response_t fail_resp;
                        fail_resp.client_correlation_id = active_outbound_correlation_id;
                        fail_resp.success = false;
                        snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Connect error: %s", strerror(so_error));
                        fail_resp.response_data_len = strlen(fail_resp.response_data);
                        send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                    }
                    if (bytes_sent == -1 || so_error != 0) {
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, NULL);
                        close(current_fd);
                        active_outbound_fd = -1;
                        LOG_INFO("[Client Outbound Worker %d]: Cleared failed outbound connection (FD %d, ID %ld).", worker_idx, current_fd, active_outbound_correlation_id);
                    }
                }
                if (events[n].events & EPOLLIN) {
                    char response_buffer[MAX_DATA_BUFFER_IN_STRUCT];
                    ssize_t bytes_read = read(current_fd, response_buffer, sizeof(response_buffer) - 1);

                    outbound_response_t outbound_resp;
                    outbound_resp.client_correlation_id = active_outbound_correlation_id;

                    if (bytes_read <= 0) {
                        if (bytes_read == 0 || (events[n].events & (EPOLLHUP | EPOLLERR))) {
                            LOG_INFO("[Client Outbound Worker %d]: Node %s:%d disconnected or error (FD %d).",
                                   worker_idx, active_outbound_target_ip, active_outbound_target_port, current_fd);
                            outbound_resp.success = false;
                            snprintf(outbound_resp.response_data, sizeof(outbound_resp.response_data), "Node disconnected prematurely.");
                        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            perror("read from node (COW)");
                            outbound_resp.success = false;
                            snprintf(outbound_resp.response_data, sizeof(outbound_resp.response_data), "Read error from node: %s", strerror(errno));
                        } else {
                            continue;
                        }
                    } else {
                        response_buffer[bytes_read] = '\0';
                        outbound_resp.success = true;
                        strncpy(outbound_resp.response_data, response_buffer, sizeof(outbound_resp.response_data) - 1);
                        outbound_resp.response_data[sizeof(outbound_resp.response_data) - 1] = '\0';
                        outbound_resp.response_data_len = bytes_read;
                        LOG_INFO("[Client Outbound Worker %d]: Received %zd bytes from node FD %d (ID %ld): '%.*s'",
                               worker_idx, bytes_read, current_fd, active_outbound_correlation_id,
                               (int)outbound_resp.response_data_len, outbound_resp.response_data);
                    }

                    send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &outbound_resp, sizeof(outbound_resp), -1);
                    LOG_INFO("[Client Outbound Worker %d]: Sent outbound response for ID %ld to Master.",
                           worker_idx, active_outbound_correlation_id);

                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, NULL);
                    close(current_fd);
                    active_outbound_fd = -1;
                    LOG_INFO("[Client Outbound Worker %d]: Closed node FD %d (ID %ld) after response.",
                           worker_idx, current_fd, outbound_resp.client_correlation_id);
                }
            } else {
                LOG_ERROR("[Client Outbound Worker %d]: Event on unknown FD %d. Ignoring.", worker_idx, current_fd);
            }
        }
    }
    close(epoll_fd);
    close(master_uds_fd);
}


// --- Setup and Cleanup (from setup.h/cleanup.h) ---
// Placeholder for setup_socket_listenner
status_t setup_socket_listenner(int *listen_sock) {
    *listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (*listen_sock == -1) {
        perror("socket (Master)");
        return FAILURE;
    }
    set_nonblocking("[Master]: ", *listen_sock); // Use label
    int opt = 1;
    if (setsockopt(*listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt SO_REUSEADDR");
        close(*listen_sock);
        return FAILURE;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(node_config.listen_port); // Use global node_config.listen_port

    if (bind(*listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind (Master)");
        close(*listen_sock);
        return FAILURE;
    }
    if (listen(*listen_sock, SOMAXCONN) == -1) {
        perror("listen (Master)");
        close(*listen_sock);
        return FAILURE;
    }
    return SUCCESS;
}

void sigint_handler(int signum) {
    shutdown_requested = 1;
    LOG_INFO("SIGINT received. Initiating graceful shutdown...");
}
void install_sigint_handler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);
    LOG_INFO("SIGINT handler installed.");
}

// Placeholder for orisium_cleanup
void orisium_cleanup(void *cleaner_thread_ptr, int *listen_sock_ptr, int *async_fd_ptr,
                     int uds_sio_fds_master_side[], int uds_logic_fds_master_side[], int uds_cow_fds_master_side[],
                     int uds_sio_fds_worker_side[], int uds_logic_fds_worker_side[], int uds_cow_fds_worker_side[],
                     pid_t sio_pids[], pid_t logic_pids[], pid_t cow_pids[]) {
    LOG_INFO("Performing cleanup...");
    if (*listen_sock_ptr != -1) close(*listen_sock_ptr);
    if (*async_fd_ptr != -1) close(*async_fd_ptr);

    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        if (uds_sio_fds_master_side[i] != 0) close(uds_sio_fds_master_side[i]);
        if (uds_sio_fds_worker_side[i] != 0) close(uds_sio_fds_worker_side[i]); // Close worker side in Master too
        if (sio_pids[i] > 0) waitpid(sio_pids[i], NULL, 0);
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        if (uds_logic_fds_master_side[i] != 0) close(uds_logic_fds_master_side[i]);
        if (uds_logic_fds_worker_side[i] != 0) close(uds_logic_fds_worker_side[i]); // Close worker side in Master too
        if (logic_pids[i] > 0) waitpid(logic_pids[i], NULL, 0);
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        if (uds_cow_fds_master_side[i] != 0) close(uds_cow_fds_master_side[i]);
        if (uds_cow_fds_worker_side[i] != 0) close(uds_cow_fds_worker_side[i]); // Close worker side in Master too
        if (cow_pids[i] > 0) waitpid(cow_pids[i], NULL, 0);
    }

    #if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
    if (cleaner_thread_ptr != NULL) {
        pthread_join(*(pthread_t*)cleaner_thread_ptr, NULL);
    }
    #endif
    LOG_INFO("Cleanup complete.");
}


// --- Fungsi setup_fork_workers yang direfaktor ---
status_t setup_fork_workers(
    const char* label,
    int listen_sock, // listen_sock passed by value, as it's closed in child
    async_type_t *async,
    int master_uds_sio_fds[], // Arrays for Master's side of UDS
    int master_uds_logic_fds[],
    int master_uds_cow_fds[],
    int worker_uds_sio_fds[], // Arrays for Worker's side of UDS
    int worker_uds_logic_fds[],
    int worker_uds_cow_fds[],
    pid_t sio_pids[],
    pid_t logic_pids[],
    pid_t cow_pids[]
) {
    // Create and fork SIO workers
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        sio_pids[i] = fork();
        if (sio_pids[i] == -1) {
            LOG_ERROR("%sfork (SIO): %s", label, strerror(errno));
            return FAILURE;
        } else if (sio_pids[i] == 0) {
            // Child (SIO Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) {
                if (j != i && worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]);
            }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]); }
            
            run_server_io_worker(i, worker_uds_sio_fds[i]);
            exit(EXIT_SUCCESS); // Child exits after running worker function
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_sio_fds[i] != 0) close(worker_uds_sio_fds[i]);
            LOG_INFO("%sForked Server IO Worker %d (PID %d).", label, i, sio_pids[i]);
        }
    }

    // Create and fork Logic workers
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        logic_pids[i] = fork();
        if (logic_pids[i] == -1) {
            LOG_ERROR("%sfork (Logic): %s", label, strerror(errno));
            return FAILURE;
        } else if (logic_pids[i] == 0) {
            // Child (Logic Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) {
                if (j != i && worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]);
            }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]); }
            
            run_logic_worker(i, worker_uds_logic_fds[i]);
            exit(EXIT_SUCCESS); // Child exits
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_logic_fds[i] != 0) close(worker_uds_logic_fds[i]);
            LOG_INFO("%sForked Logic Worker %d (PID %d).", label, i, logic_pids[i]);
        }
    }

    // Create and fork Client Outbound workers
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        cow_pids[i] = fork();
        if (cow_pids[i] == -1) {
            LOG_ERROR("%sfork (COW): %s", label, strerror(errno));
            return FAILURE;        
        } else if (cow_pids[i] == 0) {
            // Child (Client Outbound Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) {
                if (j != i && worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]);
            }
            
            run_client_outbound_worker(i, worker_uds_cow_fds[i]);
            exit(EXIT_SUCCESS); // Child exits
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_cow_fds[i] != 0) close(worker_uds_cow_fds[i]);
            LOG_INFO("%sForked Client Outbound Worker %d (PID %d).", label, i, cow_pids[i]);
        }
    }
    return SUCCESS;
}

int main() {
    memset(&node_config, 0, sizeof(node_config_t));
    strncpy(node_config.node_id, "Node1", sizeof(node_config.node_id) - 1);
    node_config.node_id[sizeof(node_config.node_id) - 1] = '\0';

#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
    log_init();
#endif
    LOG_INFO("[Master]: ==========================================================");
    LOG_INFO("[Master]: orisium dijalankan.");
    LOG_INFO("[Master]: ==========================================================");
#if defined(PRODUCTION) || defined(TOFILE)
    pthread_t cleaner_thread;
    pthread_create(&cleaner_thread, NULL, log_cleaner_thread, NULL);
#endif
    install_sigint_handler();

    int master_pid = -1;
    int listen_sock = -1;
    async_type_t master_async_ctx; // Use the struct for master's epoll
    master_async_ctx.async_fd = -1; // Initialize to -1

    // Worker UDS FDs (Master's side of the UDS) - Sized by their specific MAX_*_WORKERS
    int master_uds_sio_fds[MAX_SIO_WORKERS];
    int master_uds_logic_fds[MAX_LOGIC_WORKERS];
    int master_uds_cow_fds[MAX_COW_WORKERS];

    // Worker UDS FDs (Worker's side of the UDS) - Sized by their specific MAX_*_WORKERS
    int worker_uds_sio_fds[MAX_SIO_WORKERS];
    int worker_uds_logic_fds[MAX_LOGIC_WORKERS];
    int worker_uds_cow_fds[MAX_COW_WORKERS];

    // Worker PIDs (to keep track for waitpid later) - Sized by their specific MAX_*_WORKERS
    pid_t sio_pids[MAX_SIO_WORKERS];
    pid_t logic_pids[MAX_LOGIC_WORKERS];
    pid_t cow_pids[MAX_COW_WORKERS];
    
    if (read_network_config_from_json("config.json", &node_config) != SUCCESS) {
        LOG_ERROR("[Master]: Gagal membaca konfigurasi dari %s.", "config.json");
        goto exit;
    }
    
    LOG_INFO("[Master]: --- Node Configuration ---");
    LOG_INFO("[Master]: Node ID: %s", node_config.node_id);
    LOG_INFO("[Master]: Listen Port: %d", node_config.listen_port);
    LOG_INFO("[Master]: Bootstrap Nodes (%d):", node_config.num_bootstrap_nodes);
    for (int i = 0; i < node_config.num_bootstrap_nodes; i++) {
        LOG_INFO("[Master]:   - Node %d: IP %s, Port %d",
                 i + 1, node_config.bootstrap_nodes[i].ip, node_config.bootstrap_nodes[i].port);
    }
    LOG_INFO("[Master]: -------------------------");

    master_pid = getpid();
    LOG_INFO("[Master]: PID %d TCP Server listening on port %d.", master_pid, node_config.listen_port);

    if (setup_socket_listenner(&listen_sock) != SUCCESS) {
        goto exit;
    }
    
    master_async_ctx.async_fd = epoll_create1(0); // Initialize master's epoll instance
    if (master_async_ctx.async_fd == -1) {
        LOG_ERROR("epoll_create1 (Master): %s", strerror(errno));
        goto exit;
    }

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = listen_sock;
    if (epoll_ctl(master_async_ctx.async_fd, EPOLL_CTL_ADD, listen_sock, &event) == -1) {
        LOG_ERROR("epoll_ctl: add listen_sock (Master): %s", strerror(errno));
        goto exit;
    }
    LOG_INFO("[Master]: Listening socket %d added to epoll.", listen_sock);

    // Initialize UDS FDs arrays
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) { master_uds_sio_fds[i] = 0; worker_uds_sio_fds[i] = 0; }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) { master_uds_logic_fds[i] = 0; worker_uds_logic_fds[i] = 0; }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) { master_uds_cow_fds[i] = 0; worker_uds_cow_fds[i] = 0; }

    // Create all UDS pairs and add Master's side to epoll BEFORE forking
    // This ensures child processes inherit a complete (though mostly irrelevant) set of FDs,
    // making explicit closing easier.

    // Create UDS for SIO workers
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            LOG_ERROR("[Master]: socketpair (SIO) creation failed: %s", strerror(errno));
            goto exit;
        }
        set_nonblocking("[Master]: ", sv[0]);
        set_nonblocking("[Master]: ", sv[1]);
        master_uds_sio_fds[i] = sv[0]; // Master's side
        worker_uds_sio_fds[i] = sv[1]; // Worker's side
        if (async_create_incoming_event("[Master]: ", &master_async_ctx, &master_uds_sio_fds[i]) != SUCCESS) {
            goto exit;
        }
        LOG_INFO("[Master]: Created UDS pair for SIO Worker %d (Master side: %d, Worker side: %d).", i, master_uds_sio_fds[i], worker_uds_sio_fds[i]);
    }

    // Create UDS for Logic workers
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            LOG_ERROR("[Master]: socketpair (Logic) creation failed: %s", strerror(errno));
            goto exit;
        }
        set_nonblocking("[Master]: ", sv[0]);
        set_nonblocking("[Master]: ", sv[1]);
        master_uds_logic_fds[i] = sv[0]; // Master's side
        worker_uds_logic_fds[i] = sv[1]; // Worker's side
        if (async_create_incoming_event("[Master]: ", &master_async_ctx, &master_uds_logic_fds[i]) != SUCCESS) {
            goto exit;
        }
        LOG_INFO("[Master]: Created UDS pair for Logic Worker %d (Master side: %d, Worker side: %d).", i, master_uds_logic_fds[i], worker_uds_logic_fds[i]);
    }

    // Create UDS for COW workers
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            LOG_ERROR("[Master]: socketpair (COW) creation failed: %s", strerror(errno));
            goto exit;
        }
        set_nonblocking("[Master]: ", sv[0]);
        set_nonblocking("[Master]: ", sv[1]);
        master_uds_cow_fds[i] = sv[0]; // Master's side
        worker_uds_cow_fds[i] = sv[1]; // Worker's side
        if (async_create_incoming_event("[Master]: ", &master_async_ctx, &master_uds_cow_fds[i]) != SUCCESS) {
            goto exit;
        }
        LOG_INFO("[Master]: Created UDS pair for COW Worker %d (Master side: %d, Worker side: %d).", i, master_uds_cow_fds[i], worker_uds_cow_fds[i]);
    }


    // Call the refactored function to fork workers
    if (setup_fork_workers(
        "[Master]: ",
        listen_sock,
        &master_async_ctx, // Pass address of master's async context
        master_uds_sio_fds,
        master_uds_logic_fds,
        master_uds_cow_fds,
        worker_uds_sio_fds,
        worker_uds_logic_fds,
        worker_uds_cow_fds,
        sio_pids,
        logic_pids,
        cow_pids
    ) != SUCCESS) {
        LOG_ERROR("[Master]: Gagal mem-fork worker.");
        goto exit;
    }

    LOG_INFO("[Master]: Starting main event loop. Waiting for clients and worker communications...");

    struct epoll_event events[MAX_EVENTS];
    long next_client_id = 0; // Global unique client ID

    // Initialize master_client_sessions
    for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
        master_client_sessions[i].in_use = false;
        memset(master_client_sessions[i].ip, 0, INET6_ADDRSTRLEN);
    }

    while (!shutdown_requested) {
        int nfds = epoll_wait(master_async_ctx.async_fd, events, MAX_EVENTS, -1); // Use master's epoll FD
        if (nfds == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait (Master)");
            goto exit;
        }

        for (int n = 0; n < nfds; ++n) {
            int current_fd = events[n].data.fd;

            if (current_fd == listen_sock) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
                if (client_sock == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("accept (Master)");
                    }
                    continue;
                }
                
                uint8_t client_ip_str[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &client_addr.sin_addr, (char *)client_ip_str, INET6_ADDRSTRLEN) == NULL) {
                    perror("inet_ntop");
                    CLOSE_FD(client_sock);
                    continue;
                }

                // --- Filter: Check if IP is already connected ---
                bool ip_already_connected = false;
                for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
                    if (master_client_sessions[i].in_use &&
                        memcmp(master_client_sessions[i].ip, client_ip_str, INET6_ADDRSTRLEN) == 0) {
                        ip_already_connected = true;
                        break;
                    }
                }

                if (ip_already_connected) {
                    LOG_WARN("[Master]: Koneksi ditolak dari IP %s. Sudah ada koneksi aktif dari IP ini.", client_ip_str);
                    CLOSE_FD(client_sock);
                    continue;
                }
                // --- End Filter ---

                LOG_INFO("[Master]: New client connected from IP %s on FD %d.", client_ip_str, client_sock);

                long current_client_id = next_client_id++;
                int sio_worker_idx = (int)(current_client_id % MAX_SIO_WORKERS);
                int sio_worker_uds_fd = master_uds_sio_fds[sio_worker_idx]; // Master uses its side of UDS

                int slot_found = -1;
                for(int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
                    if(!master_client_sessions[i].in_use) {
                        master_client_sessions[i].in_use = true;
                        master_client_sessions[i].correlation_id = current_client_id;
                        master_client_sessions[i].sio_uds_fd = sio_worker_uds_fd;
                        memcpy(master_client_sessions[i].ip, client_ip_str, INET6_ADDRSTRLEN);
                        slot_found = i;
                        break;
                    }
                }
                if (slot_found == -1) {
                    LOG_ERROR("[Master]: WARNING: No free session slots in master_client_sessions. Rejecting client FD %d.", client_sock);
                    CLOSE_FD(client_sock);
                    continue;
                }
                ipc_protocol_t *p = (ipc_protocol_t *)malloc(sizeof(ipc_protocol_t));
                if (!p) {
					perror("Failed to allocate ipc_protocol_t protocol");
					CLOSE_FD(client_sock);
					continue;
				}
				memset(p, 0, sizeof(ipc_protocol_t)); // Inisialisasi dengan nol
				p->version[0] = VERSION_MAJOR;
				p->version[1] = VERSION_MINOR;
				p->type = IPC_CLIENT_REQUEST_TASK;
				ipc_client_request_task_t *payload = (ipc_client_request_task_t *)calloc(1, sizeof(ipc_client_request_task_t));
				if (!payload) {
					perror("Failed to allocate ipc_client_request_task_t payload");
					CLOSE_FD(client_sock);
					CLOSE_PROTOCOL(p);
					continue;
				}
				payload->correlation_id = (uint64_t)current_client_id; // Cast ke uint64_t
				memcpy(payload->ip, client_ip_str, INET6_ADDRSTRLEN);
				payload->len = (uint16_t)0; // Karena request_data_len 0
				p->payload.ipc_client_request_task = payload;				
				ssize_t_status_t send_result = send_ipc_protocol_message(sio_worker_uds_fd, p, client_sock);
				if (send_result.status != SUCCESS) {
					LOG_ERROR("[Master]: Failed to forward client FD %d (ID %ld) to Server IO Worker %d.",
							  client_sock, current_client_id, sio_worker_idx);
				} else {
					LOG_INFO("[Master]: Forwarding client FD %d (ID %ld) from IP %s to Server IO Worker %d (UDS FD %d). Bytes sent: %zd.",
							 client_sock, current_client_id, client_ip_str, sio_worker_idx, sio_worker_uds_fd, send_result.r_ssize_t);
					CLOSE_FD(client_sock); // di close jika berhasil Forwarding
				}
				CLOSE_PAYLOAD(p->payload.ipc_client_request_task);
				CLOSE_PROTOCOL(p);
            }
            else {
                int received_fd = -1;
                ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(current_fd, &received_fd);
                if (deserialized_result.status != SUCCESS) {
                    perror("recv_ipc_message from worker (Master)");
                    continue;
                }
                ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;                
                switch (received_protocol->type) {
                    case IPC_CLIENT_REQUEST_TASK: {
                        ipc_client_request_task_t *req = received_protocol->payload.ipc_client_request_task;
                        LOG_INFO("[Master]: Received Client Request Task (ID %ld) from Server IO Worker (UDS FD %d).", req->correlation_id, current_fd);

                        int logic_worker_idx = (int)(req->correlation_id % MAX_LOGIC_WORKERS);
                        int logic_worker_uds_fd = master_uds_logic_fds[logic_worker_idx]; // Master uses its side of UDS

                        send_ipc_message(logic_worker_uds_fd, IPC_LOGIC_TASK, req, sizeof(client_request_task_t), -1);
                        LOG_INFO("[Master]: Forwarding client request (ID %ld) to Logic Worker %d (UDS FD %d).",
                               req->correlation_id, logic_worker_idx, logic_worker_uds_fd);
                        break;
                    }
                    /*
                    case IPC_LOGIC_RESPONSE_TO_SIO: {
                        logic_response_t *resp = (logic_response_t *)master_rcv_buffer;
                        LOG_INFO("[Master]: Received Client Response (ID %ld) from Logic Worker (UDS FD %d).", resp->client_correlation_id, current_fd);

                        int target_sio_uds_fd = -1;
                        for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
                            if (master_client_sessions[i].in_use && master_client_sessions[i].correlation_id == resp->client_correlation_id) {
                                target_sio_uds_fd = master_client_sessions[i].sio_uds_fd;
                                master_client_sessions[i].in_use = false;
                                master_client_sessions[i].correlation_id = -1;
                                master_client_sessions[i].sio_uds_fd = -1;
                                memset(master_client_sessions[i].client_ip, 0, sizeof(master_client_sessions[i].client_ip));
                                break;
                            }
                        }

                        if (target_sio_uds_fd != -1) {
                            send_ipc_message(target_sio_uds_fd, IPC_LOGIC_RESPONSE_TO_SIO, resp, sizeof(logic_response_t), -1);
                            LOG_INFO("[Master]: Forwarding client response (ID %ld) to Server IO Worker (UDS FD %d).",
                                   resp->client_correlation_id, target_sio_uds_fd);
                        } else {
                            LOG_ERROR("[Master]: No SIO worker found for client ID %ld for response. Ignoring.", resp->client_correlation_id);
                        }
                        break;
                    }
                    case IPC_OUTBOUND_TASK: {
                        outbound_task_t *task = (outbound_task_t *)master_rcv_buffer;
                        LOG_INFO("[Master]: Received Outbound Task (ID %ld) from Logic Worker (UDS FD %d) for node %s:%d.",
                               task->client_correlation_id, current_fd, task->node_ip, task->node_port);

                        int cow_worker_idx = (int)(task->client_correlation_id % MAX_COW_WORKERS);
                        int cow_uds_fd = master_uds_cow_fds[cow_worker_idx]; // Master uses its side of UDS

                        send_ipc_message(cow_uds_fd, IPC_OUTBOUND_TASK, task, sizeof(outbound_task_t), -1);
                        LOG_INFO("[Master]: Forwarding outbound task (ID %ld) to Client Outbound Worker %d (UDS FD %d).",
                               task->client_correlation_id, cow_worker_idx, cow_uds_fd);
                        break;
                    }
                    case IPC_OUTBOUND_RESPONSE: {
                        outbound_response_t *resp = (outbound_response_t *)master_rcv_buffer;
                        LOG_INFO("[Master]: Received Outbound Response (ID %ld) from Client Outbound Worker (UDS FD %d). Success: %s, Data: '%.*s'",
                               resp->client_correlation_id, current_fd, resp->success ? "true" : "false",
                               (int)resp->response_data_len, resp->response_data);

                        int logic_worker_idx_for_response = (int)(resp->client_correlation_id % MAX_LOGIC_WORKERS);
                        int logic_worker_uds_fd = master_uds_logic_fds[logic_worker_idx_for_response]; // Master uses its side of UDS

                        send_ipc_message(logic_worker_uds_fd, IPC_OUTBOUND_RESPONSE, resp, sizeof(outbound_response_t), -1);
                        LOG_INFO("[Master]: Forwarding outbound response (ID %ld) to Logic Worker %d (UDS FD %d).",
                               resp->client_correlation_id, logic_worker_idx_for_response, logic_worker_uds_fd);
                        break;
                    }
                    */
                    case IPC_CLIENT_DISCONNECTED: {
                        ipc_client_disconnect_info_t *disconnect_info = received_protocol->payload.ipc_client_disconnect_info;
                        LOG_INFO("[Master]: Received Client Disconnected signal for ID %ld from IP %s (from SIO Worker UDS FD %d).",
                                 disconnect_info->correlation_id, disconnect_info->ip, current_fd);

                        for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
							
							LOG_INFO("Searching(%d) IP %s ?? %s|CI %llu ?? %llu",
                                 INET6_ADDRSTRLEN, master_client_sessions[i].ip, disconnect_info->ip,
                                 master_client_sessions[i].correlation_id, disconnect_info->correlation_id
                                 );
                                 
                            if (master_client_sessions[i].in_use &&
                                master_client_sessions[i].correlation_id == disconnect_info->correlation_id &&
                                memcmp(master_client_sessions[i].ip, disconnect_info->ip, INET6_ADDRSTRLEN) == 0) {
                                master_client_sessions[i].in_use = false;
                                master_client_sessions[i].correlation_id = -1;
                                master_client_sessions[i].sio_uds_fd = -1;
                                memset(master_client_sessions[i].ip, 0, INET6_ADDRSTRLEN);
                                LOG_INFO("[Master]: IP %s (ID %ld) dihapus dari daftar koneksi aktif.",
                                         disconnect_info->ip, disconnect_info->correlation_id);
                                break;
                            }
                        }
                        break;
                    }
                    default:
                        LOG_ERROR("[Master]: Unknown message type %d from UDS FD %d. Ignoring.", received_protocol->type, current_fd);
                        break;
                }
                CLOSE_PAYLOAD(received_protocol->payload.ipc_client_disconnect_info);
				CLOSE_PROTOCOL(received_protocol);
            }
        }
    }

exit:
    orisium_cleanup(
    #if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
        &cleaner_thread,
    #else
        NULL,
    #endif
        &listen_sock,
        &master_async_ctx.async_fd, // Pass address of the FD
        master_uds_sio_fds,
        master_uds_logic_fds,
        master_uds_cow_fds,
        worker_uds_sio_fds, // Pass worker sides for cleanup
        worker_uds_logic_fds,
        worker_uds_cow_fds,
        sio_pids,
        logic_pids,
        cow_pids
    );
    LOG_INFO("[Master]: ==========================================================");
    LOG_INFO("[Master]: orisium selesai dijalankan.");
    LOG_INFO("[Master]: ==========================================================\n\n\n");
#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))    
    log_close();
#endif
    return 0;
}
