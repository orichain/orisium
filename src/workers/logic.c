#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <string.h>      // for memset, strncpy
#include <sys/epoll.h>   // for epoll_event, epoll_ctl, EPOLLET, EPOLLIN
#include <unistd.h>      // for close, fork, getpid
#include <bits/types/sig_atomic_t.h>

#include "log.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "types.h"

void run_logic_worker(int worker_idx, int master_uds_fd) {
    LOG_INFO("[Logic Worker %d, PID %d]: Started.", worker_idx, getpid());
    sig_atomic_t worker_shutdown_requested = 0;
    
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

    while (!worker_shutdown_requested) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait (Logic)");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            int current_fd = events[n].data.fd;

            if (current_fd == master_uds_fd) {
				
				printf("=========================================Sini 3==================================\n");
				
				/*
                ipc_msg_header_t master_msg_header;
                char master_msg_data[sizeof(client_request_task_t) > sizeof(outbound_response_t) ?
                                     sizeof(client_request_task_t) : sizeof(outbound_response_t)];
                int received_fd = -1;
                */
                int received_fd = -1;
                ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(&master_uds_fd, &received_fd);
                if (deserialized_result.status != SUCCESS) {
                    fprintf(stderr, "[Logic Worker %d]: Error receiving or deserializing IPC message from Master: %d\n", worker_idx, deserialized_result.status);
                    continue;
                }
                ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;
                printf("[Logic Worker %d]: Received message type: 0x%02x\n", worker_idx, received_protocol->type);
                printf("[Logic Worker %d]: Received FD: %d\n", worker_idx, received_fd);
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
                CLOSE_IPC_PROTOCOL(received_protocol);
            }
        }
    }
    close(epoll_fd);
    close(master_uds_fd);
}
