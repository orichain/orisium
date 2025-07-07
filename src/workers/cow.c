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
#include <arpa/inet.h>   // for inet_ntop, inet_pton
#include <stdint.h>
#include <bits/types/sig_atomic_t.h>

#include "log.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "under_refinement_and_will_be_delete_after_finished.h"

void run_client_outbound_worker(int worker_idx, int master_uds_fd) {
    LOG_INFO("[Client Outbound Worker %d, PID %d]: Started.", worker_idx, getpid());
    sig_atomic_t worker_shutdown_requested = 0;

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
    uint8_t active_outbound_target_ip[INET6_ADDRSTRLEN];
    int active_outbound_target_port = 1182;
    uint8_t active_outbound_request_data[MAX_DATA_BUFFER_IN_STRUCT];
    size_t active_outbound_request_data_len = 0;

    while (!worker_shutdown_requested) {
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
                    memcpy(active_outbound_target_ip, outbound_task->node_ip, INET6_ADDRSTRLEN);
                    active_outbound_target_port = outbound_task->node_port;
                    memcpy(active_outbound_request_data, outbound_task->request_data, MAX_DATA_BUFFER_IN_STRUCT);
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
                    if (inet_pton(AF_INET, (char *)active_outbound_target_ip, &server_addr.sin_addr) <= 0) {
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
                    uint8_t response_buffer[MAX_DATA_BUFFER_IN_STRUCT];
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
                        memcpy(outbound_resp.response_data, response_buffer, MAX_DATA_BUFFER_IN_STRUCT);
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
