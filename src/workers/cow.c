#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <stdint.h>
#include <bits/types/sig_atomic_t.h>
#include <unistd.h>

#include "log.h"
#include "ipc/protocol.h"
#include "async.h"
#include "commons.h"
#include "types.h"
#include "constants.h"

void run_client_outbound_worker(int worker_idx, int master_uds_fd) {
    volatile sig_atomic_t cow_shutdown_requested = 0;
    async_type_t cow_async;
    cow_async.async_fd = -1;
    int cow_timer_fd = -1;
    
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
	if (async_create_timerfd(label, &cow_timer_fd, WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT) != SUCCESS) goto exit;
	if (async_create_incoming_event(label, &cow_async, &cow_timer_fd) != SUCCESS) goto exit;
//======================================================================
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
// 1. Kirim IPC Hertbeat ke Master
//======================================================
			} else if (current_fd == master_uds_fd) {
                int received_client_fd = -1;
				ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(&master_uds_fd, &received_client_fd);
				if (deserialized_result.status != SUCCESS) {
					if (async_event_is_EPOLLHUP(current_events) ||
						async_event_is_EPOLLERR(current_events) ||
						async_event_is_EPOLLRDHUP(current_events))
					{
						async_delete_event(label, &cow_async, &current_fd);
						cow_shutdown_requested = 1;
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
					cow_shutdown_requested = 1;
					CLOSE_IPC_PROTOCOL(received_protocol);
					continue;
				}
				/*
				else if (master_msg_header.type == IPC_OUTBOUND_TASK) {
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
                */
				CLOSE_IPC_PROTOCOL(received_protocol);
            }
            /*
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
            } 
            */
            else {
                LOG_ERROR("%sUnknown FD event %d.", label, current_fd);
            }
        }
    }

//======================================================================
// COW Cleanup
//======================================================================    
exit:    
	CLOSE_FD(master_uds_fd);
	CLOSE_FD(cow_timer_fd);
    CLOSE_FD(cow_async.async_fd);
    free(label);
}
