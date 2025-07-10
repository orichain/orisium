#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "async.h"
#include "utilities.h"
#include "constants.h"

void run_logic_worker(worker_type_t wot, int worker_idx, int master_uds_fd) {
	volatile sig_atomic_t logic_shutdown_requested = 0;
    async_type_t logic_async;
    logic_async.async_fd = -1;
    int logic_timer_fd = -1;
    srandom(time(NULL) ^ getpid());
    int worker_type_id = (int)wot;
    
//======================================================================
// Setup Logic
//======================================================================
	char *label;
	int needed = snprintf(NULL, 0, "[Logic %d]: ", worker_idx);
	label = malloc(needed + 1);
	snprintf(label, needed + 1, "[Logic %d]: ", worker_idx);  
//======================================================================	
	if (async_create(label, &logic_async) != SUCCESS) goto exit;
	LOG_INFO("%s==============================Worker side: %d).", label, master_uds_fd);
	if (async_create_incoming_event_with_disconnect(label, &logic_async, &master_uds_fd) != SUCCESS) goto exit;
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
    if (async_create_timerfd(label, &logic_timer_fd) != SUCCESS) {
		 goto exit;
	}
	if (async_set_timerfd_time(label, &logic_timer_fd,
		HEARTBEAT_BASE_SEC, 0,
        HEARTBEAT_BASE_SEC, 0) != SUCCESS)
    {
		 goto exit;
	}
	if (async_create_incoming_event(label, &logic_async, &logic_timer_fd) != SUCCESS) goto exit;
//======================================================================	     
    while (!logic_shutdown_requested) {
		int_status_t snfds = async_wait(label, &logic_async);
		if (snfds.status != SUCCESS) continue;
        for (int n = 0; n < snfds.r_int; ++n) {
            if (logic_shutdown_requested) {
				break;
			}
			int_status_t fd_status = async_getfd(label, &logic_async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents(label, &logic_async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;
            if (current_fd == logic_timer_fd) {
				uint64_t u;
				read(logic_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
//======================================================				
				double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * HEARTBEAT_JITTER_PERCENTAGE * 2) - HEARTBEAT_JITTER_PERCENTAGE;
                double new_heartbeat_interval_double = HEARTBEAT_BASE_SEC * (1.0 + jitter_amount);
                if (new_heartbeat_interval_double < 0.1) {
                    new_heartbeat_interval_double = 0.1;
                }
                if (async_set_timerfd_time(label, &logic_timer_fd,
					(time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9),
                    (time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9)) != SUCCESS)
                {
                    logic_shutdown_requested = 1;
					LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", label);
					continue;
                }
                LOG_DEBUG("%s===============HEARTBEAT============", label);
//======================================================
// 1. Kirim IPC Hertbeat ke Master
// 2. "piggybacking"/"implicit heartbeat" kalau sudah ada ipc lain yang dikirim < interval. lewati pengiriman heartbeat.
//======================================================
			} else if (current_fd == master_uds_fd) {
				int received_client_fd = -1;
				ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(&master_uds_fd, &received_client_fd);
				if (deserialized_result.status != SUCCESS) {
					if (async_event_is_EPOLLHUP(current_events) ||
						async_event_is_EPOLLERR(current_events) ||
						async_event_is_EPOLLRDHUP(current_events))
					{
						logic_shutdown_requested = 1;
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
					logic_shutdown_requested = 1;
					CLOSE_IPC_PROTOCOL(&received_protocol);
					continue;
				} else if (received_protocol->type == IPC_LOGIC_TASK) {					
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
                    LOG_ERROR("%sUnknown message type %d from Master.", label, received_protocol->type);
                }
                CLOSE_IPC_PROTOCOL(&received_protocol);
            }
        }
    }
    
//======================================================================
// Logic Cleanup
//======================================================================    
exit:    
	async_delete_event(label, &logic_async, &master_uds_fd);
    CLOSE_FD(&master_uds_fd);
	async_delete_event(label, &logic_async, &logic_timer_fd);
    CLOSE_FD(&logic_timer_fd);
    CLOSE_FD(&logic_async.async_fd);
    free(label);
}
