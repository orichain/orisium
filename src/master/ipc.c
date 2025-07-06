#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdbool.h>     // for false, bool, true
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy

#include "log.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "sessions/closed_correlation_id.h"
#include "sessions/master_client_session.h"
#include "under_refinement_and_will_be_delete_after_finished.h"
#include "types.h"

status_t handle_ipc_event(const char *label, master_client_session_t master_client_sessions[], int master_uds_logic_fds[], int master_uds_cow_fds[], int *current_fd) {
	int received_fd = -1;
	ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(current_fd, &received_fd);
	if (deserialized_result.status != SUCCESS) {
		perror("recv_ipc_message from worker (Master)");
		return deserialized_result.status;
	}
	ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;                
	switch (received_protocol->type) {
		case IPC_CLIENT_REQUEST_TASK: {
			
			printf("=========================================Sini 2==================================\n");
			
			ipc_client_request_task_t *req = received_protocol->payload.ipc_client_request_task;
			LOG_INFO("[Master]: Received Client Request Task (ID %ld) from Server IO Worker (UDS FD %d).", req->correlation_id, *current_fd);

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
			LOG_INFO("[Master]: Received Client Response (ID %ld) from Logic Worker (UDS FD %d).", resp->client_correlation_id, *current_fd);

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
				   task->client_correlation_id, *current_fd, task->node_ip, task->node_port);

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
				   resp->client_correlation_id, *current_fd, resp->success ? "true" : "false",
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
			add_closed_correlation_id("[Master]: ", &closed_correlation_id_head, disconnect_info->correlation_id, disconnect_info->ip); 
			//cnt_connection -= (double_t)1;
			//avg_connection = cnt_connection / sio_worker;
			
			
			LOG_INFO("[Master]: Received Client Disconnected signal for ID %ld from IP %s (from SIO Worker UDS FD %d).",
					 disconnect_info->correlation_id, disconnect_info->ip, *current_fd);

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
			LOG_ERROR("[Master]: Unknown message type %d from UDS FD %d. Ignoring.", received_protocol->type, *current_fd);
			break;
	}
	CLOSE_IPC_PROTOCOL(received_protocol);
	return SUCCESS;
}
