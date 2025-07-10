#include <stdbool.h>     // for false, bool, true
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <netinet/in.h>

#include "log.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "sessions/master_session.h"
#include "types.h"
#include "utilities.h"
#include "master/ipc.h"
#include "master/process.h"

worker_type_t_status_t handle_ipc_closed_event(const char *label, master_context *master_ctx, int *current_fd) {
	worker_type_t_status_t result;
	result.r_worker_type_t = UNKNOWN;
	result.status = FAILURE;
	result.index = -1;
    const char* worker_name = "Unknown";
    bool is_worker_uds = false;

    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        if (*current_fd == master_ctx->sio[i].uds[0]) {
            is_worker_uds = true;
            result.r_worker_type_t = SIO;
            worker_name = "SIO";
            result.index = i;
            break;
        }
    }
    if (!is_worker_uds) {
        for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
            if (*current_fd == master_ctx->logic[i].uds[0]) {
                is_worker_uds = true;
                result.r_worker_type_t = LOGIC;
                worker_name = "Logic";
                result.index = i;
                break;
            }
        }
    }
    if (!is_worker_uds) {
        for (int i = 0; i < MAX_COW_WORKERS; ++i) {
            if (*current_fd == master_ctx->cow[i].uds[0]) {
                is_worker_uds = true;
                result.r_worker_type_t = COW;
                worker_name = "COW";
                result.index = i;
                break;
            }
        }
    }
    if (is_worker_uds) {
		LOG_INFO("%sWorker UDS FD %d (%s Worker %d) terputus.", label, *current_fd, worker_name, result.index);
		//if (async_delete_event(label, &master_ctx->master_async, current_fd) != SUCCESS) {
		//	result.status = FAILURE;			
		//	return result;
		//}
        result.status = SUCCESS;			
		return result;
	}
	return result;
}

status_t handle_ipc_event(const char *label, master_context *master_ctx, int *current_fd) {	
	int received_fd = -1;
	ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(current_fd, &received_fd);
	if (deserialized_result.status != SUCCESS) {
		perror("recv_ipc_message from worker (Master)");
		return deserialized_result.status;
	}
	ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;                
	switch (received_protocol->type) {
		case IPC_CLIENT_REQUEST_TASK: {
			/*
			printf("=========================================Sini 2==================================\n");
			
			ipc_client_request_task_t *req = received_protocol->payload.ipc_client_request_task;
			LOG_INFO("[Master]: Received Client Request Task (ID %ld) from Server IO Worker (UDS FD %d).", req->correlation_id, *current_fd);

			int logic_worker_idx = (int)(req->correlation_id % MAX_LOGIC_WORKERS);
			int logic_worker_uds_fd = master_ctx->master_uds_logic_fds[logic_worker_idx]; // Master uses its side of UDS

			send_ipc_message(logic_worker_uds_fd, IPC_LOGIC_TASK, req, sizeof(client_request_task_t), -1);
			LOG_INFO("[Master]: Forwarding client request (ID %ld) to Logic Worker %d (UDS FD %d).",
				   req->correlation_id, logic_worker_idx, logic_worker_uds_fd);
			*/
			break;
		}
		/*
		case IPC_LOGIC_RESPONSE_TO_SIO: {
			logic_response_t *resp = (logic_response_t *)master_rcv_buffer;
			LOG_INFO("[Master]: Received Client Response (ID %ld) from Logic Worker (UDS FD %d).", resp->client_correlation_id, *current_fd);

			int target_sio_uds_fd = -1;
			for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
				if (master_ctx->sio_c_session[i].in_use && master_ctx->sio_c_session[i].correlation_id == resp->client_correlation_id) {
					target_sio_uds_fd = master_ctx->sio_c_session[i].sio_uds_fd;
					master_ctx->sio_c_session[i].in_use = false;
					master_ctx->sio_c_session[i].correlation_id = -1;
					master_ctx->sio_c_session[i].sio_uds_fd = -1;
					memset(master_ctx->sio_c_session[i].client_ip, 0, sizeof(master_ctx->sio_c_session[i].client_ip));
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
			int cow_uds_fd = master_ctx->master_uds_cow_fds[cow_worker_idx]; // Master uses its side of UDS

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
			int logic_worker_uds_fd = master_ctx->master_uds_logic_fds[logic_worker_idx_for_response]; // Master uses its side of UDS

			send_ipc_message(logic_worker_uds_fd, IPC_OUTBOUND_RESPONSE, resp, sizeof(outbound_response_t), -1);
			LOG_INFO("[Master]: Forwarding outbound response (ID %ld) to Logic Worker %d (UDS FD %d).",
				   resp->client_correlation_id, logic_worker_idx_for_response, logic_worker_uds_fd);
			break;
		}
		*/
		case IPC_CLIENT_DISCONNECTED: {
			ipc_client_disconnect_info_t *disconnect_info = received_protocol->payload.ipc_client_disconnect_info;
			add_master_sio_dc_session("[Master]: ", &master_ctx->sio_dc_session, disconnect_info->ip); 
			//cnt_connection -= (double_t)1;
			//avg_connection = cnt_connection / sio_worker;
			char ip_str[INET6_ADDRSTRLEN];
			convert_ipv6_bin_to_str(disconnect_info->ip, ip_str);
			LOG_INFO("[Master]: Received Client Disconnected signal from IP %s (from SIO Worker UDS FD %d).",
					 ip_str, *current_fd);
			for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
				if (master_ctx->sio_c_session[i].in_use &&
					memcmp(master_ctx->sio_c_session[i].ip, disconnect_info->ip, IP_ADDRESS_LEN) == 0) {
					master_ctx->sio_c_session[i].in_use = false;
					master_ctx->sio_c_session[i].sio_uds_fd = -1;
					memset(master_ctx->sio_c_session[i].ip, 0, IP_ADDRESS_LEN);
					LOG_INFO("[Master]: IP %s dihapus dari daftar koneksi aktif.",
							 ip_str);
					break;
				}
			}
			break;
		}
		default:
			LOG_ERROR("[Master]: Unknown message type %d from UDS FD %d. Ignoring.", received_protocol->type, *current_fd);
			break;
	}
	CLOSE_IPC_PROTOCOL(&received_protocol);
	return SUCCESS;
}
