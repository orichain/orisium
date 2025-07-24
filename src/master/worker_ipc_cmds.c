#include "log.h"
#include "constants.h"
#include "types.h"
#include "master/process.h"
#include "ipc/protocol.h"
#include "ipc/master_worker_shutdown.h"
#include "ipc/master_cow_connect.h"

struct sockaddr_in6;

status_t broadcast_shutdown(master_context *master_ctx) {
	const char *label = "[Master]: ";
	for (int i = 0; i < MAX_SIO_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_shutdown(label);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}
		ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_ctx->sio[i].uds[0], cmd_result.r_ipc_protocol_t);
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent master_worker_shutdown to SIO %ld.", label, i);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
		} else {
			LOG_DEBUG("%sSent master_worker_shutdown to SIO %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	}
	for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_shutdown(label);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_ctx->logic[i].uds[0], cmd_result.r_ipc_protocol_t);
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent master_worker_shutdown to Logic %ld.", label, i);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
		} else {
			LOG_DEBUG("%sSent master_worker_shutdown to Logic %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
	for (int i = 0; i < MAX_COW_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_shutdown(label);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_ctx->cow[i].uds[0], cmd_result.r_ipc_protocol_t);
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent master_worker_shutdown to COW %ld.", label, i);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
		} else {
			LOG_DEBUG("%sSent master_worker_shutdown to COW %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
    for (int i = 0; i < MAX_DBR_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_shutdown(label);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_ctx->dbr[i].uds[0], cmd_result.r_ipc_protocol_t);
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent master_worker_shutdown to DBR %ld.", label, i);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
		} else {
			LOG_DEBUG("%sSent master_worker_shutdown to DBR %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
    for (int i = 0; i < MAX_DBW_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_shutdown(label);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_ctx->dbw[i].uds[0], cmd_result.r_ipc_protocol_t);
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent master_worker_shutdown to DBW %ld.", label, i);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
		} else {
			LOG_DEBUG("%sSent master_worker_shutdown to DBW %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
	return SUCCESS;
}

status_t cow_connect(master_context *master_ctx, struct sockaddr_in6 *addr, int index) {
	const char *label = "[Master]: ";
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_cow_connect(label, addr);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_ctx->cow[index].uds[0], cmd_result.r_ipc_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent master_cow_connect to COW %ld.", label, index);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sSent master_cow_connect to COW %ld.", label, index);
    }
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}
