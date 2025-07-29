#include <stdint.h>

#include "log.h"
#include "types.h"
#include "ipc/protocol.h"
#include "ipc/worker_master_heartbeat.h"
#include "ipc/worker_master_hello1.h"
#include "ipc/cow_master_connection.h"

struct sockaddr_in6;

status_t worker_master_heartbeat(const char *label, worker_type_t wot, int worker_idx, double new_heartbeat_interval_double, int *master_uds_fd) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_heartbeat(label, wot, worker_idx, new_heartbeat_interval_double);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(label, master_uds_fd, cmd_result.r_ipc_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_heartbeat to Master.", label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_heartbeat to Master.", label);
    }
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t worker_master_hello1(const char *label, worker_type_t wot, int worker_idx, uint8_t *kem_publickey, int *master_uds_fd) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello1(label, wot, worker_idx, kem_publickey);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(label, master_uds_fd, cmd_result.r_ipc_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_hello1 to Master.", label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_hello1 to Master.", label);
    }
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t cow_master_connection(const char *label, worker_type_t wot, int worker_idx, struct sockaddr_in6 *addr, connection_type_t flag, int *master_uds_fd) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_cow_master_connection(label, wot, worker_idx, addr, flag);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(label, master_uds_fd, cmd_result.r_ipc_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent cow_master_connection to master.", label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent cow_master_connection to master.", label);
    }
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}
