#include "log.h"
#include "types.h"
#include "ipc/protocol.h"
#include "ipc/worker_master_heartbeat.h"

status_t master_heartbeat(const char *label, worker_type_t wot, int worker_idx, double new_heartbeat_interval_double, int *master_uds_fd) {
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
