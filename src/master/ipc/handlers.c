#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "log.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "types.h"
#include "master/master.h"
#include "master/ipc/handlers.h"

status_t handle_master_ipc_closed_event(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, int *file_descriptor) {
	const char *worker_name = get_master_worker_name(wot);
    LOG_DEBUG("%sWorker UDS FD %d (%s Worker %d) terputus.", label, *file_descriptor, worker_name, index);
	return SUCCESS;
}

status_t handle_master_ipc_event(const char *label, master_context_t *master_ctx, int *file_descriptor) {
    ipc_raw_protocol_t_status_t ircvdi = receive_ipc_raw_protocol_message(label, file_descriptor);
	if (ircvdi.status != SUCCESS) {
		LOG_ERROR("%srecv_ipc_message from worker. %s", label, strerror(errno));
		return ircvdi.status;
	}
    worker_type_t rcvd_wot = ircvdi.r_ipc_raw_protocol_t->wot;
    uint8_t rcvd_index = ircvdi.r_ipc_raw_protocol_t->index;
    master_worker_session_t *session = get_master_worker_session(master_ctx, rcvd_wot, rcvd_index);
    if (session == NULL) {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
    const char *worker_name = get_master_worker_name(rcvd_wot);
    worker_security_t *security = &session->security;
    worker_rekeying_t *rekeying = &session->rekeying;
    int *worker_uds_fd = &session->upp.uds[0];
    if (!security || !rekeying || *worker_uds_fd == -1) {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
    if (ipc_check_mac_ctr(
            label, 
            security->aes_key, 
            security->mac_key, 
            &security->remote_ctr, 
            ircvdi.r_ipc_raw_protocol_t
        ) != SUCCESS
    )
    {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
	switch (ircvdi.r_ipc_raw_protocol_t->type) {
        case IPC_WORKER_MASTER_HELLO1: {
            if (handle_master_ipc_hello1(label, master_ctx, rcvd_wot, rcvd_index, security, worker_name, worker_uds_fd, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
			break;
		}
        case IPC_WORKER_MASTER_HELLO2: {
            status_t rhello2 = handle_master_ipc_hello2(label, master_ctx, rcvd_wot, rcvd_index, security, rekeying, worker_name, worker_uds_fd, &ircvdi);
            if (rhello2 == SUCCESS_WRKSRDY) {
                return SUCCESS_WRKSRDY;
            }
            if (rhello2 != SUCCESS) {
                return FAILURE;
            }
			break;
		}
		case IPC_WORKER_MASTER_HEARTBEAT: {
            if (handle_master_ipc_heartbeat(label, master_ctx, rcvd_wot, rcvd_index, security, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
			break;
		}
        case IPC_UDP_DATA: {
            if (handle_master_ipc_udp_data(label, master_ctx, security, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
			break;
		}
        case IPC_WORKER_MASTER_TASK_INFO: {
            if (handle_master_ipc_task_info(label, master_ctx, rcvd_wot, rcvd_index, security, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
			break;
		}
		default:
			LOG_ERROR("%sUnknown IPC protocol type %d from UDS FD %d. Ignoring.", label, ircvdi.r_ipc_raw_protocol_t->type, *file_descriptor);
			CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
	}
	return SUCCESS;
}
