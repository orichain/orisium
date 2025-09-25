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

worker_type_t_status_t handle_master_ipc_closed_event(const char *label, master_context_t *master_ctx, int *current_fd) {
	worker_type_t_status_t result;
	result.r_worker_type_t = UNKNOWN;
	result.status = FAILURE;
	result.index = (uint8_t)0xff;
    const char* worker_name = "UNKNOWN";
    bool is_worker_uds_closing = false;

    for (uint8_t i = 0; i < MAX_SIO_WORKERS; ++i) {
        master_sio_session_t *session = &master_ctx->sio_session[i];
        if (*current_fd == session->upp.uds[0]) {
            session->isactive = false;
            is_worker_uds_closing = true;
            result.r_worker_type_t = SIO;
            worker_name = "SIO";
            result.index = i;
            break;
        }
    }
    if (!is_worker_uds_closing) {
        for (uint8_t i = 0; i < MAX_LOGIC_WORKERS; ++i) {
            master_logic_session_t *session = &master_ctx->logic_session[i];
            if (*current_fd == session->upp.uds[0]) {
                session->isactive = false;
                is_worker_uds_closing = true;
                result.r_worker_type_t = LOGIC;
                worker_name = "Logic";
                result.index = i;
                break;
            }
        }
    }
    if (!is_worker_uds_closing) {
        for (uint8_t i = 0; i < MAX_COW_WORKERS; ++i) {
            master_cow_session_t *session = &master_ctx->cow_session[i];
            if (*current_fd == session->upp.uds[0]) {
                session->isactive = false;
                is_worker_uds_closing = true;
                result.r_worker_type_t = COW;
                worker_name = "COW";
                result.index = i;
                break;
            }
        }
    }
    if (!is_worker_uds_closing) {
        for (uint8_t i = 0; i < MAX_DBR_WORKERS; ++i) {
            master_dbr_session_t *session = &master_ctx->dbr_session[i];
            if (*current_fd == session->upp.uds[0]) {
                session->isactive = false;
                is_worker_uds_closing = true;
                result.r_worker_type_t = DBR;
                worker_name = "DBR";
                result.index = i;
                break;
            }
        }
    }
    if (!is_worker_uds_closing) {
        for (uint8_t i = 0; i < MAX_DBW_WORKERS; ++i) {
            master_dbw_session_t *session = &master_ctx->dbw_session[i];
            if (*current_fd == session->upp.uds[0]) {
                session->isactive = false;
                is_worker_uds_closing = true;
                result.r_worker_type_t = DBW;
                worker_name = "DBW";
                result.index = i;
                break;
            }
        }
    }
    if (is_worker_uds_closing) {
		LOG_DEBUG("%sWorker UDS FD %d (%s Worker %d) terputus.", label, *current_fd, worker_name, result.index);
        result.status = SUCCESS;			
		return result;
	}
	return result;
}

status_t handle_master_ipc_event(const char *label, master_context_t *master_ctx, int *current_fd) {
    ipc_raw_protocol_t_status_t ircvdi = receive_ipc_raw_protocol_message(label, current_fd);
	if (ircvdi.status != SUCCESS) {
		LOG_ERROR("%srecv_ipc_message from worker. %s", label, strerror(errno));
		return ircvdi.status;
	}
    worker_security_t *security = NULL;
    worker_rekeying_t *rekeying = NULL;
    const char *worker_name = "Unknown";
    int *worker_uds_fd = NULL;
    worker_type_t rcvd_wot = ircvdi.r_ipc_raw_protocol_t->wot;
    uint8_t rcvd_index = ircvdi.r_ipc_raw_protocol_t->index;
    if (rcvd_wot == SIO) {
        security = &master_ctx->sio_session[rcvd_index].security;
        rekeying = &master_ctx->sio_session[rcvd_index].rekeying;
        worker_uds_fd = &master_ctx->sio_session[rcvd_index].upp.uds[0];
        worker_name = "SIO";
    } else if (rcvd_wot == LOGIC) {
        security = &master_ctx->logic_session[rcvd_index].security;
        rekeying = &master_ctx->logic_session[rcvd_index].rekeying;
        worker_uds_fd = &master_ctx->logic_session[rcvd_index].upp.uds[0];
        worker_name = "Logic";
    } else if (rcvd_wot == COW) {
        security = &master_ctx->cow_session[rcvd_index].security;
        rekeying = &master_ctx->cow_session[rcvd_index].rekeying;
        worker_uds_fd = &master_ctx->cow_session[rcvd_index].upp.uds[0];
        worker_name = "COW";
    } else if (rcvd_wot == DBR) {
        security = &master_ctx->dbr_session[rcvd_index].security;
        rekeying = &master_ctx->dbr_session[rcvd_index].rekeying;
        worker_uds_fd = &master_ctx->dbr_session[rcvd_index].upp.uds[0];
        worker_name = "DBR";
    } else if (rcvd_wot == DBW) {
        security = &master_ctx->dbw_session[rcvd_index].security;
        rekeying = &master_ctx->dbw_session[rcvd_index].rekeying;
        worker_uds_fd = &master_ctx->dbw_session[rcvd_index].upp.uds[0];
        worker_name = "DBW";
    } else {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
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
			LOG_ERROR("%sUnknown IPC protocol type %d from UDS FD %d. Ignoring.", label, ircvdi.r_ipc_raw_protocol_t->type, *current_fd);
			CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
	}
	return SUCCESS;
}
