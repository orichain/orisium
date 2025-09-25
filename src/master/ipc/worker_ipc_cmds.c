#include <stddef.h>
#include <stdint.h>

#include "log.h"
#include "constants.h"
#include "types.h"
#include "master/master.h"
#include "ipc/protocol.h"
#include "ipc/master_worker_info.h"
#include "ipc/master_worker_hello1_ack.h"
#include "ipc/master_worker_hello2_ack.h"
#include "ipc/master_cow_connect.h"
#include "stdbool.h"
#include "ipc/udp_data.h"
#include "orilink/protocol.h"
#include "utilities.h"

struct sockaddr_in6;
                        
status_t master_worker_info(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, info_type_t flag) {
    worker_security_t * security = NULL;
    uds_pair_pid_t *upp = NULL;
    worker_rekeying_t *rekeying = NULL;
    if (wot == SIO) {
        master_sio_session_t *session = &master_ctx->sio_session[index];
        rekeying = &session->rekeying;
        security = &session->security;
        upp = &session->upp;
    } else if (wot == LOGIC) {
        master_logic_session_t *session = &master_ctx->logic_session[index];
        rekeying = &session->rekeying;
        security = &session->security;
        upp = &session->upp;
    } else if (wot == COW) {
        master_cow_session_t *session = &master_ctx->cow_session[index];
        rekeying = &session->rekeying;
        security = &session->security;
        upp = &session->upp;
    } else if (wot == DBR) {
        master_dbr_session_t *session = &master_ctx->dbr_session[index];
        rekeying = &session->rekeying;
        security = &session->security;
        upp = &session->upp;
    } else if (wot == DBW) {
        master_dbw_session_t *session = &master_ctx->dbw_session[index];
        rekeying = &session->rekeying;
        security = &session->security;
        upp = &session->upp;
    } else {
        return FAILURE;
    }
    if (!rekeying || !security || !upp) return FAILURE;
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_info(label, wot, index, flag);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (rekeying->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(label, &queue_id) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(label, queue_id, wot, index, &upp->uds[0], cmd_result.r_ipc_protocol_t, &rekeying->rekeying_queue) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            security->aes_key,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr,
            &upp->uds[0], 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent master_worker_info to worker.", label);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        } else {
            LOG_DEBUG("%sSent master_worker_info to worker.", label);
        }
        if (flag == IT_REKEYING) {
            rekeying->is_rekeying = true;
            security->hello1_rcvd = false;
            security->hello1_ack_sent = false;
            security->hello2_rcvd = false;
            security->hello2_ack_sent = false;
        }
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    }
	return SUCCESS;
}

status_t master_workers_info(const char *label, master_context_t *master_ctx, info_type_t flag) {
	for (uint8_t i = 0; i < MAX_SIO_WORKERS; ++i) { 
		if (master_worker_info(label, master_ctx, SIO, i, flag) != SUCCESS) return FAILURE;
	}
	for (uint8_t i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		if (master_worker_info(label, master_ctx, LOGIC, i, flag) != SUCCESS) return FAILURE;
	}
	for (uint8_t i = 0; i < MAX_COW_WORKERS; ++i) { 
		if (master_worker_info(label, master_ctx, COW, i, flag) != SUCCESS) return FAILURE;
	}
    for (uint8_t i = 0; i < MAX_DBR_WORKERS; ++i) { 
		if (master_worker_info(label, master_ctx, DBR, i, flag) != SUCCESS) return FAILURE;
	}
    for (uint8_t i = 0; i < MAX_DBW_WORKERS; ++i) { 
		if (master_worker_info(label, master_ctx, DBW, i, flag) != SUCCESS) return FAILURE;
	}
	return SUCCESS;
}

status_t master_cow_connect(const char *label, master_context_t *master_ctx, struct sockaddr_in6 *addr, uint8_t index, uint8_t session_index, uint64_t id_addr) {
    master_cow_session_t *session = &master_ctx->cow_session[index];
    worker_rekeying_t *rekeying = &session->rekeying;
    if (!rekeying) return FAILURE;
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_cow_connect(label, COW, index, session_index, id_addr, addr);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (rekeying->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(label, &queue_id) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(label, queue_id, COW, index, &master_ctx->cow_session[index].upp.uds[0], cmd_result.r_ipc_protocol_t, &rekeying->rekeying_queue) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            master_ctx->cow_session[index].security.aes_key,
            master_ctx->cow_session[index].security.mac_key,
            master_ctx->cow_session[index].security.local_nonce,
            &master_ctx->cow_session[index].security.local_ctr,
            &master_ctx->cow_session[index].upp.uds[0], 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent master_cow_connect to COW %ld.", label, index);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        } else {
            LOG_DEBUG("%sSent master_cow_connect to COW %ld.", label, index);
        }
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
    }
	return SUCCESS;
}

status_t master_worker_hello1_ack(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, uint8_t local_nonce[]) {
    if (!security || *worker_uds_fd == -1) return FAILURE;
    uint8_t *kem_ciphertext = security->kem_ciphertext;
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_hello1_ack(
        label, 
        wot, 
        index, 
        local_nonce,
        kem_ciphertext
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        label, 
        security->aes_key,
        security->mac_key,
        security->local_nonce,
        &security->local_ctr,
        worker_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent master_worker_hello1_ack to %s %ld.", label, worker_name, index);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sSent master_worker_hello1_ack to %s %ld.", label, worker_name, index);
    }
    security->hello1_ack_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}

status_t master_worker_hello2_ack(const char *label, master_context_t *master_ctx, worker_type_t wot, int index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, uint8_t encrypted_wot_index1[]) {
    if (!security || *worker_uds_fd == -1) return FAILURE;
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_hello2_ack(
        label, 
        wot,
        index,
        encrypted_wot_index1
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        label, 
        security->aes_key,
        security->mac_key,
        security->local_nonce,
        &security->local_ctr,
        worker_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent master_worker_hello2_ack to %s %ld.", label, worker_name, index);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sSent master_worker_hello2_ack to %s %ld.", label, worker_name, index);
    }
    security->hello2_ack_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}

status_t master_worker_udp_data(
    const char *label, 
    master_context_t *master_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    struct sockaddr_in6 *addr,
    orilink_raw_protocol_t *r
) 
{
    worker_rekeying_t *rekeying = NULL;
    if (wot == SIO) {
        master_sio_session_t *session = &master_ctx->sio_session[index];
        rekeying = &session->rekeying;
    } else if (wot == LOGIC) {
        master_logic_session_t *session = &master_ctx->logic_session[index];
        rekeying = &session->rekeying;
    } else if (wot == COW) {
        master_cow_session_t *session = &master_ctx->cow_session[index];
        rekeying = &session->rekeying;
    } else if (wot == DBR) {
        master_dbr_session_t *session = &master_ctx->dbr_session[index];
        rekeying = &session->rekeying;
    } else if (wot == DBW) {
        master_dbw_session_t *session = &master_ctx->dbw_session[index];
        rekeying = &session->rekeying;
    } else {
        return FAILURE;
    }
    if (!rekeying) return FAILURE;
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data(
        label,
        r->local_wot,
        r->local_index,
        session_index,
        addr,
        r->n,
        r->recv_buffer
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (rekeying->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(label, &queue_id) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        uds_pair_pid_t *upp = NULL;
        switch (wot) {
            case SIO: {
                upp = &master_ctx->sio_session[index].upp;
                break;
            }
            case COW: {
                upp = &master_ctx->cow_session[index].upp;
                break;
            }
            default:
                LOG_ERROR("%sFailed to sent udp_data to Worker.", label);
                CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
                return FAILURE;
        }
        if (upp == NULL) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(label, queue_id, wot, index, &upp->uds[0], cmd_result.r_ipc_protocol_t, &rekeying->rekeying_queue) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        worker_security_t *security = NULL;
        uds_pair_pid_t *upp = NULL;
        const char* worker_name = "UNKNOWN";
        switch (wot) {
            case SIO: {
                security = &master_ctx->sio_session[index].security;
                upp = &master_ctx->sio_session[index].upp;
                worker_name = "SIO";
                break;
            }
            case COW: {
                security = &master_ctx->cow_session[index].security;
                upp = &master_ctx->cow_session[index].upp;
                worker_name = "COW";
                break;
            }
            default:
                LOG_ERROR("%sFailed to sent udp_data to Worker.", label);
                CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
                return FAILURE;
        }
        if (security == NULL || upp == NULL) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            security->aes_key,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr,
            &upp->uds[0], 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent udp_data to %s.", label, worker_name);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        } else {
            LOG_DEBUG("%sSent udp_data to %s.", label, worker_name);
        }
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}
