#ifndef MASTER_IPC_WORKER_IPC_CMDS_H
#define MASTER_IPC_WORKER_IPC_CMDS_H

#include <stddef.h>
#include <stdint.h>

#include "orilink/protocol.h"
#include "log.h"
#include "constants.h"
#include "types.h"
#include "master/master.h"
#include "ipc.h"
#include "ipc/master_worker_info.h"
#include "ipc/master_worker_hello1_ack.h"
#include "ipc/master_worker_hello2_ack.h"
#include "ipc/master_cow_connect.h"
#include "stdbool.h"
#include "ipc/udp_data.h"
#include "ipc/udp_data_ack.h"
#include "ipc/protocol.h"
#include "ipc/worker_worker_info.h"

struct sockaddr_in6;
                        
static inline status_t master_worker_info(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, info_type_t flag) {
    master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) return FAILURE;
    worker_security_t *security = session->security;
    uds_pair_pid_t *upp = session->upp;
    worker_rekeying_t *rekeying = session->rekeying;
    et_buffer_t *buffer = session->buffer;
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_info(label, &master_ctx->oritlsf_pool, wot, index, flag);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (rekeying->is_rekeying) {
        if (ipc_add_tail_protocol_queue(label, &master_ctx->oritlsf_pool, wot, index, &upp->uds[0], buffer, cmd_result.r_ipc_protocol_t, &rekeying->rekeying_queue_head, &rekeying->rekeying_queue_tail) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            &master_ctx->oritlsf_pool, 
            security->aes_key,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr,
            &upp->uds[0], 
            buffer,
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent master_worker_info to worker.", label);
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
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
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
    }
	return SUCCESS;
}

static inline status_t master_workers_info(const char *label, master_context_t *master_ctx, info_type_t flag) {
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

static inline status_t master_cow_connect(const char *label, master_context_t *master_ctx, struct sockaddr_in6 *addr, uint8_t index, uint8_t session_index, uint64_t id_addr) {
    master_worker_session_t *session = &master_ctx->cow_session[index];
    worker_rekeying_t *rekeying = session->rekeying;
    if (!rekeying) return FAILURE;
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_cow_connect(label, &master_ctx->oritlsf_pool, COW, index, session_index, id_addr, addr);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (rekeying->is_rekeying) {
        if (ipc_add_tail_protocol_queue(label, &master_ctx->oritlsf_pool, COW, index, &master_ctx->cow_session[index].upp->uds[0], master_ctx->cow_session[index].buffer, cmd_result.r_ipc_protocol_t, &rekeying->rekeying_queue_head, &rekeying->rekeying_queue_tail) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            &master_ctx->oritlsf_pool, 
            master_ctx->cow_session[index].security->aes_key,
            master_ctx->cow_session[index].security->mac_key,
            master_ctx->cow_session[index].security->local_nonce,
            &master_ctx->cow_session[index].security->local_ctr,
            &master_ctx->cow_session[index].upp->uds[0], 
            master_ctx->cow_session[index].buffer,
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent master_cow_connect to COW %ld.", label, index);
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        } else {
            LOG_DEBUG("%sSent master_cow_connect to COW %ld.", label, index);
        }
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t); 
    }
	return SUCCESS;
}

static inline status_t master_worker_hello1_ack(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, uint8_t local_nonce[]) {
    if (!security || *worker_uds_fd == -1) return FAILURE;
    master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) return FAILURE;
    et_buffer_t *buffer = session->buffer;
    uint8_t *kem_ciphertext = security->kem_ciphertext;
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_hello1_ack(
        label, 
        &master_ctx->oritlsf_pool, 
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
        &master_ctx->oritlsf_pool, 
        security->aes_key,
        security->mac_key,
        security->local_nonce,
        &security->local_ctr,
        worker_uds_fd, 
        buffer,
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent master_worker_hello1_ack to %s %ld.", label, worker_name, index);
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sSent master_worker_hello1_ack to %s %ld.", label, worker_name, index);
    }
    security->hello1_ack_sent = true;
    CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}

static inline status_t master_worker_hello2_ack(const char *label, master_context_t *master_ctx, worker_type_t wot, int index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, uint8_t encrypted_wot_index1[]) {
    if (!security || *worker_uds_fd == -1) return FAILURE;
    master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) return FAILURE;
    et_buffer_t *buffer = session->buffer;
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_master_worker_hello2_ack(
        label, 
        &master_ctx->oritlsf_pool, 
        wot,
        index,
        encrypted_wot_index1
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        label, 
        &master_ctx->oritlsf_pool, 
        security->aes_key,
        security->mac_key,
        security->local_nonce,
        &security->local_ctr,
        worker_uds_fd, 
        buffer,
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent master_worker_hello2_ack to %s %ld.", label, worker_name, index);
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sSent master_worker_hello2_ack to %s %ld.", label, worker_name, index);
    }
    security->hello2_ack_sent = true;
    CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}

static inline status_t master_worker_udp_data(
    const char *label, 
    master_context_t *master_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol, 
    uint8_t trycount,
    struct sockaddr_in6 *addr,
    orilink_raw_protocol_t *r
) 
{
    master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) return FAILURE;
    worker_rekeying_t *rekeying = session->rekeying;
    uds_pair_pid_t *upp = session->upp;
    et_buffer_t *buffer = session->buffer;
    worker_security_t *security = session->security;
    const char *worker_name = "UNKNOWN";
    worker_name = get_worker_name(wot);
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data(
        label,
        &master_ctx->oritlsf_pool, 
        r->local_wot,
        r->local_index,
        session_index,
        orilink_protocol,
        trycount,
        addr,
        r->n,
        r->recv_buffer
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (rekeying->is_rekeying) {
        if (ipc_add_tail_protocol_queue(label, &master_ctx->oritlsf_pool, wot, index, &upp->uds[0], buffer, cmd_result.r_ipc_protocol_t, &rekeying->rekeying_queue_head, &rekeying->rekeying_queue_tail) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            &master_ctx->oritlsf_pool, 
            security->aes_key,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr,
            &upp->uds[0], 
            buffer,
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent udp_data to %s.", label, worker_name);
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        } else {
            LOG_DEBUG("%sSent udp_data to %s.", label, worker_name);
        }
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

static inline status_t master_worker_udp_data_ack(
    const char *label, 
    master_context_t *master_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol,
    uint8_t trycount,
    status_t status
) 
{
    master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) return FAILURE;
    worker_rekeying_t *rekeying = session->rekeying;
    uds_pair_pid_t *upp = session->upp;
    et_buffer_t *buffer = session->buffer;
    worker_security_t *security = session->security;
    const char *worker_name = "UNKNOWN";
    worker_name = get_worker_name(wot);
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data_ack(
        label,
        &master_ctx->oritlsf_pool, 
        wot,
        index,
        session_index,
        orilink_protocol,
        trycount,
        status
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (rekeying->is_rekeying) {
        if (ipc_add_tail_protocol_queue(label, &master_ctx->oritlsf_pool, wot, index, &upp->uds[0], buffer, cmd_result.r_ipc_protocol_t, &rekeying->rekeying_queue_head, &rekeying->rekeying_queue_tail) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            &master_ctx->oritlsf_pool, 
            security->aes_key,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr,
            &upp->uds[0], 
            buffer,
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent udp_data to %s.", label, worker_name);
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        } else {
            LOG_DEBUG("%sSent udp_data to %s.", label, worker_name);
        }
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

static inline status_t relay_worker_master_worker_info(
	const char *label, 
    master_context_t *master_ctx, 
    worker_type_t wot, 
    uint8_t index,
    worker_type_t src_wot, 
	uint8_t src_index,
	info_type_t flag
)
{
	master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) return FAILURE;
    worker_rekeying_t *rekeying = session->rekeying;
    uds_pair_pid_t *upp = session->upp;
    et_buffer_t *buffer = session->buffer;
    worker_security_t *security = session->security;
    const char *worker_name = "UNKNOWN";
    worker_name = get_worker_name(wot);
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_worker_info(
        label,
        &master_ctx->oritlsf_pool, 
        wot, 
        index, 
        src_wot,
        src_index, 
        0xff,
        wot,
        index,
        0xff,
        flag
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (rekeying->is_rekeying) {
		if (ipc_add_tail_protocol_queue(label, &master_ctx->oritlsf_pool, wot, index, &upp->uds[0], buffer, cmd_result.r_ipc_protocol_t, &rekeying->rekeying_queue_head, &rekeying->rekeying_queue_tail) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
	} else {
		ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            &master_ctx->oritlsf_pool, 
            security->aes_key,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr,
            &upp->uds[0], 
            buffer,
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent relay_worker_master_worker_info to %s.", label, worker_name);
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        } else {
            LOG_DEBUG("%sSent relay_worker_master_worker_info to %s.", label, worker_name);
        }
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
	}
    return SUCCESS;
}

#endif
