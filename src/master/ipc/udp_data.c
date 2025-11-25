#include <string.h>
#include <stdint.h>

#include "log.h"
#include "ipc.h"
#include "types.h"
#include "master/master.h"
#include "master/ipc/handlers.h"
#include "master/ipc/worker_ipc_cmds.h"
#include "orilink.h"
#include "ipc/protocol.h"
#include "oritlsf.h"

status_t handle_master_ipc_udp_data(const char *label, master_context_t *master_ctx, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi) {
    worker_type_t rcvd_wot = ircvdi->r_ipc_raw_protocol_t->wot;
    uint8_t rcvd_index = ircvdi->r_ipc_raw_protocol_t->index;
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(label, &master_ctx->oritlsf_pool,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &ircvdi->r_ipc_raw_protocol_t);
        return deserialized_ircvdi.status;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
        CLOSE_IPC_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_udp_data_t *iudpi = received_protocol->payload.ipc_udp_data;
    p8zs_t *orpp = (p8zs_t *)oritlsf_calloc(__FILE__, __LINE__, &master_ctx->oritlsf_pool, 1, sizeof(p8zs_t));
    if (!orpp) {
        LOG_ERROR("%sFailed to preparing send_orilink_raw_protocol_packet.", label);
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
        return FAILURE_NOMEM;
    }
    orpp->data = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, &master_ctx->oritlsf_pool, 1, iudpi->len);
    if (!orpp->data) {
        LOG_ERROR("%sFailed to preparing send_orilink_raw_protocol_packet.", label);
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
        return FAILURE_NOMEM;
    }
    orpp->len = iudpi->len;
    orpp->status = SUCCESS;
    memcpy(orpp->data, iudpi->data, iudpi->len);
    uint8_t session_index = iudpi->session_index;
    uint8_t orilink_protocol = iudpi->orilink_protocol;
    uint8_t trycount = iudpi->trycount;
    ssize_t_status_t send_result = send_orilink_raw_protocol_packet(
        label,
        &master_ctx->oritlsf_pool,
        &orpp,
        &master_ctx->udp_sock,
        &iudpi->remote_addr
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to send_orilink_raw_protocol_packet.", label);
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
        master_worker_udp_data_ack(
            label, 
            master_ctx, 
            rcvd_wot, 
            rcvd_index,
            session_index,
            orilink_protocol,
            trycount,
            FAILURE
        );
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent send_orilink_raw_protocol_packet.", label);
    }
    CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
    master_worker_udp_data_ack(
        label, 
        master_ctx, 
        rcvd_wot, 
        rcvd_index,
        session_index,
        orilink_protocol,
        trycount,
        SUCCESS
    );
    return SUCCESS;
}
