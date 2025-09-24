#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "master/master.h"
#include "master/ipc/handlers.h"
#include "orilink/protocol.h"

status_t handle_master_ipc_udp_data(const char *label, master_context_t *master_ctx, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi) {
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(label,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return deserialized_ircvdi.status;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_udp_data_t *iudpi = received_protocol->payload.ipc_udp_data;
    puint8_t_size_t_status_t orpp;
    orpp.status = SUCCESS;
    orpp.r_size_t = iudpi->len;
    orpp.r_puint8_t = (uint8_t *)calloc(1, iudpi->len);
    memcpy(orpp.r_puint8_t, iudpi->data, iudpi->len);
    ssize_t_status_t send_result = send_orilink_raw_protocol_packet(
        label,
        &orpp,
        &master_ctx->udp_sock,
        &iudpi->remote_addr
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to send_orilink_raw_protocol_packet.", label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent send_orilink_raw_protocol_packet.", label);
    }
    CLOSE_IPC_PROTOCOL(&received_protocol);
    return SUCCESS;
}
