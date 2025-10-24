#include <stdint.h>
#include <stddef.h>

#include "log.h"
#include "ipc.h"
#include "types.h"
#include "utilities.h"
#include "master/master.h"
#include "master/ipc/handlers.h"
#include "ipc/protocol.h"

status_t handle_master_ipc_heartbeat(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi) {
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(label,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    master_worker_session_t *session = get_master_worker_session(master_ctx, rcvd_wot, rcvd_index);
    if (session == NULL) {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    }
    const char *worker_name = get_master_worker_name(rcvd_wot);
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return deserialized_ircvdi.status;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_worker_master_heartbeat_t *iheartbeati = received_protocol->payload.ipc_worker_master_heartbeat;
    uint64_t_status_t rt = get_monotonic_time_ns(label);
    LOG_DEBUG("%s%s %d set last_ack to %llu.", label, worker_name, rcvd_index, rt.r_uint64_t);
    session->metrics.last_ack = rt.r_uint64_t;
    session->metrics.count_ack += (double)1;
    session->metrics.sum_hb_interval += iheartbeati->hb_interval;
    session->metrics.hb_interval = iheartbeati->hb_interval;
    CLOSE_IPC_PROTOCOL(&received_protocol);
    return SUCCESS;
}
