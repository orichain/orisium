#include <stdint.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "utilities.h"
#include "master/master.h"
#include "master/ipc/handlers.h"

status_t handle_master_ipc_heartbeat(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, int rcvd_index, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi) {
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
    ipc_worker_master_heartbeat_t *iheartbeati = received_protocol->payload.ipc_worker_master_heartbeat;
    uint64_t_status_t rt = get_realtime_time_ns(label);
    if (rcvd_wot == SIO) {
        LOG_DEBUG("%sSIO %d set last_ack to %llu.", label, rcvd_index, rt.r_uint64_t);
        master_ctx->sio_session[rcvd_index].metrics.last_ack = rt.r_uint64_t;
        master_ctx->sio_session[rcvd_index].metrics.count_ack += (double)1;
        master_ctx->sio_session[rcvd_index].metrics.sum_hbtime += iheartbeati->hbtime;
        master_ctx->sio_session[rcvd_index].metrics.hbtime = iheartbeati->hbtime;
    } else if (rcvd_wot == LOGIC) {
        LOG_DEBUG("%sLogic %d set last_ack to %llu.", label, rcvd_index, rt.r_uint64_t);
        master_ctx->logic_session[rcvd_index].metrics.last_ack = rt.r_uint64_t;
        master_ctx->logic_session[rcvd_index].metrics.count_ack += (double)1;
        master_ctx->logic_session[rcvd_index].metrics.sum_hbtime += iheartbeati->hbtime;
        master_ctx->logic_session[rcvd_index].metrics.hbtime = iheartbeati->hbtime;
    } else if (rcvd_wot == COW) {
        LOG_DEBUG("%sCOW %d set last_ack to %llu.", label, rcvd_index, rt.r_uint64_t);
        master_ctx->cow_session[rcvd_index].metrics.last_ack = rt.r_uint64_t;
        master_ctx->cow_session[rcvd_index].metrics.count_ack += (double)1;
        master_ctx->cow_session[rcvd_index].metrics.sum_hbtime += iheartbeati->hbtime;
        master_ctx->cow_session[rcvd_index].metrics.hbtime = iheartbeati->hbtime;
    } else if (rcvd_wot == DBR) {
        LOG_DEBUG("%sDBR %d set last_ack to %llu.", label, rcvd_index, rt.r_uint64_t);
        master_ctx->dbr_session[rcvd_index].metrics.last_ack = rt.r_uint64_t;
        master_ctx->dbr_session[rcvd_index].metrics.count_ack += (double)1;
        master_ctx->dbr_session[rcvd_index].metrics.sum_hbtime += iheartbeati->hbtime;
        master_ctx->dbr_session[rcvd_index].metrics.hbtime = iheartbeati->hbtime;
    } else if (rcvd_wot == DBW) {
        LOG_DEBUG("%sDBW %d set last_ack to %llu.", label, rcvd_index, rt.r_uint64_t);
        master_ctx->dbw_session[rcvd_index].metrics.last_ack = rt.r_uint64_t;
        master_ctx->dbw_session[rcvd_index].metrics.count_ack += (double)1;
        master_ctx->dbw_session[rcvd_index].metrics.sum_hbtime += iheartbeati->hbtime;
        master_ctx->dbw_session[rcvd_index].metrics.hbtime = iheartbeati->hbtime;
    } else {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    CLOSE_IPC_PROTOCOL(&received_protocol);
    return SUCCESS;
}
