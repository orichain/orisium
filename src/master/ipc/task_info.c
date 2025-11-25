#include <stdint.h>

#include "log.h"
#include "ipc.h"
#include "types.h"
#include "master/master.h"
#include "master/master_workers.h"
#include "master/ipc/handlers.h"
#include "constants.h"
#include "stdbool.h"
#include "ipc/protocol.h"

status_t handle_master_ipc_task_info(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi) {
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
    ipc_worker_master_task_info_t *itask_infoi = received_protocol->payload.ipc_worker_master_task_info;
    switch (itask_infoi->flag) {
        case TIT_TIMEOUT: {
            if (calculate_avgtt(label, master_ctx, rcvd_wot, rcvd_index) != SUCCESS) {
                CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
                return FAILURE;
            }
            switch (rcvd_wot) {
                case SIO: {
                    master_ctx->sio_c_session[(rcvd_index * MAX_CONNECTION_PER_SIO_WORKER) + itask_infoi->session_index].sio_index = 0xff;
                    master_ctx->sio_c_session[(rcvd_index * MAX_CONNECTION_PER_SIO_WORKER) + itask_infoi->session_index].in_use = false;
                    master_ctx->sio_c_session[(rcvd_index * MAX_CONNECTION_PER_SIO_WORKER) + itask_infoi->session_index].in_secure = false;
                    break;
                }
                case COW: {
                    master_ctx->cow_c_session[(rcvd_index * MAX_CONNECTION_PER_COW_WORKER) + itask_infoi->session_index].cow_index = 0xff;
                    master_ctx->cow_c_session[(rcvd_index * MAX_CONNECTION_PER_COW_WORKER) + itask_infoi->session_index].in_use = false;
                    master_ctx->cow_c_session[(rcvd_index * MAX_CONNECTION_PER_COW_WORKER) + itask_infoi->session_index].in_secure = false;
                    break;
                }
                default:
                    CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
                    return FAILURE;
            }
            break;
        }
        case TIT_SECURE: {
            switch (rcvd_wot) {
                case SIO: {
                    master_ctx->sio_c_session[(rcvd_index * MAX_CONNECTION_PER_SIO_WORKER) + itask_infoi->session_index].in_secure = true;
                    break;
                }
                case COW: {
                    master_ctx->cow_c_session[(rcvd_index * MAX_CONNECTION_PER_COW_WORKER) + itask_infoi->session_index].in_secure = true;
                    break;
                }
                default:
                    CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
                    return FAILURE;
            }
            break;
        }
        case TIT_WAKEUP: {
            LOG_INFO("%sTIT_WAKEUP received...", label);
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
            break;
        }
        default:
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
            return FAILURE;
    }
    CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
    return SUCCESS;
}
