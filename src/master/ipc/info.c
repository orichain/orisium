#include <stdint.h>

#include "log.h"
#include "ipc.h"
#include "types.h"
#include "master/master.h"
#include "master/master_workers.h"
#include "master/master_worker_selector.h"
#include "master/master_worker_metrics.h"
#include "master/ipc/worker_ipc_cmds.h"
#include "master/ipc/handlers.h"
#include "constants.h"
#include "stdbool.h"
#include "ipc/protocol.h"

status_t handle_master_ipc_info(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi) {
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
    ipc_worker_master_info_t *iinfoi = received_protocol->payload.ipc_worker_master_info;
    switch (iinfoi->flag) {
        case IT_TIMEOUT: {
            if (calculate_avgtt(label, master_ctx, rcvd_wot, rcvd_index) != SUCCESS) {
                CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
                return FAILURE;
            }
            switch (rcvd_wot) {
                case SIO: {
                    master_ctx->sio_c_session[(rcvd_index * MAX_CONNECTION_PER_SIO_WORKER) + iinfoi->session_index].sio_index = 0xff;
                    master_ctx->sio_c_session[(rcvd_index * MAX_CONNECTION_PER_SIO_WORKER) + iinfoi->session_index].in_use = false;
                    master_ctx->sio_c_session[(rcvd_index * MAX_CONNECTION_PER_SIO_WORKER) + iinfoi->session_index].in_secure = false;
                    break;
                }
                case COW: {
                    master_ctx->cow_c_session[(rcvd_index * MAX_CONNECTION_PER_COW_WORKER) + iinfoi->session_index].cow_index = 0xff;
                    master_ctx->cow_c_session[(rcvd_index * MAX_CONNECTION_PER_COW_WORKER) + iinfoi->session_index].in_use = false;
                    master_ctx->cow_c_session[(rcvd_index * MAX_CONNECTION_PER_COW_WORKER) + iinfoi->session_index].in_secure = false;
                    break;
                }
                default:
                    CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
                    return FAILURE;
            }
            break;
        }
        case IT_SECURE: {
            switch (rcvd_wot) {
                case SIO: {
                    master_ctx->sio_c_session[(rcvd_index * MAX_CONNECTION_PER_SIO_WORKER) + iinfoi->session_index].in_secure = true;
                    break;
                }
                case COW: {
                    master_ctx->cow_c_session[(rcvd_index * MAX_CONNECTION_PER_COW_WORKER) + iinfoi->session_index].in_secure = true;
                    break;
                }
                default:
                    CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
                    return FAILURE;
            }
            break;
        }
        case IT_WAKEUP: {
            LOG_INFO("%sIT_WAKEUP received...", label);
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
            break;
        }
        default:
			LOG_ERROR("%sUnknown info flag %d. Ignoring.", label, iinfoi->flag);
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
            return FAILURE;
    }
    CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
    return SUCCESS;
}

status_t handle_worker_ipc_info(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi) {
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
    ipc_worker_worker_info_t *iinfoi = received_protocol->payload.ipc_worker_worker_info;
    switch (iinfoi->flag) {
        case IT_RNIDTY: {
            if (calculate_avgtt(label, master_ctx, rcvd_wot, rcvd_index) != SUCCESS) {
                CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
                return FAILURE;
            }
            uint8_t worker_index = select_best_worker(label, master_ctx, DBR);
			if (worker_index == 0xff) {
				LOG_ERROR("%sFailed to select an DBR worker for new task. Initiating graceful shutdown...", label);
				master_ctx->shutdown_requested = 1;
				master_workers_info(label, master_ctx, IT_SHUTDOWN);
				CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
                return FAILURE;
			}
			if (new_task_metrics(label, master_ctx, DBR, worker_index) != SUCCESS) {
				LOG_ERROR("%sFailed to input new task in DBR %d metrics. Initiating graceful shutdown...", label, worker_index);
				master_ctx->shutdown_requested = 1;
				master_workers_info(label, master_ctx, IT_SHUTDOWN);
				CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
                return FAILURE;
			}
			if (logic_master_dbr_read_node_identity(
					label, 
					master_ctx, 
					DBR, 
					worker_index, 
					iinfoi->src_index,
					IT_RNIDTY
				) != SUCCESS
			)
			{
				LOG_ERROR("%sFailed to infoing IT_RNIDTY to DBR %d. Initiating graceful shutdown...", label, worker_index);
				master_ctx->shutdown_requested = 1;
				master_workers_info(label, master_ctx, IT_SHUTDOWN);
				return FAILURE;
			}
            break;
        }
        default:
			LOG_ERROR("%sUnknown info flag %d. Ignoring.", label, iinfoi->flag);
            CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
            return FAILURE;
    }
    CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
    return SUCCESS;
}
