#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#include "log.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "types.h"
#include "utilities.h"
#include "master/ipc.h"
#include "master/process.h"
#include "master/worker_metrics.h"

worker_type_t_status_t handle_ipc_closed_event(const char *label, master_context *master_ctx, int *current_fd) {
	worker_type_t_status_t result;
	result.r_worker_type_t = UNKNOWN;
	result.status = FAILURE;
	result.index = -1;
    const char* worker_name = "Unknown";
    bool is_worker_uds = false;

    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        if (*current_fd == master_ctx->sio_session[i].upp.uds[0]) {
            is_worker_uds = true;
            result.r_worker_type_t = SIO;
            worker_name = "SIO";
            result.index = i;
            break;
        }
    }
    if (!is_worker_uds) {
        for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
            if (*current_fd == master_ctx->logic_session[i].upp.uds[0]) {
                is_worker_uds = true;
                result.r_worker_type_t = LOGIC;
                worker_name = "Logic";
                result.index = i;
                break;
            }
        }
    }
    if (!is_worker_uds) {
        for (int i = 0; i < MAX_COW_WORKERS; ++i) {
            if (*current_fd == master_ctx->cow_session[i].upp.uds[0]) {
                is_worker_uds = true;
                result.r_worker_type_t = COW;
                worker_name = "COW";
                result.index = i;
                break;
            }
        }
    }
    if (!is_worker_uds) {
        for (int i = 0; i < MAX_DBR_WORKERS; ++i) {
            if (*current_fd == master_ctx->dbr_session[i].upp.uds[0]) {
                is_worker_uds = true;
                result.r_worker_type_t = DBR;
                worker_name = "DBR";
                result.index = i;
                break;
            }
        }
    }
    if (!is_worker_uds) {
        for (int i = 0; i < MAX_DBW_WORKERS; ++i) {
            if (*current_fd == master_ctx->dbw_session[i].upp.uds[0]) {
                is_worker_uds = true;
                result.r_worker_type_t = DBW;
                worker_name = "DBW";
                result.index = i;
                break;
            }
        }
    }
    if (is_worker_uds) {
		LOG_DEBUG("%sWorker UDS FD %d (%s Worker %d) terputus.", label, *current_fd, worker_name, result.index);
        result.status = SUCCESS;			
		return result;
	}
	return result;
}

status_t handle_ipc_event(const char *label, master_context *master_ctx, int *current_fd) {
	ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(label, current_fd);
	if (deserialized_result.status != SUCCESS) {
		LOG_ERROR("%srecv_ipc_message from worker. %s", label, strerror(errno));
		return deserialized_result.status;
	}
	ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;                
	switch (received_protocol->type) {
		case IPC_WORKER_MASTER_HEARTBEAT: {
            ipc_worker_master_heartbeat_t *hbt = received_protocol->payload.ipc_worker_master_heartbeat;
            uint64_t_status_t rt = get_realtime_time_ns(label);
            if (hbt->wot == SIO) {
                LOG_DEBUG("%sSIO %d set last_ack to %llu.", label, hbt->index, rt.r_uint64_t);
                master_ctx->sio_session[hbt->index].metrics.last_ack = rt.r_uint64_t;
                master_ctx->sio_session[hbt->index].metrics.count_ack += (long)1;
                master_ctx->sio_session[hbt->index].metrics.sum_hbtime += hbt->hbtime;
                master_ctx->sio_session[hbt->index].metrics.hbtime = hbt->hbtime;
            } else if (hbt->wot == LOGIC) {
                LOG_DEBUG("%sLogic %d set last_ack to %llu.", label, hbt->index, rt.r_uint64_t);
                master_ctx->logic_session[hbt->index].metrics.last_ack = rt.r_uint64_t;
                master_ctx->logic_session[hbt->index].metrics.count_ack += (long)1;
                master_ctx->logic_session[hbt->index].metrics.sum_hbtime += hbt->hbtime;
                master_ctx->logic_session[hbt->index].metrics.hbtime = hbt->hbtime;
            } else if (hbt->wot == COW) {
                LOG_DEBUG("%sCOW %d set last_ack to %llu.", label, hbt->index, rt.r_uint64_t);
                master_ctx->cow_session[hbt->index].metrics.last_ack = rt.r_uint64_t;
                master_ctx->cow_session[hbt->index].metrics.count_ack += (long)1;
                master_ctx->cow_session[hbt->index].metrics.sum_hbtime += hbt->hbtime;
                master_ctx->cow_session[hbt->index].metrics.hbtime = hbt->hbtime;
            } else if (hbt->wot == DBR) {
                LOG_DEBUG("%sDBR %d set last_ack to %llu.", label, hbt->index, rt.r_uint64_t);
                master_ctx->dbr_session[hbt->index].metrics.last_ack = rt.r_uint64_t;
                master_ctx->dbr_session[hbt->index].metrics.count_ack += (long)1;
                master_ctx->dbr_session[hbt->index].metrics.sum_hbtime += hbt->hbtime;
                master_ctx->dbr_session[hbt->index].metrics.hbtime = hbt->hbtime;
            } else if (hbt->wot == DBW) {
                LOG_DEBUG("%sDBW %d set last_ack to %llu.", label, hbt->index, rt.r_uint64_t);
                master_ctx->dbw_session[hbt->index].metrics.last_ack = rt.r_uint64_t;
                master_ctx->dbw_session[hbt->index].metrics.count_ack += (long)1;
                master_ctx->dbw_session[hbt->index].metrics.sum_hbtime += hbt->hbtime;
                master_ctx->dbw_session[hbt->index].metrics.hbtime = hbt->hbtime;
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
			break;
		}
        case IPC_COW_MASTER_CONNECTION: {
            ipc_cow_master_connection_t *cmc = received_protocol->payload.ipc_cow_master_connection;
            for (int i = 0; i < MAX_MASTER_COW_SESSIONS; ++i) {
                if (
                    master_ctx->cow_c_session[i].in_use &&
                    sockaddr_equal((const struct sockaddr *)&master_ctx->cow_c_session[i].server_addr, (const struct sockaddr *)&cmc->server_addr)
                   )
                {
                    calculate_avg_task_time_metrics(label, master_ctx, cmc->wot, cmc->index);
                    master_ctx->cow_c_session[i].cow_index = -1;
                    master_ctx->cow_c_session[i].in_use = false;
                    memset(&master_ctx->cow_c_session[i].server_addr, 0, sizeof(struct sockaddr_in6));
                    break;
                }
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
		default:
			LOG_ERROR("[Master]: Unknown protocol type %d from UDS FD %d. Ignoring.", received_protocol->type, *current_fd);
			CLOSE_IPC_PROTOCOL(&received_protocol);
	}
	return SUCCESS;
}
