#include <stdbool.h>     // for false, bool, true
#include <string.h>      // for memset, strncpy
#include <netinet/in.h>
#include <errno.h>
#include <inttypes.h>

#include "log.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "sessions/master_session.h"
#include "types.h"
#include "utilities.h"
#include "master/ipc.h"
#include "master/process.h"

worker_type_t_status_t handle_ipc_closed_event(const char *label, master_context *master_ctx, int *current_fd) {
	worker_type_t_status_t result;
	result.r_worker_type_t = UNKNOWN;
	result.status = FAILURE;
	result.index = -1;
    const char* worker_name = "Unknown";
    bool is_worker_uds = false;

    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        if (*current_fd == master_ctx->sio[i].uds[0]) {
            is_worker_uds = true;
            result.r_worker_type_t = SIO;
            worker_name = "SIO";
            result.index = i;
            break;
        }
    }
    if (!is_worker_uds) {
        for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
            if (*current_fd == master_ctx->logic[i].uds[0]) {
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
            if (*current_fd == master_ctx->cow[i].uds[0]) {
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
            if (*current_fd == master_ctx->dbr[i].uds[0]) {
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
            if (*current_fd == master_ctx->dbw[i].uds[0]) {
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
	int received_fd = -1;
	ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(label, current_fd, &received_fd);
	if (deserialized_result.status != SUCCESS) {
		LOG_ERROR("%srecv_ipc_message from worker. %s", label, strerror(errno));
		return deserialized_result.status;
	}
	ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;                
	switch (received_protocol->type) {
		case IPC_HEARTBEAT: {
            ipc_heartbeat_t *hbt = received_protocol->payload.ipc_heartbeat;
            uint64_t_status_t rt = get_realtime_time_ns("[Master]: ");
            if (hbt->wot == SIO) {
                LOG_DEBUG("[Master]: SIO %d set last_ack to %llu.", hbt->index, rt.r_uint64_t);
                master_ctx->sio_state[hbt->index].metrics.last_ack = rt.r_uint64_t;
            } else if (hbt->wot == LOGIC) {
                LOG_DEBUG("[Master]: Logic %d set last_ack to %llu.", hbt->index, rt.r_uint64_t);
                master_ctx->logic_state[hbt->index].metrics.last_ack = rt.r_uint64_t;
            } else if (hbt->wot == COW) {
                LOG_DEBUG("[Master]: COW %d set last_ack to %llu.", hbt->index, rt.r_uint64_t);
                master_ctx->cow_state[hbt->index].metrics.last_ack = rt.r_uint64_t;
            } else if (hbt->wot == DBR) {
                LOG_DEBUG("[Master]: DBR %d set last_ack to %llu.", hbt->index, rt.r_uint64_t);
                master_ctx->dbr_state[hbt->index].metrics.last_ack = rt.r_uint64_t;
            } else if (hbt->wot == DBW) {
                LOG_DEBUG("[Master]: DBW %d set last_ack to %llu.", hbt->index, rt.r_uint64_t);
                master_ctx->dbw_state[hbt->index].metrics.last_ack = rt.r_uint64_t;
            }
			break;
		}
		case IPC_CLIENT_DISCONNECTED: {
			ipc_client_disconnect_info_t *disconnect_info = received_protocol->payload.ipc_client_disconnect_info;
			add_master_sio_dc_session("[Master]: ", &master_ctx->sio_dc_session, disconnect_info->ip); 
			//cnt_connection -= (double_t)1;
			//avg_connection = cnt_connection / sio_worker;
			char ip_str[INET6_ADDRSTRLEN];
			convert_ipv6_bin_to_str(disconnect_info->ip, ip_str);
			LOG_DEBUG("[Master]: Received Client Disconnected signal from IP %s (from SIO Worker UDS FD %d).",
					 ip_str, *current_fd);
			for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
				if (master_ctx->sio_c_session[i].in_use && memcmp(master_ctx->sio_c_session[i].ip, disconnect_info->ip, IP_ADDRESS_LEN) == 0) {
                    int sio_worker_idx = master_ctx->sio_c_session[i].sio_index;                 
//======================================================================
// Mengisi metrics sio_state
//======================================================================
                    uint64_t_status_t rt = get_realtime_time_ns(label);
                    master_ctx->sio_state[sio_worker_idx].metrics.last_ack = rt.r_uint64_t;
                    master_ctx->sio_state[sio_worker_idx].metrics.last_task_finished = rt.r_uint64_t;
                    uint64_t task_time = master_ctx->sio_state[sio_worker_idx].metrics.last_task_finished - master_ctx->sio_state[sio_worker_idx].metrics.last_task_started;
                    if (master_ctx->sio_state[sio_worker_idx].metrics.longest_task_time < task_time) {
                        master_ctx->sio_state[sio_worker_idx].metrics.longest_task_time = task_time;
                    }
                    uint64_t previous_task_count = master_ctx->sio_state[sio_worker_idx].task_count;
                    if (master_ctx->sio_state[sio_worker_idx].task_count > 0) {
                        master_ctx->sio_state[sio_worker_idx].task_count -= 1;
                    } else {
                        LOG_WARN("%sTask count for SIO worker %d is already zero when client %s disconnected. Possible logic error.",
                                 label, sio_worker_idx, ip_str);
                    }
                    uint64_t current_task_count = master_ctx->sio_state[sio_worker_idx].task_count;
                    uint64_t previous_slot_kosong = MAX_CLIENTS_PER_SIO_WORKER - previous_task_count;
                    uint64_t current_slot_kosong = MAX_CLIENTS_PER_SIO_WORKER - current_task_count;
                    long double old_avg_cost_per_empty_slot = master_ctx->sio_state[sio_worker_idx].metrics.avg_task_time;
                    long double new_avg = 0.0L;
                    if (current_task_count == 0) {
                        new_avg = 0.0L;
                    } else {
                        if (previous_slot_kosong > 0) {
                            new_avg = ((old_avg_cost_per_empty_slot * previous_slot_kosong) + task_time) / current_slot_kosong;
                        } else {
                            new_avg = (long double)task_time;
                        }
                    }
                    master_ctx->sio_state[sio_worker_idx].metrics.avg_task_time = new_avg;
                    LOG_DEVEL_DEBUG("%sSIO_STATE:\nTask Count: %" PRIu64 "\nLast Ack: %" PRIu64 "\nLast Started: %" PRIu64 "\nLast Finished: %" PRIu64 "\nLongest Task Time: %" PRIu64 "\nAvg Task Time: %Lf",
                        label,
                        master_ctx->sio_state[sio_worker_idx].task_count,
                        master_ctx->sio_state[sio_worker_idx].metrics.last_ack,
                        master_ctx->sio_state[sio_worker_idx].metrics.last_task_started,
                        master_ctx->sio_state[sio_worker_idx].metrics.last_task_finished,
                        master_ctx->sio_state[sio_worker_idx].metrics.longest_task_time,
                        master_ctx->sio_state[sio_worker_idx].metrics.avg_task_time
                    );
//======================================================================   
                    master_ctx->sio_c_session[i].sio_index = -1;
					master_ctx->sio_c_session[i].in_use = false;
					memset(master_ctx->sio_c_session[i].ip, 0, IP_ADDRESS_LEN);
					LOG_DEBUG("[Master]: IP %s dihapus dari daftar koneksi aktif.", ip_str);
					break;
				}
			}            
			break;
		}
		default:
			LOG_ERROR("[Master]: Unknown protocol type %d from UDS FD %d. Ignoring.", received_protocol->type, *current_fd);
			break;
	}
	CLOSE_IPC_PROTOCOL(&received_protocol);
	return SUCCESS;
}
