#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "log.h"
#include "orilink/protocol.h"
#include "types.h"
#include "master/udp/socket_udp.h"
#include "master/master.h"
#include "master/worker_metrics.h"
#include "master/worker_selector.h"
#include "constants.h"
#include "stdbool.h"
#include "master/ipc/worker_ipc_cmds.h"

status_t handle_master_udp_sock_event(const char *label, master_context_t *master_ctx) {
    struct sockaddr_in6 remote_addr;
	char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    
    orilink_raw_protocol_t_status_t orcvdo = receive_orilink_raw_protocol_packet(
        label,
        &master_ctx->udp_sock,
        &remote_addr
    );
    if (orcvdo.status != SUCCESS) return orcvdo.status;
    int getname_res = getnameinfo((struct sockaddr *)&remote_addr, sizeof(struct sockaddr_in6),
						host_str, NI_MAXHOST,
					  	port_str, NI_MAXSERV,
					  	NI_NUMERICHOST | NI_NUMERICSERV
					  );
	if (getname_res != 0) {
		LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
		return FAILURE;
	}
    size_t host_str_len = strlen(host_str);
    if (host_str_len >= INET6_ADDRSTRLEN) {
        LOG_ERROR("%sKoneksi ditolak dari IP %s. IP terlalu panjang.", label, host_str);
        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
        return FAILURE_IVLDIP;
    }
    char *endptr;
    long port_num = strtol(port_str, &endptr, 10);
    if (*endptr != '\0' || port_num <= 0 || port_num > 65535) {
		LOG_ERROR("%sKoneksi ditolak dari IP %s. PORT di luar rentang (1-65535).", label, host_str);
        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
        return FAILURE_IVLDPORT;
    }
    switch (orcvdo.r_orilink_raw_protocol_t->type) {
        case ORILINK_HELLO1: {
            int sio_worker_idx = select_best_worker(label, master_ctx, SIO);
            if (sio_worker_idx == -1) {
                LOG_ERROR("%sFailed to select an SIO worker for new task.", label);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE;
            }
            uint8_t slot_found = 0xff;
            for(uint8_t i = 0; i < MAX_CONNECTION_PER_SIO_WORKER; ++i) {
                if(!master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_SIO_WORKER) + i].in_use) {
                    master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_SIO_WORKER) + i].sio_index = sio_worker_idx;
                    master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_SIO_WORKER) + i].in_use = true;
                    slot_found = i;
                    break;
                }
            }
            if (slot_found == 0xff) {
                LOG_ERROR("%sWARNING: No free session slots in sio-%d sessions.", label, sio_worker_idx);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE;
            }
            if (new_task_metrics(label, master_ctx, SIO, sio_worker_idx) != SUCCESS) {
                LOG_ERROR("%sFailed to input new task in COW %d metrics.", label, sio_worker_idx);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE;
            }
            if (master_worker_udp_data(label, master_ctx, SIO, sio_worker_idx, slot_found, &remote_addr, orcvdo.r_orilink_raw_protocol_t) != SUCCESS) {
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE;
            }
            CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
			break;
		}
        case ORILINK_HELLO1_ACK:
        case ORILINK_HELLO2:
        case ORILINK_HELLO2_ACK:
        case ORILINK_HELLO3:
        case ORILINK_HELLO3_ACK:
        case ORILINK_HELLO4:
        case ORILINK_HELLO4_ACK: {
            worker_type_t wot = orcvdo.r_orilink_raw_protocol_t->remote_wot;
            int index = orcvdo.r_orilink_raw_protocol_t->remote_index;
            uint8_t session_index = orcvdo.r_orilink_raw_protocol_t->remote_session_index;
            if (master_worker_udp_data(label, master_ctx, wot, index, session_index, &remote_addr, orcvdo.r_orilink_raw_protocol_t) != SUCCESS) {
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE;
            }
            CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
			break;
		}
        default:
            LOG_ERROR("%sUnknown ORILINK protocol type %d from %s:%s. Ignoring.", label, orcvdo.r_orilink_raw_protocol_t->type, host_str, port_str);
            CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
    }
	return SUCCESS;
}
