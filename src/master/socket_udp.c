#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>

#include "log.h"
#include "utilities.h"
#include "orilink/protocol.h"
#include "types.h"
#include "master/socket_udp.h"
#include "master/master.h"
#include "master/worker_metrics.h"
#include "master/worker_selector.h"
#include "constants.h"
#include "stdbool.h"

status_t setup_master_socket_udp(const char *label, master_context_t *master_ctx) {
    struct sockaddr_in6 addr;
    int opt = 1;
    int v6only = 0;
    
    master_ctx->udp_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (master_ctx->udp_sock == -1) {
		LOG_ERROR("%ssocket failed. %s", label, strerror(errno));
        return FAILURE;
    }
    status_t r_snbkg = set_nonblocking(label, master_ctx->udp_sock);
    if (r_snbkg != SUCCESS) {
        LOG_ERROR("%sset_nonblocking failed.", label);
        return r_snbkg;
    }
    if (setsockopt(master_ctx->udp_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        LOG_ERROR("%ssetsockopt failed. %s", label, strerror(errno));
        return FAILURE;
    }
    if (setsockopt(master_ctx->udp_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
		LOG_ERROR("%ssetsockopt failed. %s", label, strerror(errno));
        return FAILURE;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(master_ctx->listen_port);
    addr.sin6_addr = in6addr_any;
    if (bind(master_ctx->udp_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("%sbind failed. %s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

status_t handle_master_udp_sock_event(const char *label, master_context_t *master_ctx) {
    struct sockaddr_in6 client_addr;
	char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    
    orilink_raw_protocol_t_status_t orcvdo = receive_orilink_raw_protocol_packet(
        label,
        &master_ctx->udp_sock,
        &client_addr
    );
    if (orcvdo.status != SUCCESS) return orcvdo.status;
    int getname_res = getnameinfo((struct sockaddr *)&client_addr, sizeof(struct sockaddr_in6),
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
            for(uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
                if(!master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].in_use) {
                    master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].sio_index = sio_worker_idx;
                    master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].in_use = true;
                    slot_found = i;
                    break;
                }
            }
            if (slot_found == 0xff) {
                LOG_ERROR("%sWARNING: No free session slots in master_ctx->sio_c_session.", label);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE;
            }
            if (new_task_metrics(label, master_ctx, COW, sio_worker_idx) != SUCCESS) {
                LOG_ERROR("%sFailed to input new task in COW %d metrics.", label, sio_worker_idx);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE;
            }
//----------------------------------------------------------------------            
//----------------------------------------------------------------------
            printf("[Debug Here Helper]: SIO Index: %d, Session Index: %d.\n", sio_worker_idx, slot_found);
            //if (master_sio_serve(label, master_ctx, &master_ctx->bootstrap_nodes.addr[ic], sio_worker_idx, slot_found) != SUCCESS) goto exit;
//----------------------------------------------------------------------
            CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
			break;
		}
        default:
            LOG_ERROR("%sUnknown ORILINK protocol type %d from %s:%s. Ignoring.", label, orcvdo.r_orilink_raw_protocol_t->type, host_str, port_str);
            CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
    }
	return SUCCESS;
}
