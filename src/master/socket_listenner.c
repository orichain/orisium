#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "log.h"
#include "utilities.h"
#include "orilink/protocol.h"
#include "types.h"
#include "master/socket_listenner.h"
#include "master/process.h"
#include "master/worker_metrics.h"
#include "master/worker_selector.h"
#include "master/server_orilink_cmds.h"
#include "async.h"
#include "constants.h"
#include "pqc.h"
#include "sessions/master_session.h"
#include "stdbool.h"

status_t setup_socket_listenner(const char *label, master_context *master_ctx, uint16_t *listen_port) {
    struct sockaddr_in6 addr;
    int opt = 1;
    int v6only = 0;
    
    master_ctx->listen_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (master_ctx->listen_sock == -1) {
		LOG_ERROR("%ssocket failed. %s", label, strerror(errno));
        return FAILURE;
    }
    status_t r_snbkg = set_nonblocking(label, master_ctx->listen_sock);
    if (r_snbkg != SUCCESS) {
        LOG_ERROR("%sset_nonblocking failed.", label);
        return r_snbkg;
    }
    if (setsockopt(master_ctx->listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        LOG_ERROR("%ssetsockopt failed. %s", label, strerror(errno));
        return FAILURE;
    }
    if (setsockopt(master_ctx->listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
		LOG_ERROR("%ssetsockopt failed. %s", label, strerror(errno));
        return FAILURE;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(*listen_port);
    addr.sin6_addr = in6addr_any;
    if (bind(master_ctx->listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("%sbind failed. %s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

status_t handle_listen_sock_event(const char *label, master_context *master_ctx) {
    struct sockaddr_in6 client_addr;
	char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    orilink_protocol_t_status_t rcvd = receive_and_deserialize_orilink_packet(
        label,
        &master_ctx->listen_sock,
        (struct sockaddr *)&client_addr
    );
    if (rcvd.status != SUCCESS) return rcvd.status;
    orilink_protocol_t* received_protocol = rcvd.r_orilink_protocol_t;
    int getname_res = getnameinfo((struct sockaddr *)&client_addr, sizeof(struct sockaddr_in6),
						host_str, NI_MAXHOST,
					  	port_str, NI_MAXSERV,
					  	NI_NUMERICHOST | NI_NUMERICSERV
					  );
	if (getname_res != 0) {
		LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
        CLOSE_ORILINK_PROTOCOL(&received_protocol);
		return FAILURE;
	}
    size_t host_str_len = strlen(host_str);
    if (host_str_len >= INET6_ADDRSTRLEN) {
        LOG_ERROR("%sKoneksi ditolak dari IP %s. IP terlalu panjang.", label, host_str);
        CLOSE_ORILINK_PROTOCOL(&received_protocol);
        return FAILURE_IVLDIP;
    }
    char *endptr;
    long port_num = strtol(port_str, &endptr, 10);
    if (*endptr != '\0' || port_num <= 0 || port_num > 65535) {
		LOG_ERROR("%sKoneksi ditolak dari IP %s. PORT di luar rentang (1-65535).", label, host_str);
        CLOSE_ORILINK_PROTOCOL(&received_protocol);
        return FAILURE_IVLDPORT;
    }
    switch (received_protocol->type) {
        case ORILINK_HELLO1: {
            orilink_hello1_t *ohello1 = received_protocol->payload.orilink_hello1;
            bool ip_already_connected = false;
            for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                if (
                        master_ctx->sio_c_session[i].in_use &&
                        sockaddr_equal((const struct sockaddr *)&master_ctx->sio_c_session[i].old_client_addr, (const struct sockaddr *)&client_addr) &&
//======================================================================
// Walaupun ID berbeda tetap tidak boleh
// Hello1 harus tuntas dengan 1 IP
//======================================================================
// (master_ctx->sio_c_session[i].client_id == ohello1->client_id) &&
//======================================================================
                        master_ctx->sio_c_session[i].hello1_rcvd
                   )
                {
                    ip_already_connected = true;
                    break;
                }
            }
            if (ip_already_connected) {
                LOG_WARN("%sHELLO1 ditolak dari IP %s. Sudah ada HELLO1 dari IP ini.", label, host_str);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE_ALRDYCONTD;
            }
            int sio_worker_idx = select_best_worker(label, master_ctx, SIO);
            if (sio_worker_idx == -1) {
                LOG_ERROR("%sFailed to select an SIO worker for new client IP %s. Rejecting.", label, host_str);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE_NOSLOT;
            }
            int slot_found = -1;
            for(int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                if(!master_ctx->sio_c_session[i].in_use) {
                    master_ctx->sio_c_session[i].sio_index = sio_worker_idx;
                    master_ctx->sio_c_session[i].in_use = true;
                    memcpy(&master_ctx->sio_c_session[i].old_client_addr, &client_addr, sizeof(struct sockaddr_in6));
                    slot_found = i;
                    break;
                }
            }
            if (slot_found == -1) {
                LOG_ERROR("%sWARNING: No free session slots in master_ctx->sio_c_session. Rejecting client IP %s.", label, host_str);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE_NOSLOT;
            }
            if (new_task_metrics(label, master_ctx, SIO, sio_worker_idx) != SUCCESS) {
                LOG_ERROR("%sFailed to input new task in SIO %d metrics.", label, sio_worker_idx);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            uint64_t_status_t rt = get_realtime_time_ns(label);
            if (rt.status != SUCCESS) {
                LOG_ERROR("%sFailed to get_realtime_time_ns.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            LOG_DEVEL_DEBUG("%sNew client connected from IP %s.", label, host_str);
            master_sio_c_session_t *session = &master_ctx->sio_c_session[slot_found];
            session->hello1_rcvd = true;
            session->hello1_rcvd_time = rt.r_uint64_t;
            session->client_id = ohello1->client_id;
            memcpy(session->kem_publickey, ohello1->publickey1, KEM_PUBLICKEY_BYTES / 2);
//======================================================================                    
            if (async_create_timerfd(label, &session->hello1_ack_timer_fd) != SUCCESS) {
                LOG_ERROR("%sFailed to async_create_timerfd.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//======================================================================
            if (send_hello1_ack(label, &master_ctx->listen_sock, session) != SUCCESS) {
                LOG_ERROR("%sFailed to send_hello1_ack.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//======================================================================
            if (async_create_incoming_event(label, &master_ctx->master_async, &session->hello1_ack_timer_fd) != SUCCESS) {
                LOG_ERROR("%sFailed to async_create_incoming_event.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }        
//======================================================================
            CLOSE_ORILINK_PROTOCOL(&received_protocol);
            break;
        }
        default:
            CLOSE_ORILINK_PROTOCOL(&received_protocol);
            return FAILURE;
    }
    /*
	master_sio_dc_session_t_status_t ccid_result = find_first_ratelimited_master_sio_dc_session("[Master]: ", master_ctx->sio_dc_session, &client_addr);
	if (ccid_result.status == SUCCESS) {
		status_t ccid_del_result = delete_master_sio_dc_session("[Master]: ", &master_ctx->sio_dc_session, &client_addr);
		if (ccid_del_result != SUCCESS) return FAILURE;
	} else {
		if (ccid_result.status == FAILURE_RATELIMIT) {
			LOG_WARN("%sKoneksi ditolak dari IP %s. ratelimit mungkin ddoser.", label, host_str);
            CLOSE_ORILINK_PROTOCOL(&received_protocol);
			return FAILURE_ALRDYCONTD;
		} else {
            CLOSE_ORILINK_PROTOCOL(&received_protocol);
			return FAILURE;
		}
	}
    */
    
	/*
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_client_request_task(label, &client_sock, host_ip_bin, (uint16_t)0, NULL);
	if (cmd_result.status != SUCCESS) {
		return cmd_result.status;
	}	
	ssize_t_status_t send_result = send_ipc_protocol_message(label, &sio_worker_uds_fd, cmd_result.r_ipc_protocol_t, &client_sock);
	if (send_result.status != SUCCESS) {
		LOG_ERROR("%sFailed to forward client FD %d to Server IO Worker %d.",
				  label, client_sock, sio_worker_idx);
	} else {
        if (new_task_metrics(label, master_ctx, SIO, sio_worker_idx) != SUCCESS) {
            LOG_ERROR("%sFailed to input new task in SIO %d metrics.",
                    label, sio_worker_idx);
        } else {
            LOG_DEBUG("%sForwarding client FD %d from IP %s to Server IO Worker %d (UDS FD %d). Bytes sent: %zd.",
                    label, client_sock, host_str, sio_worker_idx, sio_worker_uds_fd, send_result.r_ssize_t);
        }
	}
	CLOSE_FD(&client_sock); // Menghindari kebocoran FD jika send_ipc gagal => biarkan client reconnect
	CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    */
    //CLOSE_ORILINK_PROTOCOL(&received_protocol);
	return SUCCESS;
}
