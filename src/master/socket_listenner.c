#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <netdb.h>       // for getnameinfo, NI_MAXHOST, NI_MAXSERV, NI_NUME...
#include <netinet/in.h>  // for INET6_ADDRSTRLEN
#include <stdint.h>      // for uint16_t, uint64_t
#include <stdio.h>       // for NULL, perror
#include <stdlib.h>      // for malloc, free
#include <string.h>      // for strerror, memset, strcmp, memcpy, strncpy
#include <sys/socket.h>  // for accept, sockaddr_storage, socklen_t
#include <unistd.h>      // for close
#include <arpa/inet.h>

#include "log.h"
#include "constants.h"
#include "utilities.h"
#include "node.h"
#include "ipc/protocol.h"
#include "sessions/master_session.h"
#include "types.h"
#include "ipc/client_request_task.h"
#include "master/socket_listenner.h"
#include "stdbool.h"
#include "master/process.h"

status_t setup_socket_listenner(const char *label, master_context *master_ctx) {
    struct sockaddr_in6 addr;
    int opt = 1;
    int v6only = 0;
    
    master_ctx->listen_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (master_ctx->listen_sock == -1) {
		LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    status_t r_snbkg = set_nonblocking(label, master_ctx->listen_sock);
    if (r_snbkg != SUCCESS) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return r_snbkg;
    }
    if (setsockopt(master_ctx->listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    //di FreeBSD tidak bisa reuseport. sudah pernah coba
    /*
    if (setsockopt(master_ctx->listen_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    */
    if (setsockopt(master_ctx->listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
		LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(node_config.listen_port);
    addr.sin6_addr = in6addr_any;
    if (bind(master_ctx->listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    if (listen(master_ctx->listen_sock, 128) < 0) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

status_t handle_listen_sock_event(const char *label, master_context *master_ctx, uint64_t *client_num) {
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
	
	int client_sock = accept(master_ctx->listen_sock, (struct sockaddr*)&client_addr, &client_addr_len);
	if (client_sock == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			LOG_ERROR("%s%s", label, strerror(errno));
			return FAILURE;
		}
		return FAILURE_EAGNEWBLK;
	}
	int getname_res = getnameinfo((struct sockaddr *)&client_addr, client_addr_len,
						host_str, NI_MAXHOST,
					  	port_str, NI_MAXSERV,
					  	NI_NUMERICHOST | NI_NUMERICSERV
					  );
	if (getname_res != 0) {
		LOG_ERROR("%s%s", label, strerror(errno));
		close(client_sock);
		return FAILURE;
	}
	
    size_t host_str_len = strlen(host_str);
    if (host_str_len >= INET6_ADDRSTRLEN) {
        LOG_ERROR("%sKoneksi ditolak dari IP %s. IP terlalu panjang.", label, host_str);
        close(client_sock);
        return FAILURE_IVLDIP;
    }
    char *endptr;
    long port_num = strtol(port_str, &endptr, 10);
    if (*endptr != '\0' || port_num <= 0 || port_num > 65535) {
		LOG_ERROR("%sKoneksi ditolak dari IP %s. PORT di luar rentang (1-65535).", label, host_str);
        close(client_sock);
        return FAILURE_IVLDPORT;
    }
    
    uint8_t host_ip_bin[IP_ADDRESS_LEN];	
	if (convert_str_to_ipv6_bin(host_str, host_ip_bin) != SUCCESS) {
		LOG_ERROR("%sIP tidak valid %s.", label, host_str);
		return FAILURE_IVLDIP;
	}
    
	bool ip_already_connected = false;
	for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
		if (master_ctx->sio_c_session[i].in_use &&
			memcmp(master_ctx->sio_c_session[i].ip, host_ip_bin, IP_ADDRESS_LEN) == 0) {
			ip_already_connected = true;
			break;
		}
	}
	
	char ip_str[INET6_ADDRSTRLEN];
	convert_ipv6_bin_to_str(host_ip_bin, ip_str);
	
	if (ip_already_connected) {
		LOG_WARN("%sKoneksi ditolak dari IP %s. Sudah ada koneksi aktif dari IP ini.", label, ip_str);
		close(client_sock);
		return FAILURE_ALRDYCONTD;
	}
	LOG_INFO("%sNew client connected from IP %s on FD %d.", label, ip_str, client_sock);
	
	master_sio_dc_session_t_status_t ccid_result = find_first_ratelimited_master_sio_dc_session("[Master]: ", master_ctx->sio_dc_session, host_ip_bin);
	if (ccid_result.status == SUCCESS) {
		status_t ccid_del_result = delete_master_sio_dc_session("[Master]: ", &master_ctx->sio_dc_session, host_ip_bin);
		if (ccid_del_result != SUCCESS) {
			*client_num += 1ULL;
		}
	} else {
		if (ccid_result.status == FAILURE_RATELIMIT) {
			LOG_WARN("%sKoneksi ditolak dari IP %s. ratelimit mungkin ddoser.", label, ip_str);
			close(client_sock);
			return FAILURE_ALRDYCONTD;
		} else {
			*client_num += 1ULL;
		}
	}
	
	if (*client_num > MAX_MASTER_CONCURRENT_SESSIONS) {
		*client_num -= 1ULL;
		LOG_ERROR("%sWARNING: MAX_MASTER_CONCURRENT_SESSIONS reached. Rejecting client FD %d.", label, client_sock);
		CLOSE_FD(&client_sock);
		return FAILURE_MAXREACHD;
	}
	
	//cnt_connection += (double_t)1;
	//avg_connection = cnt_connection / sio_worker;
	
	int sio_worker_idx = (int)(*client_num % MAX_SIO_WORKERS);
	int sio_worker_uds_fd = master_ctx->sio[sio_worker_idx].uds[0]; // Master uses its side of UDS

	int slot_found = -1;
	for(int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
		if(!master_ctx->sio_c_session[i].in_use) {
			master_ctx->sio_c_session[i].in_use = true;
			master_ctx->sio_c_session[i].sio_uds_fd = sio_worker_uds_fd;
			memcpy(master_ctx->sio_c_session[i].ip, host_ip_bin, IP_ADDRESS_LEN);
			slot_found = i;
			break;
		}
	}
	if (slot_found == -1) {
		LOG_ERROR("%sWARNING: No free session slots in master_ctx->sio_c_session. Rejecting client FD %d.", label, client_sock);
		CLOSE_FD(&client_sock);
		return FAILURE_NOSLOT;
	}
	
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_client_request_task(&client_sock, host_ip_bin, (uint16_t)0, NULL);
	if (cmd_result.status != SUCCESS) {
		return cmd_result.status;
	}	
	ssize_t_status_t send_result = send_ipc_protocol_message(&sio_worker_uds_fd, cmd_result.r_ipc_protocol_t, &client_sock);
	if (send_result.status != SUCCESS) {
		LOG_ERROR("%sFailed to forward client FD %d to Server IO Worker %d.",
				  label, client_sock, sio_worker_idx);
	} else {
		LOG_INFO("%sForwarding client FD %d from IP %s to Server IO Worker %d (UDS FD %d). Bytes sent: %zd.",
				 label, client_sock, ip_str, sio_worker_idx, sio_worker_uds_fd, send_result.r_ssize_t);
	}
	CLOSE_FD(&client_sock); // Menghindari kebocoran FD jika send_ipc gagal => biarkan client reconnect
	CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	return SUCCESS;
}
