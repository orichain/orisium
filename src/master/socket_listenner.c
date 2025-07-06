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
#include "commons.h"
#include "node.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "sessions/closed_correlation_id.h"
#include "sessions/master_client_session.h"
#include "types.h"
#include "ipc/client_request_task.h"
#include "master/socket_listenner.h"
#include "stdbool.h"

status_t setup_socket_listenner(const char *label, int *listen_sock) {
    struct sockaddr_in6 addr;
    int opt = 1;
    int v6only = 0;
    
    *listen_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (*listen_sock == -1) {
		LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    status_t r_snbkg = set_nonblocking(label, *listen_sock);
    if (r_snbkg != SUCCESS) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return r_snbkg;
    }
    if (setsockopt(*listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    //di FreeBSD tidak bisa reuseport. sudah pernah coba
    /*
    if (setsockopt(*listen_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    */
    if (setsockopt(*listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
		LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(node_config.listen_port);
    addr.sin6_addr = in6addr_any;
    if (bind(*listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    if (listen(*listen_sock, 128) < 0) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

status_t handle_listen_sock_event(const char *label, master_client_session_t master_client_sessions[], int master_uds_sio_fds[], uint64_t *next_client_id, int *listen_sock) {
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
	
	int client_sock = accept(*listen_sock, (struct sockaddr*)&client_addr, &client_addr_len);
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
    
    uint8_t host_ip[INET6_ADDRSTRLEN];
	memset(host_ip, 0, INET6_ADDRSTRLEN);
	memcpy(host_ip, host_str, host_str_len);
    
	bool ip_already_connected = false;
	for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
		if (master_client_sessions[i].in_use &&
			memcmp(master_client_sessions[i].ip, host_ip, INET6_ADDRSTRLEN) == 0) {
			ip_already_connected = true;
			break;
		}
	}
	if (ip_already_connected) {
		LOG_WARN("%sKoneksi ditolak dari IP %s. Sudah ada koneksi aktif dari IP ini.", label, host_ip);
		close(client_sock);
		return FAILURE_ALRDYCONTD;
	}
	LOG_INFO("%sNew client connected from IP %s on FD %d.", label, host_ip, client_sock);
	
	uint64_t current_client_id = 0ULL;
	closed_correlation_id_t_status_t ccid_result = find_first_ratelimited_closed_correlation_id("[Master]: ", closed_correlation_id_head, host_ip);
	if (ccid_result.status == SUCCESS) {
		current_client_id = ccid_result.r_closed_correlation_id_t->correlation_id;
		status_t ccid_del_result = delete_closed_correlation_id("[Master]: ", &closed_correlation_id_head, current_client_id);
		if (ccid_del_result != SUCCESS) {
			current_client_id = *next_client_id++;
		}
	} else {
		if (ccid_result.status == FAILURE_RATELIMIT) {
			LOG_WARN("%sKoneksi ditolak dari IP %s. ratelimit mungkin ddoser.", label, host_ip);
			close(client_sock);
			return FAILURE_ALRDYCONTD;
		} else {
			current_client_id = *next_client_id++;
		}
	}
	
	if (current_client_id > MAX_MASTER_CONCURRENT_SESSIONS) {
		*next_client_id -= 1ULL;
		LOG_ERROR("%sWARNING: MAX_MASTER_CONCURRENT_SESSIONS reached. Rejecting client FD %d.", label, client_sock);
		CLOSE_FD(client_sock);
		return FAILURE_MAXREACHD;
	}
	
	//cnt_connection += (double_t)1;
	//avg_connection = cnt_connection / sio_worker;
	
	int sio_worker_idx = (int)(current_client_id % MAX_SIO_WORKERS);
	int sio_worker_uds_fd = master_uds_sio_fds[sio_worker_idx]; // Master uses its side of UDS

	int slot_found = -1;
	for(int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
		if(!master_client_sessions[i].in_use) {
			master_client_sessions[i].in_use = true;
			master_client_sessions[i].correlation_id = current_client_id;
			master_client_sessions[i].sio_uds_fd = sio_worker_uds_fd;
			memcpy(master_client_sessions[i].ip, host_ip, INET6_ADDRSTRLEN);
			slot_found = i;
			break;
		}
	}
	if (slot_found == -1) {
		LOG_ERROR("%sWARNING: No free session slots in master_client_sessions. Rejecting client FD %d.", label, client_sock);
		CLOSE_FD(client_sock);
		return FAILURE_NOSLOT;
	}
	
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_client_request_task(&client_sock, &current_client_id, host_ip, (uint16_t)0, NULL);
	if (cmd_result.status != SUCCESS) {
		return cmd_result.status;
	}	
	ssize_t_status_t send_result = send_ipc_protocol_message(&sio_worker_uds_fd, cmd_result.r_ipc_protocol_t, &client_sock);
	if (send_result.status != SUCCESS) {
		LOG_ERROR("%sFailed to forward client FD %d (ID %ld) to Server IO Worker %d.",
				  label, client_sock, current_client_id, sio_worker_idx);
	} else {
		LOG_INFO("%sForwarding client FD %d (ID %ld) from IP %s to Server IO Worker %d (UDS FD %d). Bytes sent: %zd.",
				 label, client_sock, current_client_id, host_ip, sio_worker_idx, sio_worker_uds_fd, send_result.r_ssize_t);
		CLOSE_FD(client_sock); // di close jika berhasil Forwarding
	}
	CLOSE_IPC_PROTOCOL(cmd_result.r_ipc_protocol_t);
	return SUCCESS;
}
