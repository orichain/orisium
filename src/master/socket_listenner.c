#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <float.h>
#include <limits.h>

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
    //di FreeBSD tidak bisa reuseport. sudah pernah coba
    /*
    if (setsockopt(master_ctx->listen_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    */
    if (setsockopt(master_ctx->listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
		LOG_ERROR("%ssetsockopt failed. %s", label, strerror(errno));
        return FAILURE;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(node_config.listen_port);
    addr.sin6_addr = in6addr_any;
    if (bind(master_ctx->listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("%sbind failed. %s", label, strerror(errno));
        return FAILURE;
    }
    if (listen(master_ctx->listen_sock, 128) < 0) {
        LOG_ERROR("%slisten failed. %s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

int select_best_sio_worker(const char *label, master_context *master_ctx) {
    int selected_worker_idx = -1; // Gunakan nama baru untuk hasil akhir
    long double min_avg_task_time = LDBL_MAX;
    uint64_t min_longest_task_time = ULLONG_MAX;
    
    // ====================================================================
    // Tahap 1: Cari worker dengan avg_task_time terendah (dan tidak penuh)
    // ====================================================================
    int temp_best_idx_t1 = -1;
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        // Hanya pertimbangkan worker yang TIDAK PENUH
        if (master_ctx->sio_state[i].task_count < MAX_CLIENTS_PER_SIO_WORKER) {
            // Gunakan avg_task_time
            if (master_ctx->sio_state[i].metrics.avg_task_time < min_avg_task_time) {
                min_avg_task_time = master_ctx->sio_state[i].metrics.avg_task_time;
                temp_best_idx_t1 = i;
            }
        }
    }

    if (temp_best_idx_t1 != -1) {
        // Jika worker terbaik yang ditemukan memiliki avg_task_time > 0, langsung pilih dia.
        if (min_avg_task_time > 0.0L) {
            selected_worker_idx = temp_best_idx_t1;
            LOG_DEVEL_DEBUG("%sSelecting SIO worker %d based on lowest Avg Task Time: %Lf", 
                      label, selected_worker_idx, min_avg_task_time);
            return selected_worker_idx; // Ditemukan worker terbaik berdasarkan metrik utama
        }
        // Jika min_avg_task_time == 0.0L, artinya semua worker yang tidak penuh memiliki avg_task_time 0.
        // Lanjutkan ke tahap berikutnya (Longest Task Time).
        LOG_DEVEL_DEBUG("%sAll not-full SIO workers have 0 Avg Task Time. Falling back to Longest Task Time / Round Robin.", label);
    } else {
        // Ini berarti semua worker SIO PENUH. Langsung fallback ke tahap berikutnya.
        LOG_DEVEL_DEBUG("%sNo not-full SIO workers found for Avg Task Time check. All might be full. Falling back.", label);
    }

    // ====================================================================
    // Tahap 2: Jika belum ada worker yang dipilih, cari berdasarkan Longest Task Time terendah
    // (di antara worker yang tidak penuh)
    // ====================================================================
    // Kita hanya masuk ke sini jika selected_worker_idx masih -1 (Tahap 1 tidak menghasilkan pilihan definitif)
    int temp_best_idx_t2 = -1;
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        // Hanya pertimbangkan worker yang TIDAK PENUH
        if (master_ctx->sio_state[i].task_count < MAX_CLIENTS_PER_SIO_WORKER) {
            if (master_ctx->sio_state[i].metrics.longest_task_time < min_longest_task_time) {
                min_longest_task_time = master_ctx->sio_state[i].metrics.longest_task_time;
                temp_best_idx_t2 = i;
            }
        }
    }
    
    if (temp_best_idx_t2 != -1) {
        // Jika worker terbaik yang ditemukan memiliki Longest Task Time > 0, langsung pilih dia.
        if (min_longest_task_time > 0ULL) {
            selected_worker_idx = temp_best_idx_t2;
            LOG_DEVEL_DEBUG("%sSelecting SIO worker %d based on lowest Longest Task Time: %" PRIu64, 
                      label, selected_worker_idx, min_longest_task_time);
            return selected_worker_idx; 
        }
        // Jika min_longest_task_time == 0ULL, artinya semua worker yang tidak penuh memiliki Longest Task Time 0.
        // Lanjut ke tahap berikutnya (Round Robin).
        LOG_DEVEL_DEBUG("%sAll not-full SIO workers have 0 Longest Task Time. Falling back to Round Robin.", label);
    } else {
        // Ini berarti semua worker SIO PENUH ATAU tidak ada yang memenuhi kriteria di Tahap 2.
        LOG_DEVEL_DEBUG("%sNo not-full SIO workers found for Longest Task Time check. All might be full. Falling back to Round Robin.", label);
    }
    
    // ====================================================================
    // Tahap 3: Fallback ke Round Robin (di antara worker yang tidak penuh)
    // ====================================================================
    // Kita hanya masuk ke sini jika selected_worker_idx masih -1 (Tahap 1 dan 2 tidak menghasilkan pilihan definitif)
    int temp_best_idx_t3 = -1;
    int start_rr_check_idx = master_ctx->last_sio_rr_idx; 

    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        int current_rr_idx = (start_rr_check_idx + i) % MAX_SIO_WORKERS;
        // Hanya pilih worker yang TIDAK PENUH
        if (master_ctx->sio_state[current_rr_idx].task_count < MAX_CLIENTS_PER_SIO_WORKER) {
            temp_best_idx_t3 = current_rr_idx;
            master_ctx->last_sio_rr_idx = (current_rr_idx + 1) % MAX_SIO_WORKERS; // Update index RR
            break; // Found a suitable worker, exit loop
        }
    }

    if (temp_best_idx_t3 != -1) {
        selected_worker_idx = temp_best_idx_t3;
        LOG_DEVEL_DEBUG("%sSelecting SIO worker %d using Round Robin (fallback).", label, selected_worker_idx);
        return selected_worker_idx;
    } else {
        // Skenario terburuk: semua worker SIO penuh (atau tidak ada sama sekali).
        LOG_ERROR("%sNo SIO worker available (all might be full).", label);
        return -1; // Indicate failure to select a worker
    }
}

status_t handle_listen_sock_event(const char *label, master_context *master_ctx, uint64_t *client_num) {
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
	
	int client_sock = accept(master_ctx->listen_sock, (struct sockaddr*)&client_addr, &client_addr_len);
	if (client_sock == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			LOG_ERROR("%saccept failed. %s", label, strerror(errno));
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
		LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
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
	LOG_DEBUG("%sNew client connected from IP %s on FD %d.", label, ip_str, client_sock);
	
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
    
    int sio_worker_idx = select_best_sio_worker(label, master_ctx);
    if (sio_worker_idx == -1) {
        LOG_ERROR("%sFailed to select an SIO worker for new client %s on FD %d. Rejecting.", label, ip_str, client_sock);
        CLOSE_FD(&client_sock);
        return FAILURE_NOSLOT;
    }
	int sio_worker_uds_fd = master_ctx->sio[sio_worker_idx].uds[0];
    
	int slot_found = -1;
	for(int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
		if(!master_ctx->sio_c_session[i].in_use) {
            master_ctx->sio_c_session[i].sio_index = sio_worker_idx;
			master_ctx->sio_c_session[i].in_use = true;
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
	
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_client_request_task(label, &client_sock, host_ip_bin, (uint16_t)0, NULL);
	if (cmd_result.status != SUCCESS) {
		return cmd_result.status;
	}	
	ssize_t_status_t send_result = send_ipc_protocol_message(label, &sio_worker_uds_fd, cmd_result.r_ipc_protocol_t, &client_sock);
	if (send_result.status != SUCCESS) {
		LOG_ERROR("%sFailed to forward client FD %d to Server IO Worker %d.",
				  label, client_sock, sio_worker_idx);
	} else {
//======================================================================
// Mengisi metrics sio_state
//======================================================================
        uint64_t_status_t rt = get_realtime_time_ns(label);
        master_ctx->sio_state[sio_worker_idx].task_count += 1;
        master_ctx->sio_state[sio_worker_idx].metrics.last_task_started = rt.r_uint64_t;
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
		LOG_DEBUG("%sForwarding client FD %d from IP %s to Server IO Worker %d (UDS FD %d). Bytes sent: %zd.",
				 label, client_sock, ip_str, sio_worker_idx, sio_worker_uds_fd, send_result.r_ssize_t);
	}
	CLOSE_FD(&client_sock); // Menghindari kebocoran FD jika send_ipc gagal => biarkan client reconnect
	CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	return SUCCESS;
}
