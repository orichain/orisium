#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
	#include <pthread.h>
#endif

#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdbool.h>     // for false, bool, true
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <string.h>      // for memset, strncpy
#include <sys/socket.h>  // for socketpair, SOCK_STREAM, AF_UNIX, AF_INET, accept
#include <sys/types.h>   // for pid_t, ssize_t
#include <unistd.h>      // for close, fork, getpid
#include <signal.h>      // for sig_atomic_t, sigaction, SIGINT
#include <arpa/inet.h>   // for inet_ntop, inet_pton
#include <sys/wait.h>    // for waitpid
#include <bits/types/sig_atomic_t.h>
#include <stdint.h>

#include "log.h"
#include "constants.h"
#include "commons.h"
#include "node.h"
#include "async.h"
#include "ipc/protocol.h"
#include "workers/sio.h"
#include "workers/logic.h"
#include "workers/cow.h"
#include "utilities.h"
#include "sessions/closed_correlation_id.h"
#include "sessions/master_client_session.h"
#include "under_refinement_and_will_be_delete_after_finished.h"
#include "types.h"
#include "ipc/client_request_task.h"
#include "master/socket_listenner.h"

volatile sig_atomic_t shutdown_requested = 0;
node_config_t node_config;
master_client_session_t master_client_sessions[MAX_MASTER_CONCURRENT_SESSIONS];

master_client_session_t *master_client_session_head = NULL;
closed_correlation_id_t *closed_correlation_id_head = NULL;

void sigint_handler(int signum) {
    shutdown_requested = 1;
    LOG_INFO("SIGINT received. Initiating graceful shutdown...");
}

// Placeholder for orisium_cleanup
void orisium_cleanup(int *listen_sock_ptr, async_type_t *async_fd_ptr,
                     int uds_sio_fds_master_side[], int uds_logic_fds_master_side[], int uds_cow_fds_master_side[],
                     int uds_sio_fds_worker_side[], int uds_logic_fds_worker_side[], int uds_cow_fds_worker_side[],
                     pid_t sio_pids[], pid_t logic_pids[], pid_t cow_pids[]) {
    LOG_INFO("Performing cleanup...");
    if (*listen_sock_ptr != -1) close(*listen_sock_ptr);
    if (async_fd_ptr->async_fd != -1) close(async_fd_ptr->async_fd);

    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        if (uds_sio_fds_master_side[i] != 0) close(uds_sio_fds_master_side[i]);
        if (uds_sio_fds_worker_side[i] != 0) close(uds_sio_fds_worker_side[i]); // Close worker side in Master too
        if (sio_pids[i] > 0) waitpid(sio_pids[i], NULL, 0);
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        if (uds_logic_fds_master_side[i] != 0) close(uds_logic_fds_master_side[i]);
        if (uds_logic_fds_worker_side[i] != 0) close(uds_logic_fds_worker_side[i]); // Close worker side in Master too
        if (logic_pids[i] > 0) waitpid(logic_pids[i], NULL, 0);
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        if (uds_cow_fds_master_side[i] != 0) close(uds_cow_fds_master_side[i]);
        if (uds_cow_fds_worker_side[i] != 0) close(uds_cow_fds_worker_side[i]); // Close worker side in Master too
        if (cow_pids[i] > 0) waitpid(cow_pids[i], NULL, 0);
    }
    LOG_INFO("Cleanup complete.");
}

status_t setup_fork_workers(
    const char* label,
    int listen_sock, // listen_sock passed by value, as it's closed in child
    async_type_t *async,
    int master_uds_sio_fds[], // Arrays for Master's side of UDS
    int master_uds_logic_fds[],
    int master_uds_cow_fds[],
    int worker_uds_sio_fds[], // Arrays for Worker's side of UDS
    int worker_uds_logic_fds[],
    int worker_uds_cow_fds[],
    pid_t sio_pids[],
    pid_t logic_pids[],
    pid_t cow_pids[]
) {
    // Create and fork SIO workers
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        sio_pids[i] = fork();
        if (sio_pids[i] == -1) {
            LOG_ERROR("%sfork (SIO): %s", label, strerror(errno));
            return FAILURE;
        } else if (sio_pids[i] == 0) {
            // Child (SIO Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) {
                if (j != i && worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]);
            }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]); }
            
            run_server_io_worker(i, worker_uds_sio_fds[i]);
            exit(EXIT_SUCCESS); // Child exits after running worker function
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_sio_fds[i] != 0) close(worker_uds_sio_fds[i]);
            LOG_INFO("%sForked Server IO Worker %d (PID %d).", label, i, sio_pids[i]);
        }
    }

    // Create and fork Logic workers
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        logic_pids[i] = fork();
        if (logic_pids[i] == -1) {
            LOG_ERROR("%sfork (Logic): %s", label, strerror(errno));
            return FAILURE;
        } else if (logic_pids[i] == 0) {
            // Child (Logic Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) {
                if (j != i && worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]);
            }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]); }
            
            run_logic_worker(i, worker_uds_logic_fds[i]);
            exit(EXIT_SUCCESS); // Child exits
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_logic_fds[i] != 0) close(worker_uds_logic_fds[i]);
            LOG_INFO("%sForked Logic Worker %d (PID %d).", label, i, logic_pids[i]);
        }
    }

    // Create and fork Client Outbound workers
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        cow_pids[i] = fork();
        if (cow_pids[i] == -1) {
            LOG_ERROR("%sfork (COW): %s", label, strerror(errno));
            return FAILURE;        
        } else if (cow_pids[i] == 0) {
            // Child (Client Outbound Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) {
                if (j != i && worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]);
            }
            
            run_client_outbound_worker(i, worker_uds_cow_fds[i]);
            exit(EXIT_SUCCESS); // Child exits
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_cow_fds[i] != 0) close(worker_uds_cow_fds[i]);
            LOG_INFO("%sForked Client Outbound Worker %d (PID %d).", label, i, cow_pids[i]);
        }
    }
    return SUCCESS;
}

void run_master_process() {
#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
    log_init();
    pthread_t cleaner_thread;
    pthread_create(&cleaner_thread, NULL, log_cleaner_thread, NULL);
#endif
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);
    LOG_INFO("SIGINT handler installed.");
    
	memset(&node_config, 0, sizeof(node_config_t));
    strncpy(node_config.node_id, "Node1", sizeof(node_config.node_id) - 1);
    node_config.node_id[sizeof(node_config.node_id) - 1] = '\0';
    
    int master_pid = -1;
    int listen_sock = -1;
    async_type_t master_async; // Use the struct for master's epoll
    master_async.async_fd = -1; // Initialize to -1

    // Worker UDS FDs (Master's side of the UDS) - Sized by their specific MAX_*_WORKERS
    int master_uds_sio_fds[MAX_SIO_WORKERS];
    int master_uds_logic_fds[MAX_LOGIC_WORKERS];
    int master_uds_cow_fds[MAX_COW_WORKERS];

    // Worker UDS FDs (Worker's side of the UDS) - Sized by their specific MAX_*_WORKERS
    int worker_uds_sio_fds[MAX_SIO_WORKERS];
    int worker_uds_logic_fds[MAX_LOGIC_WORKERS];
    int worker_uds_cow_fds[MAX_COW_WORKERS];

    // Worker PIDs (to keep track for waitpid later) - Sized by their specific MAX_*_WORKERS
    pid_t sio_pids[MAX_SIO_WORKERS];
    pid_t logic_pids[MAX_LOGIC_WORKERS];
    pid_t cow_pids[MAX_COW_WORKERS];
    
    if (read_network_config_from_json("config.json", &node_config) != SUCCESS) {
        LOG_ERROR("[Master]: Gagal membaca konfigurasi dari %s.", "config.json");
        goto exit;
    }
    
    LOG_INFO("[Master]: --- Node Configuration ---");
    LOG_INFO("[Master]: Node ID: %s", node_config.node_id);
    LOG_INFO("[Master]: Listen Port: %d", node_config.listen_port);
    LOG_INFO("[Master]: Bootstrap Nodes (%d):", node_config.num_bootstrap_nodes);
    for (int i = 0; i < node_config.num_bootstrap_nodes; i++) {
        LOG_INFO("[Master]:   - Node %d: IP %s, Port %d",
                 i + 1, node_config.bootstrap_nodes[i].ip, node_config.bootstrap_nodes[i].port);
    }
    LOG_INFO("[Master]: -------------------------");

    master_pid = getpid();
    LOG_INFO("[Master]: PID %d TCP Server listening on port %d.", master_pid, node_config.listen_port);

    if (setup_socket_listenner("[Master]: ", &listen_sock) != SUCCESS) { goto exit; }
    if (async_create("[Master]: ", &master_async) != SUCCESS) goto exit;
    if (async_create_incoming_event("[Master]: ", &master_async, &listen_sock) != SUCCESS) goto exit;

    // Initialize UDS FDs arrays
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) { master_uds_sio_fds[i] = 0; worker_uds_sio_fds[i] = 0; }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) { master_uds_logic_fds[i] = 0; worker_uds_logic_fds[i] = 0; }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) { master_uds_cow_fds[i] = 0; worker_uds_cow_fds[i] = 0; }

    // Create all UDS pairs and add Master's side to epoll BEFORE forking
    // This ensures child processes inherit a complete (though mostly irrelevant) set of FDs,
    // making explicit closing easier.

    // Create UDS for SIO workers
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            LOG_ERROR("[Master]: socketpair (SIO) creation failed: %s", strerror(errno));
            goto exit;
        }
        set_nonblocking("[Master]: ", sv[0]);
        set_nonblocking("[Master]: ", sv[1]);
        master_uds_sio_fds[i] = sv[0]; // Master's side
        worker_uds_sio_fds[i] = sv[1]; // Worker's side
        if (async_create_incoming_event("[Master]: ", &master_async, &master_uds_sio_fds[i]) != SUCCESS) {
            goto exit;
        }
        LOG_INFO("[Master]: Created UDS pair for SIO Worker %d (Master side: %d, Worker side: %d).", i, master_uds_sio_fds[i], worker_uds_sio_fds[i]);
    }

    // Create UDS for Logic workers
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            LOG_ERROR("[Master]: socketpair (Logic) creation failed: %s", strerror(errno));
            goto exit;
        }
        set_nonblocking("[Master]: ", sv[0]);
        set_nonblocking("[Master]: ", sv[1]);
        master_uds_logic_fds[i] = sv[0]; // Master's side
        worker_uds_logic_fds[i] = sv[1]; // Worker's side
        if (async_create_incoming_event("[Master]: ", &master_async, &master_uds_logic_fds[i]) != SUCCESS) {
            goto exit;
        }
        LOG_INFO("[Master]: Created UDS pair for Logic Worker %d (Master side: %d, Worker side: %d).", i, master_uds_logic_fds[i], worker_uds_logic_fds[i]);
    }

    // Create UDS for COW workers
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            LOG_ERROR("[Master]: socketpair (COW) creation failed: %s", strerror(errno));
            goto exit;
        }
        set_nonblocking("[Master]: ", sv[0]);
        set_nonblocking("[Master]: ", sv[1]);
        master_uds_cow_fds[i] = sv[0]; // Master's side
        worker_uds_cow_fds[i] = sv[1]; // Worker's side
        if (async_create_incoming_event("[Master]: ", &master_async, &master_uds_cow_fds[i]) != SUCCESS) {
            goto exit;
        }
        LOG_INFO("[Master]: Created UDS pair for COW Worker %d (Master side: %d, Worker side: %d).", i, master_uds_cow_fds[i], worker_uds_cow_fds[i]);
    }


    // Call the refactored function to fork workers
    if (setup_fork_workers(
        "[Master]: ",
        listen_sock,
        &master_async, // Pass address of master's async context
        master_uds_sio_fds,
        master_uds_logic_fds,
        master_uds_cow_fds,
        worker_uds_sio_fds,
        worker_uds_logic_fds,
        worker_uds_cow_fds,
        sio_pids,
        logic_pids,
        cow_pids
    ) != SUCCESS) {
        LOG_ERROR("[Master]: Gagal mem-fork worker.");
        goto exit;
    }

    LOG_INFO("[Master]: Starting main event loop. Waiting for clients and worker communications...");

    uint64_t next_client_id = 1ULL; // Global unique client ID
    //double_t avg_connection = 0.0;
    //double_t cnt_connection = 0.0;
    //double_t sio_worker = (double_t)MAX_SIO_WORKERS;

    // Initialize master_client_sessions
    for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
        master_client_sessions[i].in_use = false;
        memset(master_client_sessions[i].ip, 0, INET6_ADDRSTRLEN);
    }

    while (!shutdown_requested) {
		int_status_t snfds = async_wait("[Master]: ", &master_async);
		if (snfds.status == FAILURE_EINTR) continue;
		if (snfds.status == FAILURE) break;
		for (int n = 0; n < snfds.r_int; ++n) {
			int_status_t fd_status = async_getfd("[Master]: ", &master_async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
            if (current_fd == listen_sock) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
                if (client_sock == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("accept (Master)");
                    }
                    continue;
                }
                
                uint8_t client_ip_str[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &client_addr.sin_addr, (char *)client_ip_str, INET6_ADDRSTRLEN) == NULL) {
                    perror("inet_ntop");
                    CLOSE_FD(client_sock);
                    continue;
                }

                // --- Filter: Check if IP is already connected ---
                bool ip_already_connected = false;
                for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
                    if (master_client_sessions[i].in_use &&
                        memcmp(master_client_sessions[i].ip, client_ip_str, INET6_ADDRSTRLEN) == 0) {
                        ip_already_connected = true;
                        break;
                    }
                }

                if (ip_already_connected) {
                    LOG_WARN("[Master]: Koneksi ditolak dari IP %s. Sudah ada koneksi aktif dari IP ini.", client_ip_str);
                    CLOSE_FD(client_sock);
                    continue;
                }
                // --- End Filter ---

                LOG_INFO("[Master]: New client connected from IP %s on FD %d.", client_ip_str, client_sock);

				uint64_t current_client_id = 0ULL;
				closed_correlation_id_t_status_t ccid_result = find_first_closed_correlation_id("[Master]: ", closed_correlation_id_head);
				if (ccid_result.status == SUCCESS) {
					current_client_id = ccid_result.r_closed_correlation_id_t->correlation_id;
					status_t ccid_del_result = delete_closed_correlation_id("[Master]: ", &closed_correlation_id_head, current_client_id);
					if (ccid_del_result != SUCCESS) {
						current_client_id = next_client_id++;
					}
				} else {
					current_client_id = next_client_id++;
				}
				
				if (current_client_id > MAX_MASTER_CONCURRENT_SESSIONS) {
					next_client_id--;
					LOG_ERROR("[Master]: WARNING: MAX_MASTER_CONCURRENT_SESSIONS reached. Rejecting client FD %d.", client_sock);
                    CLOSE_FD(client_sock);
                    continue;
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
                        memcpy(master_client_sessions[i].ip, client_ip_str, INET6_ADDRSTRLEN);
                        slot_found = i;
                        break;
                    }
                }
                if (slot_found == -1) {
                    LOG_ERROR("[Master]: WARNING: No free session slots in master_client_sessions. Rejecting client FD %d.", client_sock);
                    CLOSE_FD(client_sock);
                    continue;
                }
                
                ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_client_request_task(&client_sock, &current_client_id, client_ip_str, (uint16_t)0, NULL);
                if (cmd_result.status != SUCCESS) {
					continue;
				}	
				ssize_t_status_t send_result = send_ipc_protocol_message(&sio_worker_uds_fd, cmd_result.r_ipc_protocol_t, &client_sock);
				if (send_result.status != SUCCESS) {
					LOG_ERROR("[Master]: Failed to forward client FD %d (ID %ld) to Server IO Worker %d.",
							  client_sock, current_client_id, sio_worker_idx);
				} else {
					LOG_INFO("[Master]: Forwarding client FD %d (ID %ld) from IP %s to Server IO Worker %d (UDS FD %d). Bytes sent: %zd.",
							 client_sock, current_client_id, client_ip_str, sio_worker_idx, sio_worker_uds_fd, send_result.r_ssize_t);
					CLOSE_FD(client_sock); // di close jika berhasil Forwarding
				}
				CLOSE_IPC_PROTOCOL(cmd_result.r_ipc_protocol_t);
            }
            else {
                int received_fd = -1;
                ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(&current_fd, &received_fd);
                if (deserialized_result.status != SUCCESS) {
                    perror("recv_ipc_message from worker (Master)");
                    continue;
                }
                ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;                
                switch (received_protocol->type) {
                    case IPC_CLIENT_REQUEST_TASK: {
						
						printf("=========================================Sini 2==================================\n");
						
                        ipc_client_request_task_t *req = received_protocol->payload.ipc_client_request_task;
                        LOG_INFO("[Master]: Received Client Request Task (ID %ld) from Server IO Worker (UDS FD %d).", req->correlation_id, current_fd);

                        int logic_worker_idx = (int)(req->correlation_id % MAX_LOGIC_WORKERS);
                        int logic_worker_uds_fd = master_uds_logic_fds[logic_worker_idx]; // Master uses its side of UDS

                        send_ipc_message(logic_worker_uds_fd, IPC_LOGIC_TASK, req, sizeof(client_request_task_t), -1);
                        LOG_INFO("[Master]: Forwarding client request (ID %ld) to Logic Worker %d (UDS FD %d).",
                               req->correlation_id, logic_worker_idx, logic_worker_uds_fd);
                        break;
                    }
                    /*
                    case IPC_LOGIC_RESPONSE_TO_SIO: {
                        logic_response_t *resp = (logic_response_t *)master_rcv_buffer;
                        LOG_INFO("[Master]: Received Client Response (ID %ld) from Logic Worker (UDS FD %d).", resp->client_correlation_id, current_fd);

                        int target_sio_uds_fd = -1;
                        for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
                            if (master_client_sessions[i].in_use && master_client_sessions[i].correlation_id == resp->client_correlation_id) {
                                target_sio_uds_fd = master_client_sessions[i].sio_uds_fd;
                                master_client_sessions[i].in_use = false;
                                master_client_sessions[i].correlation_id = -1;
                                master_client_sessions[i].sio_uds_fd = -1;
                                memset(master_client_sessions[i].client_ip, 0, sizeof(master_client_sessions[i].client_ip));
                                break;
                            }
                        }

                        if (target_sio_uds_fd != -1) {
                            send_ipc_message(target_sio_uds_fd, IPC_LOGIC_RESPONSE_TO_SIO, resp, sizeof(logic_response_t), -1);
                            LOG_INFO("[Master]: Forwarding client response (ID %ld) to Server IO Worker (UDS FD %d).",
                                   resp->client_correlation_id, target_sio_uds_fd);
                        } else {
                            LOG_ERROR("[Master]: No SIO worker found for client ID %ld for response. Ignoring.", resp->client_correlation_id);
                        }
                        break;
                    }
                    case IPC_OUTBOUND_TASK: {
                        outbound_task_t *task = (outbound_task_t *)master_rcv_buffer;
                        LOG_INFO("[Master]: Received Outbound Task (ID %ld) from Logic Worker (UDS FD %d) for node %s:%d.",
                               task->client_correlation_id, current_fd, task->node_ip, task->node_port);

                        int cow_worker_idx = (int)(task->client_correlation_id % MAX_COW_WORKERS);
                        int cow_uds_fd = master_uds_cow_fds[cow_worker_idx]; // Master uses its side of UDS

                        send_ipc_message(cow_uds_fd, IPC_OUTBOUND_TASK, task, sizeof(outbound_task_t), -1);
                        LOG_INFO("[Master]: Forwarding outbound task (ID %ld) to Client Outbound Worker %d (UDS FD %d).",
                               task->client_correlation_id, cow_worker_idx, cow_uds_fd);
                        break;
                    }
                    case IPC_OUTBOUND_RESPONSE: {
                        outbound_response_t *resp = (outbound_response_t *)master_rcv_buffer;
                        LOG_INFO("[Master]: Received Outbound Response (ID %ld) from Client Outbound Worker (UDS FD %d). Success: %s, Data: '%.*s'",
                               resp->client_correlation_id, current_fd, resp->success ? "true" : "false",
                               (int)resp->response_data_len, resp->response_data);

                        int logic_worker_idx_for_response = (int)(resp->client_correlation_id % MAX_LOGIC_WORKERS);
                        int logic_worker_uds_fd = master_uds_logic_fds[logic_worker_idx_for_response]; // Master uses its side of UDS

                        send_ipc_message(logic_worker_uds_fd, IPC_OUTBOUND_RESPONSE, resp, sizeof(outbound_response_t), -1);
                        LOG_INFO("[Master]: Forwarding outbound response (ID %ld) to Logic Worker %d (UDS FD %d).",
                               resp->client_correlation_id, logic_worker_idx_for_response, logic_worker_uds_fd);
                        break;
                    }
                    */
                    case IPC_CLIENT_DISCONNECTED: {
                        ipc_client_disconnect_info_t *disconnect_info = received_protocol->payload.ipc_client_disconnect_info;
                        add_closed_correlation_id("[Master]: ", &closed_correlation_id_head, disconnect_info->correlation_id); 
                        //cnt_connection -= (double_t)1;
						//avg_connection = cnt_connection / sio_worker;
                        
                        
                        LOG_INFO("[Master]: Received Client Disconnected signal for ID %ld from IP %s (from SIO Worker UDS FD %d).",
                                 disconnect_info->correlation_id, disconnect_info->ip, current_fd);

                        for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
							
							LOG_INFO("Searching(%d) IP %s ?? %s|CI %llu ?? %llu",
                                 INET6_ADDRSTRLEN, master_client_sessions[i].ip, disconnect_info->ip,
                                 master_client_sessions[i].correlation_id, disconnect_info->correlation_id
                                 );
                                 
                            if (master_client_sessions[i].in_use &&
                                master_client_sessions[i].correlation_id == disconnect_info->correlation_id &&
                                memcmp(master_client_sessions[i].ip, disconnect_info->ip, INET6_ADDRSTRLEN) == 0) {
                                master_client_sessions[i].in_use = false;
                                master_client_sessions[i].correlation_id = -1;
                                master_client_sessions[i].sio_uds_fd = -1;
                                memset(master_client_sessions[i].ip, 0, INET6_ADDRSTRLEN);
                                LOG_INFO("[Master]: IP %s (ID %ld) dihapus dari daftar koneksi aktif.",
                                         disconnect_info->ip, disconnect_info->correlation_id);
                                break;
                            }
                        }
                        break;
                    }
                    default:
                        LOG_ERROR("[Master]: Unknown message type %d from UDS FD %d. Ignoring.", received_protocol->type, current_fd);
                        break;
                }
                CLOSE_IPC_PROTOCOL(received_protocol);
            }
        }
    }

exit:
    orisium_cleanup(
        &listen_sock,
        &master_async, // Pass address of the FD
        master_uds_sio_fds,
        master_uds_logic_fds,
        master_uds_cow_fds,
        worker_uds_sio_fds, // Pass worker sides for cleanup
        worker_uds_logic_fds,
        worker_uds_cow_fds,
        sio_pids,
        logic_pids,
        cow_pids
    );
    free_closed_correlation_ids("[Master]: ", &closed_correlation_id_head);
    
    memset(&node_config, 0, sizeof(node_config_t));
#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))    
	pthread_join(cleaner_thread, NULL);
    log_close();
#endif
}
