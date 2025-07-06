#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
	#include <pthread.h>
#endif

#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdbool.h>     // for false, bool, true
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <sys/socket.h>  // for socketpair, SOCK_STREAM, AF_UNIX, AF_INET, accept
#include <sys/types.h>   // for pid_t, ssize_t
#include <unistd.h>      // for close, fork, getpid
#include <signal.h>      // for sig_atomic_t, sigaction, SIGINT
#include <bits/types/sig_atomic_t.h>
#include <stdint.h>

#include "log.h"
#include "constants.h"
#include "node.h"
#include "async.h"
#include "utilities.h"
#include "sessions/closed_correlation_id.h"
#include "sessions/master_client_session.h"
#include "under_refinement_and_will_be_delete_after_finished.h"
#include "types.h"
#include "master/socket_listenner.h"
#include "master/ipc.h"

volatile sig_atomic_t shutdown_requested = 0;
node_config_t node_config;
master_client_session_t *master_client_session_head = NULL;
closed_correlation_id_t *closed_correlation_id_head = NULL;

void sigint_handler(int signum) {
    shutdown_requested = 1;
    LOG_INFO("SIGINT received. Initiating graceful shutdown...");
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

	master_client_session_t master_client_sessions[MAX_MASTER_CONCURRENT_SESSIONS];
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
                if (handle_listen_sock_event("[Master]: ", master_client_sessions, master_uds_sio_fds, &next_client_id, &listen_sock) != SUCCESS) {
					continue;
				}
            } else {
                if (handle_ipc_event("[Master]: ", master_client_sessions, master_uds_logic_fds, master_uds_cow_fds, &current_fd) != SUCCESS) {
					continue;
				}
            }
        }
    }

exit:
    orisium_cleanup(
        &listen_sock,
        &master_async,
        master_uds_sio_fds,
        master_uds_logic_fds,
        master_uds_cow_fds,
        worker_uds_sio_fds,
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
