#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
	#include <pthread.h>
#endif

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>

#include "log.h"
#include "node.h"
#include "sessions/master_session.h"
#include "master/process.h"
#include "utilities.h"
#include "types.h"

volatile sig_atomic_t shutdown_requested = 0;
node_config_t node_config;
master_sio_dc_session_t *master_sio_dc_session_head = NULL;
int *shutdown_event_fd = NULL;

void sigint_handler(int signum) {
    shutdown_requested = 1ULL;
    //LOG_INFO("[Orisium]: SIGINT received. Initiating graceful shutdown...");
    if (shutdown_event_fd && *shutdown_event_fd != -1) {
        static const uint64_t u = 1ULL;
        write(*shutdown_event_fd, &u, sizeof(uint64_t));
    }
}

int main() {
	printf("[Orisium]: ==========================================================\n");
    printf("[Orisium]: Orisium dijalankan.\n");
    printf("[Orisium]: ==========================================================\n");
    
#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
    log_init();
    pthread_t cleaner_thread;
    pthread_create(&cleaner_thread, NULL, log_cleaner_thread, NULL);
#endif
//======================================================================
// Configuring node and bootstrap
//======================================================================
	if (ensure_directory_exists("[Orisium]: ", "./database") != SUCCESS) goto exit;
//======================================================================    
	memset(&node_config, 0, sizeof(node_config_t));
    strncpy(node_config.node_id, "Node1", sizeof(node_config.node_id) - 1);
    node_config.node_id[sizeof(node_config.node_id) - 1] = '\0';
    if (read_network_config_from_json("[Orisium]: ", "config.json", &node_config) != SUCCESS) {
        LOG_ERROR("[Orisium]: Gagal membaca konfigurasi dari %s.", "config.json");
        goto exit;
    }    
    LOG_INFO("[Orisium]: --- Node Configuration ---");
    LOG_INFO("[Orisium]: Node ID: %s", node_config.node_id);
    LOG_INFO("[Orisium]: Listen Port: %d", node_config.listen_port);
    LOG_INFO("[Orisium]: Bootstrap Nodes (%d):", node_config.num_bootstrap_nodes);
    for (int i = 0; i < node_config.num_bootstrap_nodes; i++) {
		char ip_str[INET6_ADDRSTRLEN];
		if (convert_ipv6_bin_to_str(node_config.bootstrap_nodes[i].ip, ip_str) != SUCCESS)goto exit;
        LOG_INFO("[Orisium]:   - Node %d: IP %s, Port %d", i + 1, ip_str, node_config.bootstrap_nodes[i].port);
    }
    LOG_INFO("[Orisium]: -------------------------");
//======================================================================
// Install sigint handler
//======================================================================    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);
    LOG_INFO("[Orisium]: SIGINT handler installed.");
//======================================================================
// Master
//======================================================================
	master_context master_ctx;
    if (setup_master(&master_ctx) != SUCCESS) goto exit;
    shutdown_event_fd = &master_ctx.shutdown_event_fd;
    if (setup_workers(&master_ctx) != SUCCESS) goto exit;
	run_master_process(&master_ctx);
//======================================================================
// Cleanup
//======================================================================
exit:
	free_master_sio_dc_sessions("[Orisium]: ", &master_sio_dc_session_head);
#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))    
	pthread_join(cleaner_thread, NULL);
    log_close();
#endif
	
	printf("[Orisium]: ==========================================================\n");
    printf("[Orisium]: Orisium selesai dijalankan.\n");
    printf("[Orisium]: ==========================================================\n");
    
    return 0;
}
