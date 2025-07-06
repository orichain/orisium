#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
	#include <pthread.h>
#endif

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "log.h"
#include "node.h"
#include "sessions/closed_correlation_id.h"
#include "types.h"
#include "master/process.h"

volatile sig_atomic_t shutdown_requested = 0;
node_config_t node_config;
closed_correlation_id_t *closed_correlation_id_head = NULL;

void sigint_handler(int signum) {
    shutdown_requested = 1;
    LOG_INFO("SIGINT received. Initiating graceful shutdown...");
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
// Install sigint handler
//======================================================================    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);
    LOG_INFO("SIGINT handler installed.");
//======================================================================
// Configuring node and bootstrap
//======================================================================
	memset(&node_config, 0, sizeof(node_config_t));
    strncpy(node_config.node_id, "Node1", sizeof(node_config.node_id) - 1);
    node_config.node_id[sizeof(node_config.node_id) - 1] = '\0';
    if (read_network_config_from_json("config.json", &node_config) != SUCCESS) {
        LOG_ERROR("[Orisium]: Gagal membaca konfigurasi dari %s.", "config.json");
        goto exit;
    }    
    LOG_INFO("[Orisium]: --- Node Configuration ---");
    LOG_INFO("[Orisium]: Node ID: %s", node_config.node_id);
    LOG_INFO("[Orisium]: Listen Port: %d", node_config.listen_port);
    LOG_INFO("[Orisium]: Bootstrap Nodes (%d):", node_config.num_bootstrap_nodes);
    for (int i = 0; i < node_config.num_bootstrap_nodes; i++) {
        LOG_INFO("[Orisium]:   - Node %d: IP %s, Port %d", i + 1, node_config.bootstrap_nodes[i].ip, node_config.bootstrap_nodes[i].port);
    }
    LOG_INFO("[Orisium]: -------------------------");
//======================================================================
// Master
//======================================================================
	master_context master_ctx;
    if (setup_master(&master_ctx) != SUCCESS) goto exit;
    if (setup_workers(&master_ctx) != SUCCESS) goto exit;
	run_master_process(&master_ctx);
//======================================================================
// Cleanup
//======================================================================
exit:
	free_closed_correlation_ids("[Orisium]: ", &closed_correlation_id_head);
#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))    
	pthread_join(cleaner_thread, NULL);
    log_close();
#endif
	
	printf("[Orisium]: ==========================================================\n");
    printf("[Orisium]: Orisium selesai dijalankan.\n");
    printf("[Orisium]: ==========================================================\n");
    
    return 0;
}
