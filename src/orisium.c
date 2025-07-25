#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
	#include <pthread.h>
#endif

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>

#include "log.h"
#include "node.h"
#include "master/process.h"
#include "utilities.h"
#include "types.h"

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
    uint16_t listen_port = 0;
    bootstrap_nodes_t bootstrap_nodes;
    memset(&bootstrap_nodes, 0, sizeof(bootstrap_nodes_t));
    if (read_listen_port_and_bootstrap_nodes_from_json("[Orisium]: ", "config.json", &listen_port, &bootstrap_nodes) != SUCCESS) {
        LOG_ERROR("[Orisium]: Gagal membaca konfigurasi dari %s.", "config.json");
        goto exit;
    }    
    LOG_INFO("[Orisium]: --- Node Configuration ---");
    LOG_INFO("[Orisium]: Listen Port: %d", listen_port);
    LOG_INFO("[Orisium]: Bootstrap Nodes (%d):", bootstrap_nodes.len);
    for (int i = 0; i < bootstrap_nodes.len; i++) {
        char host_str[NI_MAXHOST];
        char port_str[NI_MAXSERV];
        int getname_res = getnameinfo((struct sockaddr *)&bootstrap_nodes.addr[i], sizeof(bootstrap_nodes.addr[i]),
                            host_str, NI_MAXHOST,
                            port_str, NI_MAXSERV,
                            NI_NUMERICHOST | NI_NUMERICSERV
                          );
        if (getname_res != 0) {
            LOG_ERROR("[Orisium]: getnameinfo failed. %s", strerror(errno));
            goto exit;
        }
        LOG_INFO("[Orisium]:   - Node %d: IP %s, Port %s", i + 1, host_str, port_str);
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
    run_master_process(&master_ctx, &listen_port, &bootstrap_nodes);
//======================================================================
// Cleanup
//======================================================================
exit:
    memset(&bootstrap_nodes, 0, sizeof(bootstrap_nodes_t));
#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))    
	pthread_join(cleaner_thread, NULL);
    log_close();
#endif
	
	printf("[Orisium]: ==========================================================\n");
    printf("[Orisium]: Orisium selesai dijalankan.\n");
    printf("[Orisium]: ==========================================================\n");
    
    return 0;
}
