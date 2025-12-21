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

#if defined(__NetBSD__)
    #include <sys/signal.h>
    #if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
        #include <pthread_types.h>
    #endif
#elif defined(__OpenBSD__)
    #include <sys/signal.h>
#elif defined(__FreeBSD__)
    #include <sys/signal.h>
    #if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
        #include <sys/_pthreadtypes.h>
    #endif
#endif

#include "log.h"
#include "node.h"
#include "master/master.h"
#include "utilities.h"
#include "types.h"
#include "globals.h"

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
	if (ensure_directory_exists("[Orisium]: ", "./database") != SUCCESS) goto exit2;
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
	master_context_t master_ctx;
    master_ctx.listen_port = (uint16_t)0;
    memset(&master_ctx.bootstrap_nodes, 0, sizeof(bootstrap_nodes_t));
    if (read_listen_port_and_bootstrap_nodes_from_json(
        "[Orisium]: ", 
        "config.json", 
        &master_ctx.listen_port, 
        &master_ctx.bootstrap_nodes
        ) != SUCCESS
    )
    {
        LOG_ERROR("[Master]: Gagal membaca konfigurasi dari %s.", "config.json");
        goto exit2;
    }
    printf("[Master]: --- Node Configuration ---\n");
    printf("[Master]: Listen Port: %d\n", master_ctx.listen_port);
    printf("[Master]: Bootstrap Nodes (%d):\n", master_ctx.bootstrap_nodes.len);
    for (int i = 0; i < master_ctx.bootstrap_nodes.len; i++) {
        char host_str[NI_MAXHOST];
        char port_str[NI_MAXSERV];
        int getname_res = getnameinfo((struct sockaddr *)&master_ctx.bootstrap_nodes.addr[i], sizeof(struct sockaddr_in6),
                            host_str, NI_MAXHOST,
                            port_str, NI_MAXSERV,
                            NI_NUMERICHOST | NI_NUMERICSERV
                          );
        if (getname_res != 0) {
            LOG_ERROR("[Master]: getnameinfo failed. %s", strerror(errno));
            goto exit2;
        }
        printf("[Master]:   - Node %d: IP %s, Port %s\n", i + 1, host_str, port_str);
    }
    printf("[Master]: -------------------------\n");
    if (setup_master("[Master]: ", &master_ctx) != SUCCESS) goto exit1;
    run_master("[Master]: ", &master_ctx);
//======================================================================
// Cleanup
//======================================================================
exit1:
    cleanup_master("[Master]: ", &master_ctx);
exit2:
#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
    shutdown_requested = 1;
	pthread_join(cleaner_thread, NULL);
    log_close();
#endif
	printf("[Orisium]: ==========================================================\n");
    printf("[Orisium]: Orisium selesai dijalankan.\n");
    printf("[Orisium]: ==========================================================\n");
    return 0;
}
