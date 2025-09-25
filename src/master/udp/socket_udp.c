#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "log.h"
#include "utilities.h"
#include "types.h"
#include "master/udp/socket_udp.h"
#include "master/master.h"

status_t setup_master_socket_udp(const char *label, master_context_t *master_ctx) {
    struct sockaddr_in6 addr;
    int opt = 1;
    int v6only = 0;
    
    master_ctx->udp_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (master_ctx->udp_sock == -1) {
		LOG_ERROR("%ssocket failed. %s", label, strerror(errno));
        return FAILURE;
    }
    status_t r_snbkg = set_nonblocking(label, master_ctx->udp_sock);
    if (r_snbkg != SUCCESS) {
        LOG_ERROR("%sset_nonblocking failed.", label);
        return r_snbkg;
    }
    if (setsockopt(master_ctx->udp_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        LOG_ERROR("%ssetsockopt failed. %s", label, strerror(errno));
        return FAILURE;
    }
    if (setsockopt(master_ctx->udp_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
		LOG_ERROR("%ssetsockopt failed. %s", label, strerror(errno));
        return FAILURE;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(master_ctx->listen_port);
    addr.sin6_addr = in6addr_any;
    if (bind(master_ctx->udp_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("%sbind failed. %s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}
