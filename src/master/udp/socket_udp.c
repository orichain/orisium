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
    struct sockaddr_in6 ipv6_addr;
    struct sockaddr_in ipv4_addr;
    int v6only = 1;

    master_ctx->ipv4_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (master_ctx->ipv4_udp == -1) {
        LOG_ERROR("%ssocket failed. %s", label, strerror(errno));
        return FAILURE;
    }
    master_ctx->ipv6_udp = socket(AF_INET6, SOCK_DGRAM, 0);
    if (master_ctx->ipv6_udp == -1) {
		LOG_ERROR("%ssocket failed. %s", label, strerror(errno));
        return FAILURE;
    }
    status_t r_snbkg = set_nonblocking(label, master_ctx->ipv4_udp);
    if (r_snbkg != SUCCESS) {
        LOG_ERROR("%sset_nonblocking failed.", label);
        return r_snbkg;
    }
    r_snbkg = set_nonblocking(label, master_ctx->ipv6_udp);
    if (r_snbkg != SUCCESS) {
        LOG_ERROR("%sset_nonblocking failed.", label);
        return r_snbkg;
    }
    if (setsockopt(master_ctx->ipv6_udp, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
		LOG_ERROR("%ssetsockopt failed. %s", label, strerror(errno));
        return FAILURE;
    }
    memset(&ipv4_addr, 0, sizeof(struct sockaddr_in));
    ipv4_addr.sin_family = AF_INET;
    ipv4_addr.sin_port = htons(master_ctx->listen_port);
    ipv4_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    memset(&ipv6_addr, 0, sizeof(struct sockaddr_in6));
    ipv6_addr.sin6_family = AF_INET6;
    ipv6_addr.sin6_port = htons(master_ctx->listen_port);
    ipv6_addr.sin6_addr = in6addr_any;
    if (bind(master_ctx->ipv4_udp, (struct sockaddr *)&ipv4_addr, sizeof(struct sockaddr_in)) < 0) {
        LOG_ERROR("%sbind failed. %s", label, strerror(errno));
        return FAILURE;
    }
    if (bind(master_ctx->ipv6_udp, (struct sockaddr *)&ipv6_addr, sizeof(struct sockaddr_in6)) < 0) {
        LOG_ERROR("%sbind failed. %s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}
