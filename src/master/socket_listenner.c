#include <arpa/inet.h>     // for htons
#include <errno.h>         // for errno
#include <netinet/in.h>    // for sockaddr_in, INADDR_ANY, in_addr
#include <string.h>        // for strerror, memset
#include <sys/socket.h>    // for AF_INET, bind, listen, setsockopt, socket

#include "log.h"
#include "types.h"
#include "utilities.h"
#include "node.h"

status_t setup_socket_listenner(const char *label, int *listen_sock) {
    struct sockaddr_in6 addr;
    int opt = 1;
    int v6only = 0;
    
    *listen_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (*listen_sock == -1) {
		LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
    }
    if (set_nonblocking(label, *listen_sock) != SUCCESS) {
        LOG_ERROR("%s%s", label, strerror(errno));
        return FAILURE;
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
