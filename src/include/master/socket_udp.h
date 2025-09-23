#ifndef MASTER_SOCKET_UDP_H
#define MASTER_SOCKET_UDP_H

#include "master/master.h"

status_t setup_master_socket_udp(const char *label, master_context_t *master_ctx);
status_t handle_master_udp_sock_event(const char *label, master_context_t *master_ctx);

#endif
