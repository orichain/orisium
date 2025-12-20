#ifndef MASTER_UDP_HANDLERS_H
#define MASTER_UDP_HANDLERS_H

#include "master/master.h"
#include "types.h"

status_t handle_master_ipv4_udp_sock_event(const char *label, master_context_t *master_ctx);
status_t handle_master_ipv6_udp_sock_event(const char *label, master_context_t *master_ctx);

#endif
