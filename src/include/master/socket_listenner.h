#ifndef MASTER_SOCKET_LISTENNER_H
#define MASTER_SOCKET_LISTENNER_H

#include "master/process.h"
#include "sessions/master_session.h"

status_t setup_socket_listenner(const char *label, master_context *master_ctx);
status_t handle_listen_sock_event(const char *label, master_context *master_ctx);

#endif
