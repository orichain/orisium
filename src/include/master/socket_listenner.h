#ifndef MASTER_SOCKET_LISTENNER_H
#define MASTER_SOCKET_LISTENNER_H

#include "master/process.h"

status_t setup_socket_listenner(const char *label, master_context *master_ctx);
status_t handle_listen_sock_event(const char *label, master_context *master_ctx, master_client_session_t master_client_sessions[], uint64_t *next_client_id);

#endif
