#ifndef MASTER_IPC_H
#define MASTER_IPC_H

#include "master/process.h"

status_t handle_ipc_event(const char *label, master_context *master_ctx, int *current_fd);
worker_type_t_status_t handle_ipc_closed_event(const char *label, master_context *master_ctx, int *current_fd);

#endif
