#ifndef MASTER_IPC_HANDLERS_H
#define MASTER_IPC_HANDLERS_H

#include "master/master.h"

status_t handle_master_ipc_hello1(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, int rcvd_index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_hello2(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, int rcvd_index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_heartbeat(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, int rcvd_index, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_udp_data(const char *label, master_context_t *master_ctx, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi);

status_t handle_master_ipc_event(const char *label, master_context_t *master_ctx, int *current_fd);
worker_type_t_status_t handle_master_ipc_closed_event(const char *label, master_context_t *master_ctx, int *current_fd);

#endif
