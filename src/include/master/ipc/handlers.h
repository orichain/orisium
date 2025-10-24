#ifndef MASTER_IPC_HANDLERS_H
#define MASTER_IPC_HANDLERS_H

#include <stdint.h>

#include "master/master.h"
#include "ipc/protocol.h"
#include "types.h"

status_t handle_master_ipc_hello1(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_hello2(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, worker_rekeying_t *rekeying, const char *worker_name, int *worker_uds_fd, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_heartbeat(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_udp_data(const char *label, master_context_t *master_ctx, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_task_info(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi);

status_t handle_master_ipc_event(const char *label, master_context_t *master_ctx, int *file_descriptor);
status_t handle_master_ipc_closed_event(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, int *file_descriptor);

#endif
