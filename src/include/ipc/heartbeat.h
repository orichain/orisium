#ifndef IPC_HEARTBEAT_H
#define IPC_HEARTBEAT_H

status_t ipc_serialize_heartbeat(const char *label, const ipc_heartbeat_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_heartbeat(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_heartbeat(const char *label, int *fd_to_close, worker_type_t wot, uint8_t index, double hbtime);

#endif
