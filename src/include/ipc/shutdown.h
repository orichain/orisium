#ifndef IPC_SHUTDOWN_H
#define IPC_SHUTDOWN_H

status_t ipc_serialize_shutdown(const ipc_shutdown_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_shutdown(ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_shutdown(int *fd_to_close);

#endif
