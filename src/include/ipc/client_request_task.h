#ifndef IPC_CLIENT_REQUEST_TASK_H
#define IPC_CLIENT_REQUEST_TASK_H

status_t ipc_serialize_client_request_task(const char *label, const ipc_client_request_task_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_client_request_task(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_client_request_task(const char *label, int *fd_to_close, uint8_t client_ip_for_request[], uint16_t data_len, uint8_t *data);

#endif
