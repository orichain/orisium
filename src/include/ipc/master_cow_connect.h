#ifndef IPC_MASTER_COW_CONNECT_H
#define IPC_MASTER_COW_CONNECT_H

status_t ipc_serialize_master_cow_connect(const char *label, const ipc_master_cow_connect_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_master_cow_connect(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_master_cow_connect(const char *label, struct sockaddr_in6 *server_addr);

#endif
