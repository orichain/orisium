#ifndef IPC_MASTER_COW_CONNECT_H
#define IPC_MASTER_COW_CONNECT_H

status_t ipc_serialize_master_cow_connect(const char *label, const ipc_master_cow_connect_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_master_cow_connect(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_master_cow_connect(const char *label, worker_type_t wot, uint8_t index, uint8_t session_index, uint64_t id_connection, struct sockaddr_in6 *remote_addr);

#endif
