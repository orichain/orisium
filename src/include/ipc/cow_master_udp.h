#ifndef IPC_COW_MASTER_UDP_H
#define IPC_COW_MASTER_UDP_H

status_t ipc_serialize_cow_master_udp(const char *label, const ipc_cow_master_udp_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_cow_master_udp(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_cow_master_udp(const char *label, worker_type_t wot, uint8_t index, struct sockaddr_in6 *remote_addr, uint16_t len, uint8_t *data);

#endif
