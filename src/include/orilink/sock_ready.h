#ifndef ORILINK_SOCK_READY_H
#define ORILINK_SOCK_READY_H

status_t orilink_serialize_sock_ready(const char *label, const orilink_sock_ready_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t orilink_deserialize_sock_ready(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
orilink_protocol_t_status_t orilink_prepare_cmd_sock_ready(const char *label, uint64_t client_id, uint64_t server_id, uint16_t port, uint8_t trycount);

#endif
