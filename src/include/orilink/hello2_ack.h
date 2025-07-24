#ifndef ORILINK_HELLO2_ACK_H
#define ORILINK_HELLO2_ACK_H

status_t orilink_serialize_hello2_ack(const char *label, const orilink_hello2_ack_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t orilink_deserialize_hello2_ack(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
orilink_protocol_t_status_t orilink_prepare_cmd_hello2_ack(const char *label, uint64_t client_id, uint8_t *ciphertext, uint8_t trycount);

#endif
