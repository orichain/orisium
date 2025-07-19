#ifndef ORILINK_SYN_ACK_H
#define ORILINK_SYN_ACK_H

status_t orilink_serialize_syn_ack(const char *label, const orilink_syn_ack_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t orilink_deserialize_syn_ack(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
orilink_protocol_t_status_t orilink_prepare_cmd_syn_ack(const char *label, uint64_t *id);

#endif
