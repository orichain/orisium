#ifndef ORILINK_FINDT_H
#define ORILINK_FINDT_H

status_t orilink_serialize_findt(const char *label, const orilink_findt_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t orilink_deserialize_findt(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
orilink_protocol_t_status_t orilink_prepare_cmd_findt(const char *label, uint64_t id, uint64_t sid, uint8_t trycount);

#endif
