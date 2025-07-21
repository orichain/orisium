#ifndef ORILINK_SYNDT_H
#define ORILINK_SYNDT_H

status_t orilink_serialize_syndt(const char *label, const orilink_syndt_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t orilink_deserialize_syndt(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
orilink_protocol_t_status_t orilink_prepare_cmd_syndt(const char *label, uint64_t id, uint64_t sid, uint8_t trycount, orilink_mode_t mode, uint16_t dtsize, uint16_t mbpp);

#endif
