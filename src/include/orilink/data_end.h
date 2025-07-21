#ifndef ORILINK_DATA_END_H
#define ORILINK_DATA_END_H

status_t orilink_serialize_data_end(const char *label, const orilink_data_end_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t orilink_deserialize_data_end(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
orilink_protocol_t_status_t orilink_prepare_cmd_data_end(const char *label, uint64_t id, uint64_t sid, uint16_t spktnum, uint8_t trycount);

#endif
