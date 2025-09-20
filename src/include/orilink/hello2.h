#ifndef ORILINK_HELLO2_H
#define ORILINK_HELLO2_H

status_t orilink_serialize_hello2(const char *label, const orilink_hello2_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t orilink_deserialize_hello2(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
orilink_protocol_t_status_t orilink_prepare_cmd_hello2(
    const char *label, 
    uint8_t inc_ctr, 
    worker_type_t remote_wot, 
    uint8_t remote_index, 
    uint8_t remote_session_index, 
    worker_type_t local_wot, 
    uint8_t local_index, 
    uint8_t local_session_index, 
    uint64_t local_id, 
    uint8_t *publickey, 
    uint8_t trycount
);

#endif
