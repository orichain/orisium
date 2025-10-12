#ifndef IPC_UDP_DATA_H
#define IPC_UDP_DATA_H

status_t ipc_serialize_udp_data(const char *label, const ipc_udp_data_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_udp_data(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_udp_data(
    const char *label, 
    worker_type_t wot, 
    uint8_t index, 
    uint8_t session_index, 
    uint8_t orilink_protocol, 
    uint8_t trycount,
    struct sockaddr_in6 *remote_addr, 
    uint16_t len, 
    uint8_t *data
);

#endif
