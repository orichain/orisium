#ifndef IPC_LOGIC_RESPONSE_H
#define IPC_LOGIC_RESPONSE_H

status_t ipc_serialize_logic_response(const ipc_logic_response_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_logic_response(ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);

#endif
