#ifndef IPC_CLIENT_DISCONNECT_INFO_H
#define IPC_CLIENT_DISCONNECT_INFO_H

#include <stdlib.h>

status_t ipc_serialize_client_disconnect_info(const ipc_client_disconnect_info_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_client_disconnect_info(ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_client_disconnect_info(int *current_fd, uint64_t *correlation_id, uint8_t disconnected_client_ip[]);


#endif
