#ifndef IPC_WORKER_MASTER_HELLO2_H
#define IPC_WORKER_MASTER_HELLO2_H

status_t ipc_serialize_worker_master_hello2(const char *label, const ipc_worker_master_hello2_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_worker_master_hello2(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_worker_master_hello2(const char *label, uint8_t *encrypted_wot_index);

#endif
