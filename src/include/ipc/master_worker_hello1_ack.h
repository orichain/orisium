#ifndef IPC_MASTER_WORKER_HELLO1_ACK_H
#define IPC_MASTER_WORKER_HELLO1_ACK_H

status_t ipc_serialize_master_worker_hello1_ack(const char *label, const ipc_master_worker_hello1_ack_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_master_worker_hello1_ack(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_master_worker_hello1_ack(const char *label, worker_type_t wot, uint8_t index, uint8_t *nonce, uint8_t *kem_ciphertext);

#endif
