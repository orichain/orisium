#ifndef IPC_WORKER_MASTER_TASK_INFO_H
#define IPC_WORKER_MASTER_TASK_INFO_H

status_t ipc_serialize_worker_master_task_info(const char *label, const ipc_worker_master_task_info_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_worker_master_task_info(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_worker_master_task_info(const char *label, worker_type_t wot, uint8_t index, uint8_t session_index, task_info_type_t flag);

#endif
