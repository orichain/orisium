#ifndef under_refinement_and_will_be_delete_after_finished_H
#define under_refinement_and_will_be_delete_after_finished_H

#include <stdbool.h>
#include "node.h"
#include "ipc/protocol.h"
#include "async.h"

typedef struct {
    ipc_protocol_type_t type;
    size_t data_len;
} ipc_msg_header_t;

// --- Data Structures for Tasks/Messages (from ipc.h/types.h) ---
typedef struct {
    long client_correlation_id;
    char request_data[MAX_DATA_BUFFER_IN_STRUCT];
    size_t request_data_len;
} client_request_task_t;

typedef struct {
    long client_correlation_id;
    char response_data[MAX_DATA_BUFFER_IN_STRUCT];
    size_t response_data_len;
} logic_response_t;

typedef struct {
    long client_correlation_id;
    char node_ip[INET6_ADDRSTRLEN];
    int node_port;
    char request_data[MAX_DATA_BUFFER_IN_STRUCT];
    size_t request_data_len;
} outbound_task_t;

typedef struct {
    long client_correlation_id;
    bool success;
    char response_data[MAX_DATA_BUFFER_IN_STRUCT];
    size_t response_data_len;
} outbound_response_t;

typedef struct {
    long client_correlation_id;
    char client_ip[INET6_ADDRSTRLEN]; // IP dari klien yang terputus
} client_disconnect_info_t;

ssize_t send_ipc_message(int uds_fd, ipc_protocol_type_t type, const void *data, size_t data_len, int fd_to_pass);
ssize_t recv_ipc_message(int uds_fd, ipc_msg_header_t *header, void *data_buffer, size_t buffer_size, int *actual_fd_received);
void orisium_cleanup(int *listen_sock_ptr, async_type_t *async_fd_ptr,
                     int uds_sio_fds_master_side[], int uds_logic_fds_master_side[], int uds_cow_fds_master_side[],
                     int uds_sio_fds_worker_side[], int uds_logic_fds_worker_side[], int uds_cow_fds_worker_side[],
                     pid_t sio_pids[], pid_t logic_pids[], pid_t cow_pids[]);
status_t setup_fork_workers(
    const char* label,
    int listen_sock, // listen_sock passed by value, as it's closed in child
    async_type_t *async,
    int master_uds_sio_fds[], // Arrays for Master's side of UDS
    int master_uds_logic_fds[],
    int master_uds_cow_fds[],
    int worker_uds_sio_fds[], // Arrays for Worker's side of UDS
    int worker_uds_logic_fds[],
    int worker_uds_cow_fds[],
    pid_t sio_pids[],
    pid_t logic_pids[],
    pid_t cow_pids[]
);

#endif
