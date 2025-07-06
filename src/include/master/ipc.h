#ifndef MASTER_IPC_H
#define MASTER_IPC_H

status_t handle_ipc_event(const char *label, master_client_session_t master_client_sessions[], int master_uds_logic_fds[], int master_uds_cow_fds[], int *current_fd);

#endif
