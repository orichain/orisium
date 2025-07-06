#ifndef MASTER_SOCKET_LISTENNER_H
#define MASTER_SOCKET_LISTENNER_H

status_t setup_socket_listenner(const char *label, int *listen_sock);
status_t handle_listen_sock_event(const char *label, master_client_session_t master_client_sessions[], int master_uds_sio_fds[], uint64_t *next_client_id, int *listen_sock);

#endif
