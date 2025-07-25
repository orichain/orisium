#ifndef MASTER_SERVER_ORILINK_CMDS_H
#define MASTER_SERVER_ORILINK_CMDS_H

status_t hello1_ack(const char *label, int *listen_sock, master_sio_c_session_t *session);
status_t send_hello1_ack(const char *label, int *listen_sock, master_sio_c_session_t *session);

#endif
