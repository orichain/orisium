#ifndef MASTER_SERVER_ORILINK_H
#define MASTER_SERVER_ORILINK_H

status_t send_hello1_ack(const char *label, int *listen_sock, master_sio_c_session_t *session);
status_t send_hello2_ack(const char *label, int *listen_sock, master_sio_c_session_t *session);
status_t send_hello3_ack(const char *label, int *listen_sock, master_sio_c_session_t *session);
void sio_c_calculate_retry(const char *label, master_sio_c_session_t *session, int session_index, double try_count);
void sio_c_calculate_rtt(const char *label, master_sio_c_session_t *session, int session_index, double rtt_value);

#endif
