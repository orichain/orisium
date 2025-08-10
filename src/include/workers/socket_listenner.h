#ifndef WORKERS_SOCKET_LISTENNER_H
#define WORKERS_SOCKET_LISTENNER_H

status_t setup_cow_socket_listenner(worker_context_t *worker_ctx, cow_c_session_t *single_session);
bool server_disconnected(worker_context_t *worker_ctx, int session_index, cow_c_session_t *single_session, uint8_t try_count);
status_t send_hello1(worker_context_t *worker_ctx, cow_c_session_t *single_session);
status_t send_hello2(worker_context_t *worker_ctx, cow_c_session_t *single_session);
status_t send_hello3(worker_context_t *worker_ctx, cow_c_session_t *single_session);
status_t send_hello_end(worker_context_t *worker_ctx, cow_c_session_t *single_session);
void cow_calculate_retry(worker_context_t *worker_ctx, cow_c_session_t *single_session, int session_index, double try_count);
void cow_calculate_rtt(worker_context_t *worker_ctx, cow_c_session_t *single_session, int session_index, double rtt_value);

#endif
