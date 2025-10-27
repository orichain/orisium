#ifndef WORKERS_WORKER_IPC_H
#define WORKERS_WORKER_IPC_H

#include <inttypes.h>

#include "ipc/protocol.h"
#include "orilink/protocol.h"
#include "types.h"
#include "workers/workers.h"

struct sockaddr_in6;

status_t worker_master_heartbeat(worker_context_t *ctx, double new_heartbeat_interval_double);
status_t worker_master_hello1(worker_context_t *ctx);
status_t worker_master_hello2(worker_context_t *ctx, uint8_t encrypted_wot_index2[]);
status_t worker_master_udp_data_ack_send_ipc(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol, 
    uint8_t trycount,
    struct sockaddr_in6 *addr,
    control_packet_ack_t *h
);
status_t worker_master_udp_data_send_ipc(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol, 
    uint8_t trycount,
    struct sockaddr_in6 *addr,
    control_packet_t *h
);
status_t worker_master_task_info(worker_context_t *ctx, uint8_t session_index, task_info_type_t flag);
status_t handle_workers_ipc_info(worker_context_t *worker_ctx, double *initial_delay_ms, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_workers_ipc_cow_connect(worker_context_t *worker_ctx, void *worker_sessions, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_workers_ipc_hello1_ack(worker_context_t *worker_ctx, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_workers_ipc_hello2_ack(worker_context_t *worker_ctx, ipc_raw_protocol_t_status_t *ircvdi);
void handle_workers_ipc_closed_event(worker_context_t *worker_ctx);
status_t first_heartbeat_finalization(worker_context_t *worker_ctx, sio_c_session_t *session, orilink_identity_t *identity, uint8_t *trycount);
status_t retry_control_packet_ack(
    worker_context_t *worker_ctx, 
    orilink_identity_t *identity, 
    orilink_security_t *security, 
    control_packet_ack_t *control_packet_ack,
    orilink_protocol_type_t orilink_protocol
);
status_t retry_control_packet(
    worker_context_t *worker_ctx, 
    orilink_identity_t *identity, 
    orilink_security_t *security, 
    control_packet_t *control_packet,
    orilink_protocol_type_t orilink_protocol
);
status_t handle_workers_ipc_udp_data_cow_heartbeat_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_cow_heartbeat(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_cow_hello4(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_cow_hello3(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_cow_hello2(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_cow_hello1(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_sio_heartbeat_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_sio_heartbeat(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_sio_hello4_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_sio_hello3_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_sio_hello2_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_sio_hello1_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao);
status_t handle_workers_ipc_udp_data_sio(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol);
status_t handle_workers_ipc_udp_data_cow(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol);
status_t handle_workers_ipc_udp_data(worker_context_t *worker_ctx, void *worker_sessions, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_workers_ipc_udp_data_ack_cow(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol);
status_t handle_workers_ipc_udp_data_ack_sio(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol);
status_t handle_workers_ipc_udp_data_ack(worker_context_t *worker_ctx, void *worker_sessions, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_workers_ipc_event(worker_context_t *worker_ctx, void *worker_sessions, double *initial_delay_ms);

#endif
