#ifndef ORILINK_NET_H
#define ORILINK_NET_H

#include "constants.h"
#include "types.h"

typedef struct {
    udp_session_t sessions[MAX_SESSIONS];
    int session_count;

    udp_sent_packet_t *send_buffer[MAX_BUFFER_SIZE];
    int buffer_count;
    uint32_t next_global_seq_to_send;
    uint32_t last_acked_global_seq;
    uint32_t connection_id;
    uint32_t next_stream_seq_to_send[NUM_STREAMS];
    int total_packets_to_send;

    double congestion_window;
    double slow_start_threshold;
    int fast_retransmit_count;
    double Wmax;
    time_t last_congestion_time;

    uint32_t send_window_credit;
    time_t last_keepalive_time;
    int is_fin_sent;
    int is_fin_acked;

    double srtt;
    double rttvar;
    double rto;
} udp_context_t;

udp_session_t* find_or_create_session(udp_context_t *ctx, uint32_t conn_id, const struct sockaddr_in6 *addr, socklen_t len);
void send_sack(int sockfd, udp_session_t* session);
void process_data_packet(int sockfd, udp_session_t* session, udp_packet_t* pkt);

void send_packet(int sockfd, const struct sockaddr_in *dest_addr,
                 uint32_t conn_id, uint32_t global_seq_num, udp_packet_type_t type,
                 uint16_t stream_id, uint32_t stream_seq_num, const uint8_t *data, size_t data_len);
udp_sent_packet_t* find_packet_in_buffer(udp_context_t *ctx, uint32_t global_seq_num);
void update_cubic_cwnd(udp_context_t *ctx);
void save_connection_id(uint32_t id);
uint32_t load_connection_id();

void orilink_handle_syn(int sockfd, udp_session_t *session, udp_packet_t *received, const struct sockaddr *client_addr, socklen_t client_addr_len);
void orilink_handle_ack(udp_session_t *session, udp_packet_t *received);
void orilink_handle_data(int sockfd, udp_session_t *session, udp_packet_t *received);
void orilink_handle_fin(int sockfd, udp_session_t *session, udp_packet_t *received, const struct sockaddr *client_addr, socklen_t client_addr_len);
void orilink_handle_keepalive(udp_session_t *session, udp_packet_t *received);
void orilink_cleanup_sessions(udp_context_t *ctx);

#endif
