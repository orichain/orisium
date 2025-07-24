#ifndef SESSIONS_WORKERS_SESSION_H
#define SESSIONS_WORKERS_SESSION_H

#include "kalman.h"
#include "pqc.h"

typedef struct {
    uint64_t pid;
//======================================================================
// PING
//======================================================================    
    bool ping_rcvd;
    uint64_t ping_rcvd_time;    
    bool pong_sent;
    int pong_sent_try_count;
    uint64_t pong_sent_time;
    int pong_timer_fd;
    double interval_pong_timer_fd;
    bool pong_ack_rcvd;
    uint64_t pong_ack_rcvd_time;  
//======================================================================
// PING END
//======================================================================        
    bool ping_end_sent;
    int ping_end_sent_try_count;
    uint64_t ping_end_sent_time;
} sio_h_session_t;

typedef struct {
    bool in_use;
    struct sockaddr_in6 client_addr;
    int sock_fd;
	uint64_t id;
//======================================================================
// SYN
//======================================================================
    bool syn_rcvd;
    uint64_t syn_rcvd_time;
    bool syn_ack_sent;
    int syn_ack_sent_try_count;
    uint64_t syn_ack_sent_time;
    int syn_ack_timer_fd;
    double interval_syn_ack_timer_fd;
    bool syn_end_rcvd;
    uint64_t syn_end_rcvd_time;
//======================================================================
// HEARTBEAT
//======================================================================
    sio_h_session_t heartbeat;
//======================================================================
// FIN
//======================================================================
    bool fin_rcvd;
    uint64_t fin_rcvd_time;
    bool fin_ack_sent;
    int fin_ack_sent_try_count;
    uint64_t fin_ack_sent_time;
    int fin_ack_timer_fd;
    double interval_fin_ack_timer_fd;
    bool fin_end_rcvd;
    uint64_t fin_end_rcvd_time;  
//======================================================================
// RTT
//======================================================================    
    uint8_t first_check_rtt;
    kalman_t rtt_kalman_filter;
    int rtt_kalman_initialized_count;
    float *rtt_kalman_calibration_samples; 
    float rtt_temp_ewma_value;
//======================================================================
// RETRY
//======================================================================    
    uint8_t first_check_retry;
    kalman_t retry_kalman_filter;
    int retry_kalman_initialized_count;
    float *retry_kalman_calibration_samples; 
    float retry_temp_ewma_value;
} sio_c_session_t; //Server

typedef struct {
    uint64_t pid;
//======================================================================
// PING
//======================================================================    
    bool ping_sent;
    int ping_sent_try_count;
    uint64_t ping_sent_time;
    int ping_timer_fd;
    double interval_ping_timer_fd;
    bool pong_rcvd;
    uint64_t pong_rcvd_time;  
//======================================================================
// PONG ACK
//======================================================================        
    bool pong_ack_sent;
    int pong_ack_sent_try_count;
    uint64_t pong_ack_sent_time;
    int pong_ack_timer_fd;
    double interval_pong_ack_timer_fd;
    bool ping_end_rcvd;
    uint64_t ping_end_rcvd_time;
} cow_h_session_t;

typedef struct {
    bool in_use;
    struct sockaddr_in6 old_server_addr;
    struct sockaddr_in6 server_addr;
    int sock_fd;
//======================================================================
// IDENTITY
//======================================================================    
	uint64_t client_id;
    uint8_t kem_privatekey[KEM_PRIVATEKEY_BYTES];
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
    uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
    uint64_t server_id;
    uint16_t port;
//======================================================================
// HELLO SOCK
//======================================================================
    bool hello1_sent;
    int hello1_sent_try_count;
    uint64_t hello1_sent_time;
    int hello1_timer_fd;
    double interval_hello1_timer_fd;
    bool hello1_ack_rcvd;
    uint64_t hello1_ack_rcvd_time;
//======================================================================    
    bool hello2_sent;
    int hello2_sent_try_count;
    uint64_t hello2_sent_time;
    int hello2_timer_fd;
    double interval_hello2_timer_fd;
    bool hello2_ack_rcvd;
    uint64_t hello2_ack_rcvd_time;
//======================================================================    
    bool hello3_sent;
    int hello3_sent_try_count;
    uint64_t hello3_sent_time;
    int hello3_timer_fd;
    double interval_hello3_timer_fd;
    bool hello3_ack_rcvd;
    uint64_t hello3_ack_rcvd_time;
//======================================================================    
    bool hello_end_sent;
    int hello_end_sent_try_count;
    uint64_t hello_end_sent_time;
    int hello_end_timer_fd;
    double interval_hello_end_timer_fd;
    bool sock_ready_rcvd;
    uint64_t sock_ready_rcvd_time;
//======================================================================
// SYN
//======================================================================
    bool syn_sent;
    int syn_sent_try_count;
    uint64_t syn_sent_time;
    int syn_timer_fd;
    double interval_syn_timer_fd;
    bool syn_ack_rcvd;
    uint64_t syn_ack_rcvd_time;    
    bool syn_end_sent;
    int syn_end_sent_try_count;
    uint64_t syn_end_sent_time;
//======================================================================
// HEARTBEAT
//======================================================================
    cow_h_session_t heartbeat;
//======================================================================
// FIN
//======================================================================
    bool fin_sent;
    int fin_sent_try_count;
    uint64_t fin_sent_time;
    int fin_timer_fd;
    double interval_fin_timer_fd;
    bool fin_ack_rcvd;
    uint64_t fin_ack_rcvd_time;    
    bool fin_end_sent;
    int fin_end_sent_try_count;
    uint64_t fin_end_sent_time;    
//======================================================================
// RTT
//======================================================================    
    uint8_t first_check_rtt;
    kalman_t rtt_kalman_filter;
    int rtt_kalman_initialized_count;
    float *rtt_kalman_calibration_samples; 
    float rtt_value_prediction;
    float rtt_temp_ewma_value;
//======================================================================
// RETRY
//======================================================================    
    uint8_t first_check_retry;
    kalman_t retry_kalman_filter;
    int retry_kalman_initialized_count;
    float *retry_kalman_calibration_samples; 
    float retry_value_prediction;
    float retry_temp_ewma_value;
} cow_c_session_t; //Client

#endif
