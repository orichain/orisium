#ifndef SESSIONS_WORKERS_SESSION_H
#define SESSIONS_WORKERS_SESSION_H

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
    int pong_fd;
    int pong_timer_fd;    
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
    struct sockaddr_storage client_addr;
	socklen_t client_addr_len;
	uint64_t id;
//======================================================================
// SYN
//======================================================================
    bool syn_rcvd;
    uint64_t syn_rcvd_time;
    bool syn_ack_sent;
    int syn_ack_sent_try_count;
    uint64_t syn_ack_sent_time;
    int syn_ack_fd;
    int syn_ack_timer_fd;
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
    int fin_ack_fd;
    int fin_ack_timer_fd;
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
} sio_c_state_t; //Server

typedef struct {
    uint64_t pid;
//======================================================================
// PING
//======================================================================    
    bool ping_sent;
    int ping_sent_try_count;
    uint64_t ping_sent_time;
    int ping_fd;
    int ping_timer_fd;
    bool pong_rcvd;
    uint64_t pong_rcvd_time;  
//======================================================================
// PONG ACK
//======================================================================        
    bool pong_ack_sent;
    int pong_ack_sent_try_count;
    uint64_t pong_ack_sent_time;
    int pong_ack_fd;
    int pong_ack_timer_fd;
    bool ping_end_rcvd;
    uint64_t ping_end_rcvd_time;
} cow_h_session_t;

typedef struct {
    bool in_use;
    struct sockaddr_storage client_addr;
	socklen_t client_addr_len;
	uint64_t id;
//======================================================================
// SYN
//======================================================================
    bool syn_sent;
    int syn_sent_try_count;
    uint64_t syn_sent_time;
    int syn_fd;
    int syn_timer_fd;
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
    int fin_fd;
    int fin_timer_fd;
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
    float rtt_temp_ewma_value;
//======================================================================
// RETRY
//======================================================================    
    uint8_t first_check_retry;
    kalman_t retry_kalman_filter;
    int retry_kalman_initialized_count;
    float *retry_kalman_calibration_samples; 
    float retry_temp_ewma_value;
} cow_c_session_t; //Client

#endif
