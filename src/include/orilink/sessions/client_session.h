#ifndef ORILINK_SESSIONS_CLIENT_SESSION_H
#define ORILINK_SESSIONS_CLIENT_SESSION_H

#include <stdbool.h>
#include "types.h"
#include "constants.h"
#include "kalman.h"

typedef struct orilink_heartbeat_client_session_t {
    uint64_t pid;
    bool sent;
    int sent_try_count;
    uint64_t sent_time;
    int fd;
    int timer_fd;
    bool pong_rcvd;
    uint64_t pong_rcvd_time;
    bool pong_ack_sent;
    int pong_ack_sent_try_count;
    uint64_t pong_ack_sent_time;
    int pong_ack_fd;
    int pong_ack_timer_fd;
    bool ping_rdy_rcvd;
    uint64_t ping_rdy_rcvd_time;
    struct orilink_heartbeat_client_session_t *next;
} orilink_heartbeat_client_session_t;

typedef struct {
    uint64_t id;
    bool syn_sent;
    int syn_sent_try_count;
    uint64_t syn_sent_time;
    int syn_fd;
    int syn_timer_fd;
    bool syn_ack_rcvd;
    uint64_t syn_ack_rcvd_time;
//======================================================================
// Heartbeat
//======================================================================
    bool heartbeat_rdy;
    int heartbeat_timer_fd;
    orilink_heartbeat_client_session_t *heartbeat;
//======================================================================    
    bool fin_sent;
    int fin_sent_try_count;
    uint64_t fin_sent_time;
    int fin_fd;
    int fin_timer_fd;
    bool fin_ack_rcvd;
    uint64_t fin_ack_rcvd_time;
    uint8_t first_check_rtt;
    kalman_t rtt_kalman_filter;
    int rtt_kalman_initialized_count;
    float *rtt_kalman_calibration_samples; 
    float rtt_temp_ewma_value;
} orilink_client_session_t;

#endif
