#ifndef ORILINK_SESSIONS_SERVER_SESSION_H
#define ORILINK_SESSIONS_SERVER_SESSION_H

#include <stdbool.h>
#include "types.h"
#include "constants.h"
#include "kalman.h"

typedef struct orilink_heartbeat_server_session_t {
    uint64_t pid;
    bool sent;
    int sent_try_count;
    uint64_t sent_time;
    int fd;
    int timer_fd;
    bool pong_ack_rcvd;
    uint64_t pong_ack_rcvd_time;
    bool ping_rdy_sent;
    int ping_rdy_sent_try_count;
    uint64_t ping_rdy_sent_time;
    struct orilink_heartbeat_server_session_t *next;
} orilink_heartbeat_server_session_t;

typedef struct {
    uint64_t id;
    bool syn_ack_sent;
    int syn_ack_sent_try_count;
    uint64_t syn_ack_sent_time;
//======================================================================
// Heartbeat
//======================================================================
    uint64_t last_heartbeat_time;
    orilink_heartbeat_server_session_t *heartbeat;
//======================================================================    
    bool fin_rcvd;
    uint64_t fin_rcvd_time;
    bool fin_ack_sent;
    int fin_ack_sent_try_count;
    uint64_t fin_ack_sent_time;
    uint8_t first_check_rtt;
    kalman_t rtt_kalman_filter;
    int rtt_kalman_initialized_count;
    float *rtt_kalman_calibration_samples; 
    float rtt_temp_ewma_value;
} orilink_server_session_t;

#endif
