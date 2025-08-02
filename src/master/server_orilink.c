#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>

#include "types.h"
#include "master/master.h"
#include "utilities.h"
#include "async.h"
#include "master/server_orilink_cmds.h"
#include "constants.h"
#include "kalman.h"

status_t send_hello1_ack(const char *label, int *listen_sock, master_sio_c_session_t *session) {
    uint64_t_status_t rt = get_realtime_time_ns(label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    session->hello1_ack.ack_sent = true;
    session->hello1_ack.ack_sent_try_count++;
    session->hello1_ack.ack_sent_time = rt.r_uint64_t;
    if (hello1_ack(label, listen_sock, session) != SUCCESS) {
        printf("Error hello1_ack\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(label, &session->hello1_ack.ack_timer_fd,
        (time_t)session->hello1_ack.interval_ack_timer_fd,
        (long)((session->hello1_ack.interval_ack_timer_fd - (time_t)session->hello1_ack.interval_ack_timer_fd) * 1e9),
        (time_t)session->hello1_ack.interval_ack_timer_fd,
        (long)((session->hello1_ack.interval_ack_timer_fd - (time_t)session->hello1_ack.interval_ack_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

status_t send_hello2_ack(const char *label, int *listen_sock, master_sio_c_session_t *session) {
    uint64_t_status_t rt = get_realtime_time_ns(label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    session->hello2_ack.ack_sent = true;
    session->hello2_ack.ack_sent_try_count++;
    session->hello2_ack.ack_sent_time = rt.r_uint64_t;
    if (hello2_ack(label, listen_sock, session) != SUCCESS) {
        printf("Error hello2_ack\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(label, &session->hello2_ack.ack_timer_fd,
        (time_t)session->hello2_ack.interval_ack_timer_fd,
        (long)((session->hello2_ack.interval_ack_timer_fd - (time_t)session->hello2_ack.interval_ack_timer_fd) * 1e9),
        (time_t)session->hello2_ack.interval_ack_timer_fd,
        (long)((session->hello2_ack.interval_ack_timer_fd - (time_t)session->hello2_ack.interval_ack_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

status_t send_hello3_ack(const char *label, int *listen_sock, master_sio_c_session_t *session) {
    uint64_t_status_t rt = get_realtime_time_ns(label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    session->hello3_ack.ack_sent = true;
    session->hello3_ack.ack_sent_try_count++;
    session->hello3_ack.ack_sent_time = rt.r_uint64_t;
    if (hello3_ack(label, listen_sock, session) != SUCCESS) {
        printf("Error hello3_ack\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(label, &session->hello3_ack.ack_timer_fd,
        (time_t)session->hello3_ack.interval_ack_timer_fd,
        (long)((session->hello3_ack.interval_ack_timer_fd - (time_t)session->hello3_ack.interval_ack_timer_fd) * 1e9),
        (time_t)session->hello3_ack.interval_ack_timer_fd,
        (long)((session->hello3_ack.interval_ack_timer_fd - (time_t)session->hello3_ack.interval_ack_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

void sio_c_calculate_retry(const char *label, master_sio_c_session_t *session, int session_index, double try_count) {
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => RETRY %d", session_index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => RETRY %d", session_index);
    calculate_oricle_double(label, desc, &session->identity.retry, try_count, ((double)MAX_RETRY * (double)2));
    free(desc);
}

void sio_c_calculate_rtt(const char *label, master_sio_c_session_t *session, int session_index, double rtt_value) {
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => RTT %d", session_index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => RTT %d", session_index);
    calculate_oricle_double(label, desc, &session->identity.rtt, rtt_value, ((double)MAX_RTT_SEC * (double)1e9 * (double)2));
    free(desc);
}
