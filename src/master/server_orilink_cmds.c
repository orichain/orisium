#include <stdio.h>
#include <time.h>

#include "log.h"
#include "types.h"
#include "orilink/protocol.h"
#include "orilink/hello1_ack.h"
#include "sessions/master_session.h"
#include "utilities.h"
#include "async.h"
#include "stdbool.h"

status_t hello1_ack(const char *label, int *listen_sock, master_sio_c_session_t *session) {
	orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello1_ack(label, session->client_id, session->hello1_ack_sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, listen_sock, (const struct sockaddr *)&session->old_client_addr, cmd_result.r_orilink_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent hello1_ack to Client.", label);
        CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent hello1_ack to Client.", label);
    }
    CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
    return SUCCESS;
}

status_t send_hello1_ack(const char *label, int *listen_sock, master_sio_c_session_t *session) {
    uint64_t_status_t rt = get_realtime_time_ns(label);
    if (rt.status != SUCCESS) {
        return FAILURE;
    }
    session->hello1_ack_sent = true;
    session->hello1_ack_sent_try_count++;
    session->hello1_ack_sent_time = rt.r_uint64_t;
    if (hello1_ack(label, listen_sock, session) != SUCCESS) {
        printf("Error hello1_ack\n");
        return FAILURE;
    }
    if (async_set_timerfd_time(label, &session->hello1_ack_timer_fd,
        (time_t)session->interval_hello1_ack_timer_fd,
        (long)((session->interval_hello1_ack_timer_fd - (time_t)session->interval_hello1_ack_timer_fd) * 1e9),
        (time_t)session->interval_hello1_ack_timer_fd,
        (long)((session->interval_hello1_ack_timer_fd - (time_t)session->interval_hello1_ack_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}
