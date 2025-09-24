#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "types.h"
#include "workers/workers.h"
#include "orilink/protocol.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "utilities.h"
#include "async.h"

status_t retry_cow_connect(worker_context_t *worker_ctx, cow_c_session_t *session) {
    orilink_identity_t *identity = &session->identity;
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_realtime_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    session->hello1.sent_try_count++;
    session->hello1.sent_time = current_time.r_uint64_t;
    if (async_set_timerfd_time(worker_ctx->label, &session->hello1.timer_fd,
        (time_t)session->hello1.interval_timer_fd,
        (long)((session->hello1.interval_timer_fd - (time_t)session->hello1.interval_timer_fd) * 1e9),
        (time_t)session->hello1.interval_timer_fd,
        (long)((session->hello1.interval_timer_fd - (time_t)session->hello1.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
//======================================================================
    puint8_t_size_t_status_t udp_data;
    udp_data.status = SUCCESS;
    udp_data.r_size_t = session->hello1.len;
    udp_data.r_puint8_t = (uint8_t *)calloc(1, session->hello1.len);
    memcpy(udp_data.r_puint8_t, session->hello1.data, session->hello1.len);
    free(session->hello1.data);
    session->hello1.data = NULL;
    session->hello1.len = 0;
    if (udp_data.status != SUCCESS) {
        return FAILURE;
    }
    if (worker_master_udp_data(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &identity->remote_addr, &udp_data, &session->hello1) != SUCCESS) {
        return FAILURE;
    }
//======================================================================
    return SUCCESS;
}
