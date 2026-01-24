#include <stdint.h>

#include "constants.h"
#include "utilities.h"
#include "types.h"
#include "master/master.h"

double initialize_metrics(const char *label, worker_metrics_t* metrics, worker_type_t wot, int index) {
    int worker_type_id = (int)wot;
    const double MAX_INITIAL_DELAY_MS = (double)WORKER_HEARTBEAT_INTERVAL * 1000.0;
    double initial_delay_ms = (double)worker_type_id * index * INITIAL_MILISECONDS_PER_UNIT;
    if (initial_delay_ms > MAX_INITIAL_DELAY_MS) {
        initial_delay_ms = MAX_INITIAL_DELAY_MS;
    }
    uint64_t_status_t rt = get_monotonic_time_ns(label);
    metrics->sum_hb_interval = (double)0;
    metrics->hb_interval = (double)0;
    metrics->count_ack = (double)0;
    metrics->last_ack = rt.r_uint64_t;
    metrics->last_checkhealthy = rt.r_uint64_t;
    metrics->last_task_started = rt.r_uint64_t;
    metrics->last_task_finished = rt.r_uint64_t;
    metrics->longest_task_time = 0ULL;
    //======================================================================
    if (initial_delay_ms > 0) {
        metrics->hb_interval = (double)WORKER_HEARTBEAT_INTERVAL + ((double)initial_delay_ms/1000.0);
        metrics->sum_hb_interval = metrics->hb_interval;
        metrics->count_ack = (double)0;
    }
    return initial_delay_ms;
}

status_t new_task_metrics(const char *label, master_context_t *master_ctx, worker_type_t wot, int index) {
    uint64_t_status_t rt = get_monotonic_time_ns(label);
    if (rt.status != SUCCESS) return rt.status;
    worker_metrics_t *metrics = NULL;
    uint16_t *task_count = NULL;
    if (wot == SIO) {
        metrics = master_ctx->sio_session[index].metrics;
        task_count = &master_ctx->sio_session[index].task_count;
    } else if (wot == LOGIC) {
        metrics = master_ctx->logic_session[index].metrics;
        task_count = &master_ctx->logic_session[index].task_count;
    } else if (wot == COW) {
        metrics = master_ctx->cow_session[index].metrics;
        task_count = &master_ctx->cow_session[index].task_count;
    } else if (wot == DBR) {
        metrics = master_ctx->dbr_session[index].metrics;
        task_count = &master_ctx->dbr_session[index].task_count;
    } else if (wot == DBW) {
        metrics = master_ctx->dbw_session[index].metrics;
        task_count = &master_ctx->dbw_session[index].task_count;
    }
    if (!task_count || !metrics) return FAILURE;
    *task_count += 1;
    metrics->last_task_started = rt.r_uint64_t;
    return SUCCESS;
}
