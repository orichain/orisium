#include <inttypes.h>
#include <float.h>
#include <limits.h>
#include <stddef.h>

#include "log.h"
#include "constants.h"
#include "types.h"
#include "master/master.h"

int select_best_worker(const char *label, master_context_t *master_ctx, worker_type_t wot) {
    const char *worker_name = get_master_worker_name(wot);
    int selected_worker_idx = -1;
    long double min_avg_task_time = LDBL_MAX;
    uint64_t min_longest_task_time = ULLONG_MAX;
    
    int temp_best_idx_t1 = -1;
    if (wot == SIO) {
        for (uint8_t i = 0; i < MAX_SIO_WORKERS; ++i) {
            master_worker_session_t *session = get_master_worker_session(master_ctx, SIO, i);
            if (session == NULL) {
                return -1;
            }
            if (session->task_count < MAX_CONNECTION_PER_SIO_WORKER) {
                if (session->isactive && session->ishealthy) {
                    if (session->avgtt.value_prediction < min_avg_task_time) {
                        min_avg_task_time = session->avgtt.value_prediction;
                        temp_best_idx_t1 = i;
                    }
                }
            }
        }
    } else if (wot == COW) {
        for (uint8_t i = 0; i < MAX_COW_WORKERS; ++i) {
            master_worker_session_t *session = get_master_worker_session(master_ctx, COW, i);
            if (session == NULL) {
                return -1;
            }
            if (session->task_count < MAX_CONNECTION_PER_COW_WORKER) {
                if (session->isactive && session->ishealthy) {
                    if (session->avgtt.value_prediction < min_avg_task_time) {
                        min_avg_task_time = session->avgtt.value_prediction;
                        temp_best_idx_t1 = i;
                    }
                }
            }
        }
    }
    if (temp_best_idx_t1 != -1) {
        if (min_avg_task_time > 0.0L) {
            selected_worker_idx = temp_best_idx_t1;
            LOG_DEBUG("%sSelecting %s worker %d based on lowest Avg Task Time: %Lf", 
                      label, worker_name, selected_worker_idx, min_avg_task_time);
            return selected_worker_idx;
        }
        LOG_DEBUG("%sAll not-full %s workers have 0 Avg Task Time. Falling back to Longest Task Time / Round Robin.", label, worker_name);
    } else {
        LOG_DEBUG("%sNo not-full %s workers found for Avg Task Time check. All might be full. Falling back.", label, worker_name);
    }
    int temp_best_idx_t2 = -1;
    if (wot == SIO) {
        for (uint8_t i = 0; i < MAX_SIO_WORKERS; ++i) {
            master_worker_session_t *session = get_master_worker_session(master_ctx, SIO, i);
            if (session == NULL) {
                return -1;
            }
            if (session->task_count < MAX_CONNECTION_PER_SIO_WORKER) {
                if (session->isactive && session->ishealthy) {
                    if (session->metrics.longest_task_time < min_longest_task_time) {
                        min_longest_task_time = session->metrics.longest_task_time;
                        temp_best_idx_t2 = i;
                    }
                }
            }
        }
    } else if (wot == COW) {
        for (uint8_t i = 0; i < MAX_COW_WORKERS; ++i) {
            master_worker_session_t *session = get_master_worker_session(master_ctx, COW, i);
            if (session == NULL) {
                return -1;
            }
            if (session->task_count < MAX_CONNECTION_PER_COW_WORKER) {
                if (session->isactive && session->ishealthy) {
                    if (session->metrics.longest_task_time < min_longest_task_time) {
                        min_longest_task_time = session->metrics.longest_task_time;
                        temp_best_idx_t2 = i;
                    }
                }
            }
        }
    }
    if (temp_best_idx_t2 != -1) {
        if (min_longest_task_time > 0ULL) {
            selected_worker_idx = temp_best_idx_t2;
            LOG_DEBUG("%sSelecting %s worker %d based on lowest Longest Task Time: %" PRIu64, 
                      label, worker_name, selected_worker_idx, min_longest_task_time);
            return selected_worker_idx; 
        }
        LOG_DEBUG("%sAll not-full %s workers have 0 Longest Task Time. Falling back to Round Robin.", label, worker_name);
    } else {
        LOG_DEBUG("%sNo not-full %s workers found for Longest Task Time check. All might be full. Falling back to Round Robin.", label, worker_name);
    }
    int temp_best_idx_t3 = -1;
    if (wot == SIO) {
        int start_rr_check_idx = master_ctx->last_sio_rr_idx; 
        for (uint8_t i = 0; i < MAX_SIO_WORKERS; ++i) {
            master_worker_session_t *session = get_master_worker_session(master_ctx, SIO, i);
            if (session == NULL) {
                return -1;
            }
            int current_rr_idx = (start_rr_check_idx + i) % MAX_SIO_WORKERS;
            if (master_ctx->sio_session[current_rr_idx].task_count < MAX_CONNECTION_PER_SIO_WORKER) {
                if (master_ctx->sio_session[current_rr_idx].isactive && master_ctx->sio_session[current_rr_idx].ishealthy) {
                    temp_best_idx_t3 = current_rr_idx;
                    master_ctx->last_sio_rr_idx = (current_rr_idx + 1) % MAX_SIO_WORKERS;
                    break;
                }
            }
        }
    } else if (wot == COW) {
        int start_rr_check_idx = master_ctx->last_cow_rr_idx; 
        for (uint8_t i = 0; i < MAX_COW_WORKERS; ++i) {
            master_worker_session_t *session = get_master_worker_session(master_ctx, COW, i);
            if (session == NULL) {
                return -1;
            }
            int current_rr_idx = (start_rr_check_idx + i) % MAX_COW_WORKERS;
            if (master_ctx->cow_session[current_rr_idx].task_count < MAX_CONNECTION_PER_COW_WORKER) {
                if (master_ctx->cow_session[current_rr_idx].isactive && master_ctx->cow_session[current_rr_idx].ishealthy) {
                    temp_best_idx_t3 = current_rr_idx;
                    master_ctx->last_cow_rr_idx = (current_rr_idx + 1) % MAX_COW_WORKERS;
                    break;
                }
            }
        }
    }
    if (temp_best_idx_t3 != -1) {
        selected_worker_idx = temp_best_idx_t3;
        LOG_DEBUG("%sSelecting %s worker %d using Round Robin (fallback).", label, worker_name, selected_worker_idx);
        return selected_worker_idx;
    } else {
        LOG_ERROR("%sNo %s worker available (all might be full/unhealthy/nonactive).", label, worker_name);
        return -1;
    }
}
