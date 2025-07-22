#ifndef MASTER_WORKER_METRICS_H
#define MASTER_WORKER_METRICS_H

#include "master/process.h"

double initialize_metrics(const char *label, worker_metrics_t* metrics, worker_type_t wot, int index);
status_t check_workers_healthy(master_context *master_ctx);
status_t new_task_metrics(const char *label, master_context *master_ctx, worker_type_t wot, int index);
status_t calculate_avg_task_time_metrics(const char *label, master_context *master_ctx, worker_type_t wot, int index);

#endif
