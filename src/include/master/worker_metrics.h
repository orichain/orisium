#ifndef MASTER_WORKER_METRICS_H
#define MASTER_WORKER_METRICS_H

#include <stdint.h>

#include "master/master.h"
#include "types.h"

double initialize_metrics(const char *label, worker_metrics_t* metrics, worker_type_t wot, uint8_t index);
status_t new_task_metrics(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);

#endif
