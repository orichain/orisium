#ifndef MASTER_WORKERMETRICS_H
#define MASTER_WORKERMETRICS_H

#include "master/process.h"

double initialize_metrics(const char *label, worker_metrics_t* metrics, worker_type_t wot, int index);
status_t check_workers_healthy(master_context *master_ctx);

#endif
