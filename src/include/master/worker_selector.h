#ifndef MASTER_WORKER_SELECTOR_H
#define MASTER_WORKER_SELECTOR_H

#include "master/master.h"
#include "types.h"

int select_best_worker(const char *label, master_context_t *master_ctx, worker_type_t wot);

#endif
