#ifndef WORKERS_POLLING_H
#define WORKERS_POLLING_H

#include <math.h>
#include <stdint.h>

#include "workers/workers.h"
#include "types.h"
#include "utilities.h"

static inline status_t create_polling_1ms(worker_context_t *worker_ctx, control_packet_t *h, double total_polling_interval) {
    double polling_interval = (double)1000000 / (double)1e9;
    h->polling_1ms_max_cnt = (uint16_t)ceil((total_polling_interval * (double)1e9) / (double)1000000);
    status_t ctmr = create_timer_oneshot(worker_ctx->label, &worker_ctx->async, &h->polling_timer_fd, polling_interval);
    if (ctmr != SUCCESS) {
        return FAILURE;
    }
    return SUCCESS;
}

#endif
