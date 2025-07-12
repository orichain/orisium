#ifndef WORKERS_DBR_H
#define WORKERS_DBR_H

void run_dbr_worker(worker_type_t wot, int worker_idx, long initial_delay_ms, int master_uds_fd);

#endif
