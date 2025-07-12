#ifndef WORKERS_DBW_H
#define WORKERS_DBW_H

void run_dbw_worker(worker_type_t wot, int worker_idx, long initial_delay_ms, int master_uds_fd);

#endif
