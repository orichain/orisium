#ifndef WORKERS_COW_H
#define WORKERS_COW_H

void run_cow_worker(worker_type_t wot, int worker_idx, long initial_delay_ms, int master_uds_fd);

#endif
