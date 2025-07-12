#ifndef WORKERS_LOGIC_H
#define WORKERS_LOGIC_H

void run_logic_worker(worker_type_t wot, int worker_idx, long initial_delay_ms, int master_uds_fd);

#endif
