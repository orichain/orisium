#ifndef WORKERS_MASTER_IPC_CMDS_H
#define WORKERS_MASTER_IPC_CMDS_H

status_t master_heartbeat(const char *label, worker_type_t wot, int worker_idx, double new_heartbeat_interval_double, int *master_uds_fd);

#endif
