#include <string.h>      // for memset, strncpy
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "utilities.h"
#include "constants.h"
#include "types.h"
#include "workers/sio.h"
#include "workers/logic.h"
#include "workers/cow.h"
#include "workers/dbr.h"
#include "workers/dbw.h"
#include "master/workers.h"
#include "async.h"
#include "master/process.h"

status_t close_worker(const char *label, master_context *master_ctx, worker_type_t wot, int index) {
	if (wot == SIO) {
		if (async_delete_event(label, &master_ctx->master_async, &master_ctx->sio[index].uds[0]) != SUCCESS) {		
			return FAILURE;
		}
        CLOSE_UDS(&master_ctx->sio[index].uds[0]);
		CLOSE_UDS(&master_ctx->sio[index].uds[1]);
		CLOSE_PID(&master_ctx->sio[index].pid);
	} else if (wot == LOGIC) {
		if (async_delete_event(label, &master_ctx->master_async, &master_ctx->logic[index].uds[0]) != SUCCESS) {		
			return FAILURE;
		}
        CLOSE_UDS(&master_ctx->logic[index].uds[0]);
		CLOSE_UDS(&master_ctx->logic[index].uds[1]);
		CLOSE_PID(&master_ctx->logic[index].pid);
	} else if (wot == COW) {
		if (async_delete_event(label, &master_ctx->master_async, &master_ctx->cow[index].uds[0]) != SUCCESS) {		
			return FAILURE;
		}
        CLOSE_UDS(&master_ctx->cow[index].uds[0]);
		CLOSE_UDS(&master_ctx->cow[index].uds[1]);
		CLOSE_PID(&master_ctx->cow[index].pid);
	} else if (wot == DBR) {
		if (async_delete_event(label, &master_ctx->master_async, &master_ctx->dbr[index].uds[0]) != SUCCESS) {		
			return FAILURE;
		}
        CLOSE_UDS(&master_ctx->dbr[index].uds[0]);
		CLOSE_UDS(&master_ctx->dbr[index].uds[1]);
		CLOSE_PID(&master_ctx->dbr[index].pid);
	} else if (wot == DBW) {
		if (async_delete_event(label, &master_ctx->master_async, &master_ctx->dbw[index].uds[0]) != SUCCESS) {		
			return FAILURE;
		}
        CLOSE_UDS(&master_ctx->dbw[index].uds[0]);
		CLOSE_UDS(&master_ctx->dbw[index].uds[1]);
		CLOSE_PID(&master_ctx->dbw[index].pid);
	}
	return SUCCESS;
}

status_t create_socket_pair(const char *label, master_context *master_ctx, worker_type_t wot, int index) {
	if (wot == SIO) {
		const char *worker_name = "SIO";
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, master_ctx->sio[index].uds) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, master_ctx->sio[index].uds[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, master_ctx->sio[index].uds[1]) != SUCCESS) {
			return FAILURE;
		}
		if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->sio[index].uds[0]) != SUCCESS) {
			return FAILURE;
		}
		LOG_DEBUG("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, master_ctx->sio[index].uds[0], master_ctx->sio[index].uds[1]);
	} else if (wot == LOGIC) {
		const char *worker_name = "Logic";
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, master_ctx->logic[index].uds) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, master_ctx->logic[index].uds[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, master_ctx->logic[index].uds[1]) != SUCCESS) {
			return FAILURE;
		}
		if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->logic[index].uds[0]) != SUCCESS) {
			return FAILURE;
		}
		LOG_DEBUG("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, master_ctx->logic[index].uds[0], master_ctx->logic[index].uds[1]);
	} else if (wot == COW) {
		const char *worker_name = "COW";
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, master_ctx->cow[index].uds) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, master_ctx->cow[index].uds[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, master_ctx->cow[index].uds[1]) != SUCCESS) {
			return FAILURE;
		}
		if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->cow[index].uds[0]) != SUCCESS) {
			return FAILURE;
		}
		LOG_DEBUG("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, master_ctx->cow[index].uds[0], master_ctx->cow[index].uds[1]);
	} else if (wot == DBR) {
		const char *worker_name = "DBR";
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, master_ctx->dbr[index].uds) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, master_ctx->dbr[index].uds[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, master_ctx->dbr[index].uds[1]) != SUCCESS) {
			return FAILURE;
		}
		if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->dbr[index].uds[0]) != SUCCESS) {
			return FAILURE;
		}
		LOG_DEBUG("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, master_ctx->dbr[index].uds[0], master_ctx->dbr[index].uds[1]);
	} else if (wot == DBW) {
		const char *worker_name = "DBW";
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, master_ctx->dbw[index].uds) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, master_ctx->dbw[index].uds[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, master_ctx->dbw[index].uds[1]) != SUCCESS) {
			return FAILURE;
		}
		if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->dbw[index].uds[0]) != SUCCESS) {
			return FAILURE;
		}
		LOG_DEBUG("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, master_ctx->dbw[index].uds[0], master_ctx->dbw[index].uds[1]);
	}
	return SUCCESS;
}


status_t setup_fork_worker(const char* label, master_context *master_ctx, worker_type_t wot, int index) {
	if (wot == SIO) {
		const char *worker_name = "SIO";
		master_ctx->sio[index].pid = fork();
        if (master_ctx->sio[index].pid == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->sio[index].pid == 0) {
            close(master_ctx->listen_sock);
            close(master_ctx->master_async.async_fd);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio[j].uds[0]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic[j].uds[0]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow[j].uds[0]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr[j].uds[0]); }           
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw[j].uds[0]); }
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) {
				if (j != index) {
					CLOSE_FD(&master_ctx->sio[j].uds[1]);
				}
            }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic[j].uds[1]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow[j].uds[1]); }            
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr[j].uds[1]); }
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw[j].uds[1]); }
            run_sio_worker(wot, index, master_ctx->sio[index].uds[1]);
            exit(EXIT_SUCCESS);
        } else {
			CLOSE_FD(&master_ctx->sio[index].uds[1]);
            LOG_DEBUG("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->sio[index].pid);
        }
	} else if (wot == LOGIC) {
		const char *worker_name = "Logic";		
		master_ctx->logic[index].pid = fork();
        if (master_ctx->logic[index].pid == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->logic[index].pid == 0) {
            close(master_ctx->listen_sock);
            close(master_ctx->master_async.async_fd);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio[j].uds[0]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic[j].uds[0]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow[j].uds[0]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr[j].uds[0]); }           
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw[j].uds[0]); }
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio[j].uds[1]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) {
				if (j != index) {
					CLOSE_FD(&master_ctx->logic[j].uds[1]);
				}
			}
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow[j].uds[1]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr[j].uds[1]); }
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw[j].uds[1]); }
            run_logic_worker(wot, index, master_ctx->logic[index].uds[1]);
            exit(EXIT_SUCCESS);
        } else {
			CLOSE_FD(&master_ctx->logic[index].uds[1]);
            LOG_DEBUG("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->logic[index].pid);
        }
	} else if (wot == COW) {
		const char *worker_name = "COW";
		master_ctx->cow[index].pid = fork();
        if (master_ctx->cow[index].pid == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->cow[index].pid == 0) {
            close(master_ctx->listen_sock);
            close(master_ctx->master_async.async_fd);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio[j].uds[0]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic[j].uds[0]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow[j].uds[0]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr[j].uds[0]); }           
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw[j].uds[0]); }
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio[j].uds[1]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic[j].uds[1]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) {
				if (j != index) {
					CLOSE_FD(&master_ctx->cow[j].uds[1]); 
				}
			}
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr[j].uds[1]); }
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw[j].uds[1]); }
            run_cow_worker(wot, index, master_ctx->cow[index].uds[1]);
            exit(EXIT_SUCCESS);
        } else {
			CLOSE_FD(&master_ctx->cow[index].uds[1]);
            LOG_DEBUG("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->cow[index].pid);
        }
	} else if (wot == DBR) {
		const char *worker_name = "DBR";
		master_ctx->dbr[index].pid = fork();
        if (master_ctx->dbr[index].pid == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->dbr[index].pid == 0) {
            close(master_ctx->listen_sock);
            close(master_ctx->master_async.async_fd);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio[j].uds[0]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic[j].uds[0]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow[j].uds[0]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr[j].uds[0]); }           
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw[j].uds[0]); }
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio[j].uds[1]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic[j].uds[1]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow[j].uds[1]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { 
                if (j != index) {
                    CLOSE_FD(&master_ctx->dbr[j].uds[1]); 
                }
            }
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw[j].uds[1]); }
            run_dbr_worker(wot, index, master_ctx->dbr[index].uds[1]);
            exit(EXIT_SUCCESS);
        } else {
			CLOSE_FD(&master_ctx->dbr[index].uds[1]);
            LOG_DEBUG("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->dbr[index].pid);
        }
	} else if (wot == DBW) {
		const char *worker_name = "DBW";
		master_ctx->dbw[index].pid = fork();
        if (master_ctx->dbw[index].pid == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->dbw[index].pid == 0) {
            close(master_ctx->listen_sock);
            close(master_ctx->master_async.async_fd);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio[j].uds[0]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic[j].uds[0]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow[j].uds[0]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr[j].uds[0]); }           
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbw[j].uds[0]); }
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { CLOSE_FD(&master_ctx->sio[j].uds[1]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { CLOSE_FD(&master_ctx->logic[j].uds[1]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { CLOSE_FD(&master_ctx->cow[j].uds[1]); }
            for (int j = 0; j < MAX_DBR_WORKERS; ++j) { CLOSE_FD(&master_ctx->dbr[j].uds[1]); }
            for (int j = 0; j < MAX_DBW_WORKERS; ++j) {
                if (j != index) {
                    CLOSE_FD(&master_ctx->dbw[j].uds[1]);
                }
            }
            run_dbw_worker(wot, index, master_ctx->dbw[index].uds[1]);
            exit(EXIT_SUCCESS);
        } else {
			CLOSE_FD(&master_ctx->dbw[index].uds[1]);
            LOG_DEBUG("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->dbw[index].pid);
        }
	}
    return SUCCESS;
}

void workers_cleanup(master_context *master_ctx) {
    LOG_INFO("[Master]: Performing cleanup...");
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
		async_delete_event("[Master]: ", &master_ctx->master_async, &master_ctx->sio[i].uds[0]);
        CLOSE_UDS(&master_ctx->sio[i].uds[0]);
		CLOSE_UDS(&master_ctx->sio[i].uds[1]);
		CLOSE_PID(&master_ctx->sio[i].pid);
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		async_delete_event("[Master]: ", &master_ctx->master_async, &master_ctx->logic[i].uds[0]);
        CLOSE_UDS(&master_ctx->logic[i].uds[0]);
		CLOSE_UDS(&master_ctx->logic[i].uds[1]);
		CLOSE_PID(&master_ctx->logic[i].pid);
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
		async_delete_event("[Master]: ", &master_ctx->master_async, &master_ctx->cow[i].uds[0]);
        CLOSE_UDS(&master_ctx->cow[i].uds[0]);
		CLOSE_UDS(&master_ctx->cow[i].uds[1]);
		CLOSE_PID(&master_ctx->cow[i].pid);
    }
    for (int i = 0; i < MAX_DBR_WORKERS; ++i) {
		async_delete_event("[Master]: ", &master_ctx->master_async, &master_ctx->dbr[i].uds[0]);
        CLOSE_UDS(&master_ctx->dbr[i].uds[0]);
		CLOSE_UDS(&master_ctx->dbr[i].uds[1]);
		CLOSE_PID(&master_ctx->dbr[i].pid);
    }
    for (int i = 0; i < MAX_DBW_WORKERS; ++i) {
		async_delete_event("[Master]: ", &master_ctx->master_async, &master_ctx->dbw[i].uds[0]);
        CLOSE_UDS(&master_ctx->dbw[i].uds[0]);
		CLOSE_UDS(&master_ctx->dbw[i].uds[1]);
		CLOSE_PID(&master_ctx->dbw[i].pid);
    }
    LOG_INFO("[Master]: Cleanup complete.");
}
