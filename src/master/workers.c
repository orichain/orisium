#include <string.h>      // for memset, strncpy
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "constants.h"
#include "types.h"
#include "commons.h"
#include "utilities.h"
#include "workers/sio.h"
#include "workers/logic.h"
#include "workers/cow.h"
#include "master/workers.h"
#include "async.h"
#include "master/process.h"

status_t close_worker(const char *label, master_context *master_ctx, worker_type_t wot, int index) {
	if (wot == SIO) {
		CLOSE_UDS(master_ctx->master_uds_sio_fds[index]);
		CLOSE_UDS(master_ctx->worker_uds_sio_fds[index]);
		CLOSE_PID(master_ctx->sio_pids[index]);
	} else if (wot == LOGIC) {
		CLOSE_UDS(master_ctx->master_uds_logic_fds[index]);
		CLOSE_UDS(master_ctx->worker_uds_logic_fds[index]);
		CLOSE_PID(master_ctx->logic_pids[index]);
	} else if (wot == COW) {
		CLOSE_UDS(master_ctx->master_uds_cow_fds[index]);
		CLOSE_UDS(master_ctx->worker_uds_cow_fds[index]);
		CLOSE_PID(master_ctx->cow_pids[index]);
	}
	return SUCCESS;
}

status_t create_socket_pair(const char *label, master_context *master_ctx, worker_type_t wot, int index) {
	int sv[2];
	if (wot == SIO) {
		const char *worker_name = "SIO";
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, sv[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, sv[1]) != SUCCESS) {
			return FAILURE;
		}
		master_ctx->master_uds_sio_fds[index] = sv[0];
		master_ctx->worker_uds_sio_fds[index] = sv[1];
		if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->master_uds_sio_fds[index]) != SUCCESS) {
			return FAILURE;
		}
		LOG_INFO("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, master_ctx->master_uds_sio_fds[index], master_ctx->worker_uds_sio_fds[index]);
	} else if (wot == LOGIC) {
		const char *worker_name = "Logic";
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, sv[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, sv[1]) != SUCCESS) {
			return FAILURE;
		}
		master_ctx->master_uds_logic_fds[index] = sv[0];
		master_ctx->worker_uds_logic_fds[index] = sv[1];
		if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->master_uds_logic_fds[index]) != SUCCESS) {
			return FAILURE;
		}
		LOG_INFO("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, master_ctx->master_uds_logic_fds[index], master_ctx->worker_uds_logic_fds[index]);
	} else if (wot == COW) {
		const char *worker_name = "COW";
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
			LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
			return FAILURE;
		}
		if (set_nonblocking(label, sv[0]) != SUCCESS) {
			return FAILURE;
		}
		if (set_nonblocking(label, sv[1]) != SUCCESS) {
			return FAILURE;
		}
		master_ctx->master_uds_cow_fds[index] = sv[0];
		master_ctx->worker_uds_cow_fds[index] = sv[1];
		if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->master_uds_cow_fds[index]) != SUCCESS) {
			return FAILURE;
		}
		LOG_INFO("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, master_ctx->master_uds_cow_fds[index], master_ctx->worker_uds_cow_fds[index]);
	}
	return SUCCESS;
}

void workers_cleanup(master_context *master_ctx) {
    LOG_INFO("Performing cleanup...");
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
		CLOSE_UDS(master_ctx->master_uds_sio_fds[i]);
		CLOSE_UDS(master_ctx->worker_uds_sio_fds[i]);
		CLOSE_PID(master_ctx->sio_pids[i]);
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		CLOSE_UDS(master_ctx->master_uds_logic_fds[i]);
		CLOSE_UDS(master_ctx->worker_uds_logic_fds[i]);
		CLOSE_PID(master_ctx->logic_pids[i]);
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
		CLOSE_UDS(master_ctx->master_uds_cow_fds[i]);
		CLOSE_UDS(master_ctx->worker_uds_cow_fds[i]);
		CLOSE_PID(master_ctx->cow_pids[i]);
    }
    LOG_INFO("Cleanup complete.");
}


status_t setup_fork_worker(const char* label, master_context *master_ctx, worker_type_t wot, int index) {
	if (wot == SIO) {
		const char *worker_name = "SIO";
		master_ctx->sio_pids[index] = fork();
        if (master_ctx->sio_pids[index] == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->sio_pids[index] == 0) {
            close(master_ctx->listen_sock);
            close(master_ctx->master_async.async_fd);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_ctx->master_uds_sio_fds[j] != 0) close(master_ctx->master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_ctx->master_uds_logic_fds[j] != 0) close(master_ctx->master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_ctx->master_uds_cow_fds[j] != 0) close(master_ctx->master_uds_cow_fds[j]); }
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) {
                if (j != index && master_ctx->worker_uds_sio_fds[j] != 0) close(master_ctx->worker_uds_sio_fds[j]);
            }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_ctx->worker_uds_logic_fds[j] != 0) close(master_ctx->worker_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_ctx->worker_uds_cow_fds[j] != 0) close(master_ctx->worker_uds_cow_fds[j]); }            
            run_server_io_worker(index, master_ctx->worker_uds_sio_fds[index]);
            exit(EXIT_SUCCESS);
        } else {
            if (master_ctx->worker_uds_sio_fds[index] != 0) close(master_ctx->worker_uds_sio_fds[index]);
            LOG_INFO("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->sio_pids[index]);
        }
	} else if (wot == LOGIC) {
		const char *worker_name = "Logic";
		master_ctx->logic_pids[index] = fork();
        if (master_ctx->logic_pids[index] == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->logic_pids[index] == 0) {
            close(master_ctx->listen_sock);
            close(master_ctx->master_async.async_fd);
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_ctx->master_uds_sio_fds[j] != 0) close(master_ctx->master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_ctx->master_uds_logic_fds[j] != 0) close(master_ctx->master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_ctx->master_uds_cow_fds[j] != 0) close(master_ctx->master_uds_cow_fds[j]); }
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_ctx->worker_uds_sio_fds[j] != 0) close(master_ctx->worker_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) {
                if (j != index && master_ctx->worker_uds_logic_fds[j] != 0) close(master_ctx->worker_uds_logic_fds[j]);
            }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_ctx->worker_uds_cow_fds[j] != 0) close(master_ctx->worker_uds_cow_fds[j]); }         
            run_logic_worker(index, master_ctx->worker_uds_logic_fds[index]);
            exit(EXIT_SUCCESS);
        } else {
            if (master_ctx->worker_uds_logic_fds[index] != 0) close(master_ctx->worker_uds_logic_fds[index]);
            LOG_INFO("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->logic_pids[index]);
        }
	} else if (wot == COW) {
		const char *worker_name = "COW";
		master_ctx->cow_pids[index] = fork();
        if (master_ctx->cow_pids[index] == -1) {
            LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
            return FAILURE;
        } else if (master_ctx->cow_pids[index] == 0) {
            close(master_ctx->listen_sock);
            close(master_ctx->master_async.async_fd);           
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_ctx->master_uds_sio_fds[j] != 0) close(master_ctx->master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_ctx->master_uds_logic_fds[j] != 0) close(master_ctx->master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_ctx->master_uds_cow_fds[j] != 0) close(master_ctx->master_uds_cow_fds[j]); }
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_ctx->worker_uds_sio_fds[j] != 0) close(master_ctx->worker_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_ctx->worker_uds_logic_fds[j] != 0) close(master_ctx->worker_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) {
                if (j != index && master_ctx->worker_uds_cow_fds[j] != 0) close(master_ctx->worker_uds_cow_fds[j]);
            }
            run_client_outbound_worker(index, master_ctx->worker_uds_cow_fds[index]);
            exit(EXIT_SUCCESS);
        } else {
            if (master_ctx->worker_uds_cow_fds[index] != 0) close(master_ctx->worker_uds_cow_fds[index]);
            LOG_INFO("%sForked %s Worker %d (PID %d).", label, worker_name, index, master_ctx->cow_pids[index]);
        }
	}
    return SUCCESS;
}
