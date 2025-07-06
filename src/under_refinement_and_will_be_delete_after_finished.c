#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <string.h>      // for memset, strncpy
#include <sys/types.h>   // for pid_t, ssize_t
#include <unistd.h>      // for close, fork, getpid
#include <sys/wait.h>    // for waitpid

#include "log.h"
#include "constants.h"
#include "async.h"
#include "ipc/protocol.h"
#include "workers/sio.h"
#include "workers/logic.h"
#include "workers/cow.h"
#include "under_refinement_and_will_be_delete_after_finished.h"
#include "types.h"

// Send message over UDS, with optional FD passing (from ipc.h/ipc.c)
ssize_t send_ipc_message(int uds_fd, ipc_protocol_type_t type, const void *data, size_t data_len, int fd_to_pass) {
	/*
    ipc_msg_header_t header = { .type = type, .data_len = data_len };
    struct iovec iov[2];
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = (void *)data;
    iov[1].iov_len = data_len;

    char cmsgbuf[CMSG_SPACE(sizeof(int))]; // Buffer for control message (for FD)

    struct msghdr msg = {0};
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    if (fd_to_pass != -1) { // If an FD needs to be passed
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *((int *) CMSG_DATA(cmsg)) = fd_to_pass;
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
    }

    ssize_t bytes_sent = sendmsg(uds_fd, &msg, 0);
    if (bytes_sent == -1) {
        perror("send_ipc_message sendmsg"); // Using perror as LOG_ERROR might not be available in all contexts
    }
    return bytes_sent;
    */
    return -1;
}

// Receive message over UDS, with optional FD reception (from ipc.h/ipc.c)
ssize_t recv_ipc_message(int uds_fd, ipc_msg_header_t *header, void *data_buffer, size_t buffer_size, int *actual_fd_received) {
	/*
    struct iovec iov[2];
    iov[0].iov_base = header;
    iov[0].iov_len = sizeof(ipc_msg_header_t);
    iov[1].iov_base = data_buffer;
    iov[1].iov_len = buffer_size;

    char cmsgbuf[CMSG_SPACE(sizeof(int))]; // Buffer for control message (for FD)

    struct msghdr msg = {0};
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    *actual_fd_received = -1; // Initialize to -1

    ssize_t bytes_read = recvmsg(uds_fd, &msg, 0);
    if (bytes_read == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recv_ipc_message recvmsg");
        }
        return -1;
    }

    if (bytes_read < (ssize_t)sizeof(ipc_msg_header_t)) {
        fprintf(stderr, "recv_ipc_message: Incomplete header received (%zd bytes)\n", bytes_read);
        return -1;
    }

    if (header->data_len > buffer_size) {
        fprintf(stderr, "recv_ipc_message: Data too large for buffer (expected %zu, got %zu). Truncating.\n",
                header->data_len, buffer_size);
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
        *actual_fd_received = *((int *) CMSG_DATA(cmsg));
    }

    return bytes_read;
    */
    return -1;
}

// --- Fungsi Pembaca JSON Konfigurasi Jaringan (dari config.c/config.h) ---


// Placeholder for orisium_cleanup
void orisium_cleanup(int *listen_sock_ptr, async_type_t *async_fd_ptr,
                     int uds_sio_fds_master_side[], int uds_logic_fds_master_side[], int uds_cow_fds_master_side[],
                     int uds_sio_fds_worker_side[], int uds_logic_fds_worker_side[], int uds_cow_fds_worker_side[],
                     pid_t sio_pids[], pid_t logic_pids[], pid_t cow_pids[]) {
    LOG_INFO("Performing cleanup...");
    if (*listen_sock_ptr != -1) close(*listen_sock_ptr);
    if (async_fd_ptr->async_fd != -1) close(async_fd_ptr->async_fd);

    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        if (uds_sio_fds_master_side[i] != 0) close(uds_sio_fds_master_side[i]);
        if (uds_sio_fds_worker_side[i] != 0) close(uds_sio_fds_worker_side[i]); // Close worker side in Master too
        if (sio_pids[i] > 0) waitpid(sio_pids[i], NULL, 0);
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        if (uds_logic_fds_master_side[i] != 0) close(uds_logic_fds_master_side[i]);
        if (uds_logic_fds_worker_side[i] != 0) close(uds_logic_fds_worker_side[i]); // Close worker side in Master too
        if (logic_pids[i] > 0) waitpid(logic_pids[i], NULL, 0);
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        if (uds_cow_fds_master_side[i] != 0) close(uds_cow_fds_master_side[i]);
        if (uds_cow_fds_worker_side[i] != 0) close(uds_cow_fds_worker_side[i]); // Close worker side in Master too
        if (cow_pids[i] > 0) waitpid(cow_pids[i], NULL, 0);
    }
    LOG_INFO("Cleanup complete.");
}

status_t setup_fork_workers(
    const char* label,
    int listen_sock, // listen_sock passed by value, as it's closed in child
    async_type_t *async,
    int master_uds_sio_fds[], // Arrays for Master's side of UDS
    int master_uds_logic_fds[],
    int master_uds_cow_fds[],
    int worker_uds_sio_fds[], // Arrays for Worker's side of UDS
    int worker_uds_logic_fds[],
    int worker_uds_cow_fds[],
    pid_t sio_pids[],
    pid_t logic_pids[],
    pid_t cow_pids[]
) {
    // Create and fork SIO workers
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        sio_pids[i] = fork();
        if (sio_pids[i] == -1) {
            LOG_ERROR("%sfork (SIO): %s", label, strerror(errno));
            return FAILURE;
        } else if (sio_pids[i] == 0) {
            // Child (SIO Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) {
                if (j != i && worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]);
            }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]); }
            
            run_server_io_worker(i, worker_uds_sio_fds[i]);
            exit(EXIT_SUCCESS); // Child exits after running worker function
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_sio_fds[i] != 0) close(worker_uds_sio_fds[i]);
            LOG_INFO("%sForked Server IO Worker %d (PID %d).", label, i, sio_pids[i]);
        }
    }

    // Create and fork Logic workers
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        logic_pids[i] = fork();
        if (logic_pids[i] == -1) {
            LOG_ERROR("%sfork (Logic): %s", label, strerror(errno));
            return FAILURE;
        } else if (logic_pids[i] == 0) {
            // Child (Logic Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) {
                if (j != i && worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]);
            }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]); }
            
            run_logic_worker(i, worker_uds_logic_fds[i]);
            exit(EXIT_SUCCESS); // Child exits
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_logic_fds[i] != 0) close(worker_uds_logic_fds[i]);
            LOG_INFO("%sForked Logic Worker %d (PID %d).", label, i, logic_pids[i]);
        }
    }

    // Create and fork Client Outbound workers
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        cow_pids[i] = fork();
        if (cow_pids[i] == -1) {
            LOG_ERROR("%sfork (COW): %s", label, strerror(errno));
            return FAILURE;        
        } else if (cow_pids[i] == 0) {
            // Child (Client Outbound Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) {
                if (j != i && worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]);
            }
            
            run_client_outbound_worker(i, worker_uds_cow_fds[i]);
            exit(EXIT_SUCCESS); // Child exits
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_cow_fds[i] != 0) close(worker_uds_cow_fds[i]);
            LOG_INFO("%sForked Client Outbound Worker %d (PID %d).", label, i, cow_pids[i]);
        }
    }
    return SUCCESS;
}
