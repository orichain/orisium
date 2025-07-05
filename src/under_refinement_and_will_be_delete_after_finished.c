#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <sys/types.h>   // for pid_t, ssize_t

#include "ipc/protocol.h"
#include "under_refinement_and_will_be_delete_after_finished.h"

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
