#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <sys/socket.h>  // for socketpair, SOCK_STREAM, AF_UNIX, AF_INET, accept
#include <sys/types.h>   // for pid_t, ssize_t
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_types.h>
#include <sys/uio.h>

#include "log.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "under_refinement_and_will_be_delete_after_finished.h"
#include "node.h"
#include "types.h"

// Send message over UDS, with optional FD passing (from ipc.h/ipc.c)
ssize_t send_ipc_message(int uds_fd, ipc_protocol_type_t type, const void *data, size_t data_len, int fd_to_pass) {
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
}

// Receive message over UDS, with optional FD reception (from ipc.h/ipc.c)
ssize_t recv_ipc_message(int uds_fd, ipc_msg_header_t *header, void *data_buffer, size_t buffer_size, int *actual_fd_received) {
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
}

// --- Fungsi Pembaca JSON Konfigurasi Jaringan (dari config.c/config.h) ---
status_t read_network_config_from_json(const char* filename, node_config_t* config_out) {
    FILE *fp = NULL;
    char buffer[MAX_FILE_SIZE];
    struct json_object *parsed_json = NULL;
    struct json_object *listen_port_obj = NULL;
    struct json_object *bootstrap_nodes_array = NULL;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        LOG_ERROR("Gagal membuka file konfigurasi: %s", strerror(errno));
        return FAILURE;
    }

    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, fp);
    if (bytes_read == 0 && !feof(fp)) {
        LOG_ERROR("Gagal membaca file atau file kosong: %s", filename);
        fclose(fp);
        return FAILURE;
    }
    buffer[bytes_read] = '\0';
    fclose(fp);

    parsed_json = json_tokener_parse(buffer);
    if (parsed_json == NULL) {
        LOG_ERROR("Gagal mem-parsing JSON dari file: %s", filename);
        return FAILURE;
    }

    if (!json_object_object_get_ex(parsed_json, "listen_port", &listen_port_obj) || !json_object_is_type(listen_port_obj, json_type_int)) {
        LOG_ERROR("Kunci 'listen_port' tidak ditemukan atau tidak valid.");
        json_object_put(parsed_json);
        return FAILURE;
    }
    config_out->listen_port = json_object_get_int(listen_port_obj);

    if (!json_object_object_get_ex(parsed_json, "bootstrap_nodes", &bootstrap_nodes_array) || !json_object_is_type(bootstrap_nodes_array, json_type_array)) {
        LOG_ERROR("Kunci 'bootstrap_nodes' tidak ditemukan atau tidak valid.");
        json_object_put(parsed_json);
        return FAILURE;
    }

    int array_len = json_object_array_length(bootstrap_nodes_array);
    if (array_len > MAX_NODES) {
        LOG_WARN("Jumlah bootstrap nodes (%d) melebihi MAX_NODES (%d). Hanya %d yang akan dibaca.",
                array_len, MAX_NODES, MAX_NODES);
        array_len = MAX_NODES;
    }

    config_out->num_bootstrap_nodes = 0;
    for (int i = 0; i < array_len; i++) {
        struct json_object *node_obj = json_object_array_get_idx(bootstrap_nodes_array, i);
        if (!json_object_is_type(node_obj, json_type_object)) {
            LOG_WARN("Elemen array bootstrap_nodes bukan objek pada indeks %d. Melewatkan.", i);
            continue;
        }

        struct json_object *ip_obj = NULL;
        struct json_object *port_obj = NULL;

        if (!json_object_object_get_ex(node_obj, "ip", &ip_obj) || !json_object_is_type(ip_obj, json_type_string)) {
            LOG_WARN("Kunci 'ip' tidak ditemukan atau bukan string pada node indeks %d. Melewatkan.", i);
            continue;
        }
        memcpy(config_out->bootstrap_nodes[config_out->num_bootstrap_nodes].ip,
                json_object_get_string(ip_obj), INET6_ADDRSTRLEN);
                
        if (!json_object_object_get_ex(node_obj, "port", &port_obj) || !json_object_is_type(port_obj, json_type_int)) {
            LOG_WARN("Kunci 'port' tidak ditemukan atau bukan integer pada node indeks %d. Melewatkan.", i);
            continue;
        }
        config_out->bootstrap_nodes[config_out->num_bootstrap_nodes].port = json_object_get_int(port_obj);

        config_out->num_bootstrap_nodes++;
    }

    json_object_put(parsed_json);
    return SUCCESS;
}
