#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_types.h>

#include "log.h"
#include "constants.h"
#include "under_refinement_and_will_be_delete_after_finished.h"
#include "node.h"
#include "types.h"

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
