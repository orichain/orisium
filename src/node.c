#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
// #include <json-c/json_types.h> // Hapus baris ini
#include <arpa/inet.h>
#include <sys/socket.h>
#include <json-c/json_types.h>

#include "log.h"
#include "constants.h"
#include "node.h"
#include "types.h"
#include "utilities.h"

status_t read_network_config_from_json(const char* label, const char* filename, node_config_t* config_out) {
    FILE *fp = NULL;
    char buffer[MAX_FILE_SIZE];
    struct json_object *parsed_json = NULL;
    struct json_object *listen_port_obj = NULL;
    struct json_object *bootstrap_nodes_array = NULL;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        LOG_ERROR("%sGagal membuka file konfigurasi: %s", label, strerror(errno));
        return FAILURE;
    }

    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, fp);
    if (bytes_read == 0 && !feof(fp)) {
        LOG_ERROR("%sGagal membaca file atau file kosong: %s", label, filename);
        fclose(fp);
        return FAILURE;
    }
    buffer[bytes_read] = '\0';
    fclose(fp);

    parsed_json = json_tokener_parse(buffer);
    if (parsed_json == NULL) {
        LOG_ERROR("%sGagal mem-parsing JSON dari file: %s", label, filename);
        return FAILURE;
    }

    if (!json_object_object_get_ex(parsed_json, "listen_port", &listen_port_obj) || json_object_get_type(listen_port_obj) != json_type_int) {
        LOG_ERROR("%sKunci 'listen_port' tidak ditemukan atau tidak valid.", label);
        json_object_put(parsed_json);
        return FAILURE;
    }
    config_out->listen_port = json_object_get_int(listen_port_obj);

    if (!json_object_object_get_ex(parsed_json, "bootstrap_nodes", &bootstrap_nodes_array) || json_object_get_type(bootstrap_nodes_array) != json_type_array) {
        LOG_ERROR("%sKunci 'bootstrap_nodes' tidak ditemukan atau tidak valid.", label);
        json_object_put(parsed_json);
        return FAILURE;
    }

    int array_len = json_object_array_length(bootstrap_nodes_array);
    if (array_len > MAX_NODES) {
        LOG_WARN("%sJumlah bootstrap nodes (%d) melebihi MAX_NODES (%d). Hanya %d yang akan dibaca.",
                 label, array_len, MAX_NODES, MAX_NODES);
        array_len = MAX_NODES;
    }

    config_out->num_bootstrap_nodes = 0;
    for (int i = 0; i < array_len; i++) {
        struct json_object *node_obj = json_object_array_get_idx(bootstrap_nodes_array, i);
        if (json_object_get_type(node_obj) != json_type_object) {
            LOG_WARN("%sElemen array bootstrap_nodes bukan objek pada indeks %d. Melewatkan.", label, i);
            continue;
        }

        struct json_object *ip_obj = NULL;
        struct json_object *port_obj = NULL;

        if (!json_object_object_get_ex(node_obj, "ip", &ip_obj) || json_object_get_type(ip_obj) != json_type_string) {
            LOG_WARN("%sKunci 'ip' tidak ditemukan atau bukan string pada node indeks %d. Melewatkan.", label, i);
            continue;
        }
        
        char iptmp[INET6_ADDRSTRLEN];
        strncpy(iptmp, json_object_get_string(ip_obj), INET6_ADDRSTRLEN - 1);
        iptmp[INET6_ADDRSTRLEN - 1] = '\0';
        
        if (convert_str_to_ipv6_bin(iptmp, config_out->bootstrap_nodes[config_out->num_bootstrap_nodes].ip) != SUCCESS) {
            LOG_ERROR("%sIP tidak valid %s.", iptmp);
            continue;
        }
        
        inet_pton(AF_INET6, iptmp, config_out->bootstrap_nodes[config_out->num_bootstrap_nodes].ip);
                
        if (!json_object_object_get_ex(node_obj, "port", &port_obj) || json_object_get_type(port_obj) != json_type_int) {
            LOG_WARN("%sKunci 'port' tidak ditemukan atau bukan integer pada node indeks %d. Melewatkan.", label, i);
            continue;
        }
        
        int port = json_object_get_int(port_obj);
        if (port <= 0 || port > 65535) {
            LOG_ERROR("%sPORT tidak valid %d.", port);
            continue;
        }
        
        config_out->bootstrap_nodes[config_out->num_bootstrap_nodes].port = json_object_get_int(port_obj);

        config_out->num_bootstrap_nodes++;
    }

    json_object_put(parsed_json);
    return SUCCESS;
}
