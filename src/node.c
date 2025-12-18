#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#if defined(__NetBSD__) || defined(__FreeBSD__)
    #include <json_object.h>
    #include <json_tokener.h>
    #include <json_types.h>
#else
    #include <json-c/json_object.h>
    #include <json-c/json_tokener.h>
    #include <json-c/json_types.h>
#endif

#include <stdint.h>

#include "log.h"
#include "constants.h"
#include "node.h"
#include "types.h"
#include "utilities.h"

status_t read_listen_port_and_bootstrap_nodes_from_json(const char* label, const char* filename, uint16_t *listen_port, bootstrap_nodes_t* bootstrap_nodes) {
    FILE *fp = NULL;
    uint8_t buffer[MAX_BOOTSTRAP_FILE_SIZE];
    struct json_object *parsed_json = NULL;
    struct json_object *listen_port_obj = NULL;
    struct json_object *bootstrap_nodes_array = NULL;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        LOG_ERROR("%sGagal membuka file konfigurasi: %s", label, strerror(errno));
        return FAILURE;
    }

    memset(buffer, 0, MAX_BOOTSTRAP_FILE_SIZE);
    size_t bytes_read = fread(buffer, 1, MAX_BOOTSTRAP_FILE_SIZE, fp);
    if (bytes_read == 0 && !feof(fp)) {
        LOG_ERROR("%sGagal membaca file atau file kosong: %s", label, filename);
        fclose(fp);
        return FAILURE;
    }
    fclose(fp);

    parsed_json = json_tokener_parse((const char *)buffer);
    if (parsed_json == NULL) {
        LOG_ERROR("%sGagal mem-parsing JSON dari file: %s", label, filename);
        return FAILURE;
    }

    if (!json_object_object_get_ex(parsed_json, "listen_port", &listen_port_obj) || !json_object_is_type(listen_port_obj, json_type_int)) {
        LOG_ERROR("%sKunci 'listen_port' tidak ditemukan atau tidak valid.", label);
        json_object_put(parsed_json);
        return FAILURE;
    }
    *listen_port = json_object_get_int(listen_port_obj);

    if (!json_object_object_get_ex(parsed_json, "bootstrap_nodes", &bootstrap_nodes_array) || !json_object_is_type(bootstrap_nodes_array, json_type_array)) {
        LOG_ERROR("%sKunci 'bootstrap_nodes' tidak ditemukan atau tidak valid.", label);
        json_object_put(parsed_json);
        return FAILURE;
    }

    int array_len = json_object_array_length(bootstrap_nodes_array);
    if (array_len > MAX_BOOTSTRAP_NODES) {
        LOG_DEBUG("%sJumlah bootstrap nodes (%d) melebihi MAX_BOOTSTRAP_NODES (%d). Hanya %d yang akan dibaca.",
                label, array_len, MAX_BOOTSTRAP_NODES, MAX_BOOTSTRAP_NODES);
        array_len = MAX_BOOTSTRAP_NODES;
    }

    bootstrap_nodes->len = 0;
    for (int i = 0; i < array_len; i++) {
        struct json_object *node_obj = json_object_array_get_idx(bootstrap_nodes_array, i);
        if (!json_object_is_type(node_obj, json_type_object)) {
            LOG_DEBUG("%sElemen array bootstrap_nodes bukan objek pada indeks %d. Melewatkan.", label, i);
            continue;
        }

        struct json_object *ip_obj = NULL;
        struct json_object *port_obj = NULL;

        if (!json_object_object_get_ex(node_obj, "ip", &ip_obj) || !json_object_is_type(ip_obj, json_type_string)) {
            LOG_DEBUG("%sKunci 'ip' tidak ditemukan atau bukan string pada node indeks %d. Melewatkan.", label, i);
            continue;
        }
        
        char iptmp[INET6_ADDRSTRLEN];
        strncpy(iptmp, json_object_get_string(ip_obj), INET6_ADDRSTRLEN - 1);
        iptmp[INET6_ADDRSTRLEN - 1] = '\0';
        
        if (!json_object_object_get_ex(node_obj, "port", &port_obj) || !json_object_is_type(port_obj, json_type_int)) {
            LOG_DEBUG("%sKunci 'port' tidak ditemukan atau bukan integer pada node indeks %d. Melewatkan.", label, i);
            continue;
        }
        
        int port = json_object_get_int(port_obj);
        if (port <= 0 || port > 65535) {
			LOG_ERROR("%sPORT tidak valid %d.", port);
            continue;
		}
        
        if (convert_str_to_sockaddr_in6(iptmp, port, &bootstrap_nodes->addr[bootstrap_nodes->len]) != SUCCESS) {
            LOG_ERROR("%sIP tidak valid %s.", iptmp);
            continue;
        }

        bootstrap_nodes->len++;
    }

    json_object_put(parsed_json);
    return SUCCESS;
}
