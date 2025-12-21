#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(__NetBSD__)
    #include <sys/unistd.h>
    #include <json_object.h>
    #include <json_tokener.h>
    #include <json_types.h>
    #include <json_util.h>
#elif defined(__OpenBSD__)
    #include <sys/unistd.h>
    #include <json-c/json_object.h>
    #include <json-c/json_tokener.h>
    #include <json-c/json_types.h>
    #include <json-c/json_util.h>
#elif defined(__FreeBSD__)
    #include <sys/unistd.h>
    #include <arpa/inet.h>
    #include <json_object.h>
    #include <json_tokener.h>
    #include <json_types.h>
    #include <json_util.h>
#else
    #include <json-c/json_object.h>
    #include <json-c/json_tokener.h>
    #include <json-c/json_types.h>
    #include <json-c/json_util.h>
#endif

#include <stdint.h>

#include "log.h"
#include "constants.h"
#include "node.h"
#include "types.h"
#include "utilities.h"
#include "pqc.h"

status_t read_listen_port_and_bootstrap_nodes_from_json(
    const char* label, 
    const char* filename, 
    uint16_t *listen_port,
    uint8_t *bootstrap_signature, 
    uint8_t *config_signature,
    bootstrap_nodes_t* bootstrap_nodes
)
{
    FILE *fp = NULL;
    uint8_t buffer[MAX_BOOTSTRAP_FILE_SIZE];
    struct json_object *root_obj = NULL;
    struct json_object *listen_obj = NULL;
    struct json_object *bootstrap_obj = NULL;
    struct json_object *bnodes_obj = NULL;
    struct json_object *bsignature_obj = NULL;
    struct json_object *signature_obj = NULL;
    
    if (access(filename, F_OK) == 0) {
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
        root_obj = json_tokener_parse((const char *)buffer);
        if (root_obj == NULL) {
            LOG_ERROR("%sGagal mem-parsing JSON dari file: %s", label, filename);
            return FAILURE;
        }
        if (!json_object_object_get_ex(root_obj, "listen", &listen_obj) || !json_object_is_type(listen_obj, json_type_int)) {
            LOG_ERROR("%sKunci 'listen' tidak ditemukan atau tidak valid.", label);
            json_object_put(root_obj);
            return FAILURE;
        }
        *listen_port = json_object_get_int(listen_obj);
        if (!json_object_object_get_ex(root_obj, "bootstrap", &bootstrap_obj) || !json_object_is_type(bootstrap_obj, json_type_object)) {
            LOG_ERROR("%sKunci 'bootstrap' tidak ditemukan atau tidak valid.", label);
            json_object_put(root_obj);
            return FAILURE;
        }
        if (!json_object_object_get_ex(bootstrap_obj, "nodes", &bnodes_obj) || !json_object_is_type(bnodes_obj, json_type_array)) {
            LOG_ERROR("%sKunci 'bootstrap.nodes' tidak ditemukan atau tidak valid.", label);
            json_object_put(root_obj);
            return FAILURE;
        }
        int array_len = json_object_array_length(bnodes_obj);
        if (array_len > MAX_BOOTSTRAP_NODES) {
            LOG_DEBUG("%sJumlah bootstrap nodes (%d) melebihi MAX_BOOTSTRAP_NODES (%d). Hanya %d yang akan dibaca.",
                    label, array_len, MAX_BOOTSTRAP_NODES, MAX_BOOTSTRAP_NODES);
            array_len = MAX_BOOTSTRAP_NODES;
        }
        bootstrap_nodes->len = 0;
        for (int i = 0; i < array_len; i++) {
            struct json_object *node_obj = json_object_array_get_idx(bnodes_obj, i);
            if (!json_object_is_type(node_obj, json_type_object)) {
                LOG_DEBUG("%sElemen array bootstrap.nodes bukan objek pada indeks %d. Melewatkan.", label, i);
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
        if (!json_object_object_get_ex(bootstrap_obj, "signature", &bsignature_obj) || !json_object_is_type(bsignature_obj, json_type_string)) {
            LOG_ERROR("%sKunci 'bootstrap.signature' tidak ditemukan atau tidak valid.", label);
            json_object_put(root_obj);
            return FAILURE;
        }
        const char *bsignature_hex = json_object_get_string(bsignature_obj);
        if (hexs2bin(bsignature_hex, strlen(bsignature_hex), bootstrap_signature, SIGN_GENERATE_SIGNATURE_BBYTES) != 0) {
            LOG_ERROR("%sSignature bootstrap tidak valid.", label);
        }
        if (!json_object_object_get_ex(root_obj, "signature", &signature_obj) || !json_object_is_type(signature_obj, json_type_string)) {
            LOG_ERROR("%sKunci 'signature' tidak ditemukan atau tidak valid.", label);
            json_object_put(root_obj);
            return FAILURE;
        }
        const char *signature_hex = json_object_get_string(signature_obj);
        if (hexs2bin(signature_hex, strlen(signature_hex), config_signature, SIGN_GENERATE_SIGNATURE_BBYTES) != 0) {
            LOG_ERROR("%sSignature config tidak valid.", label);
        }
        json_object_put(root_obj);
    } else {
//======================================================================
// --- Write Initial Config File With Signature
// --- wip
//======================================================================
        struct json_object *root = json_object_new_object();
        struct json_object *boot_wrapper = json_object_new_object();
        struct json_object *nodes_arr = json_object_new_array();

        json_object_object_add(root, "timestamp", json_object_new_string(""));
        json_object_object_add(root, "listen", json_object_new_int(8443));
        for (int i = 0; i < 5; i++) {
            struct json_object *node = json_object_new_object();
            json_object_object_add(node, "ip", json_object_new_string("127.0.0.1"));
            json_object_object_add(node, "port", json_object_new_int(8443 + i));
            json_object_array_add(nodes_arr, node);
        }
        json_object_object_add(boot_wrapper, "nodes", nodes_arr);
        json_object_object_add(boot_wrapper, "signature", json_object_new_string(""));
        json_object_object_add(root, "bootstrap", boot_wrapper);
        json_object_object_add(root, "signature", json_object_new_string(""));
        if (json_object_to_file_ext(filename, root, JSON_C_TO_STRING_PRETTY) >= 0) {
            LOG_INFO("%sBerhasil membuat file konfigurasi default dengan 5 nodes: %s", label, filename);
        } else {
            LOG_ERROR("%sGagal menulis file konfigurasi: %s", label, filename);
            json_object_put(root);
            return FAILURE;
        }
        json_object_put(root);
        return read_listen_port_and_bootstrap_nodes_from_json(
            label, 
            filename, 
            listen_port,
            bootstrap_signature, 
            config_signature,
            bootstrap_nodes
        );
    }
    
    return SUCCESS;
}
