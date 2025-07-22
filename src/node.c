#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "log.h"
#include "constants.h"
#include "node.h"
#include "types.h"
#include "utilities.h"
#include "pqc.h"

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
        
        if (convert_str_to_ipv6_bin(iptmp, bootstrap_nodes->data[bootstrap_nodes->len].ip) != SUCCESS) {
			LOG_ERROR("%sIP tidak valid %s.", iptmp);
            continue;
		}
        
        inet_pton(AF_INET6, iptmp, bootstrap_nodes->data[bootstrap_nodes->len].ip);
                
        if (!json_object_object_get_ex(node_obj, "port", &port_obj) || !json_object_is_type(port_obj, json_type_int)) {
            LOG_DEBUG("%sKunci 'port' tidak ditemukan atau bukan integer pada node indeks %d. Melewatkan.", label, i);
            continue;
        }
        
        int port = json_object_get_int(port_obj);
        if (port <= 0 || port > 65535) {
			LOG_ERROR("%sPORT tidak valid %d.", port);
            continue;
		}
        
        bootstrap_nodes->data[bootstrap_nodes->len].port = json_object_get_int(port_obj);

        bootstrap_nodes->len++;
    }

    json_object_put(parsed_json);
    return SUCCESS;
}


status_t node_identity_init(const char *filepath, node_identity_t *out) {
    FILE *f = fopen(filepath, "rb");
    if (f) {
        // File exists, load
        char magic[9] = {0};
        fread(magic, 1, 8, f);
        if (strcmp(magic, NODE_FILE_MAGIC) != 0) {
            fclose(f);
            return FAILURE_NDFLMGC;
        }

        fread(&out->version, sizeof(uint8_t), 1, f);
        fread(&out->timestamp, sizeof(uint64_t), 1, f);
        fread(&out->kem_algo, sizeof(algo_type_t), 1, f);
        fread(&out->sign_algo, sizeof(algo_type_t), 1, f);
        fread(&out->vrf_algo, sizeof(algo_type_t), 1, f);

        const pqc_algo_info_t *kem  = get_pqc_info(out->kem_algo);
        const pqc_algo_info_t *sign = get_pqc_info(out->sign_algo);
        const pqc_algo_info_t *vrf  = get_pqc_info(out->vrf_algo);

        out->kem_pubkey     = malloc(kem->public_key_len);
        out->sign_pubkey    = malloc(sign->public_key_len);
        out->vrf_pubkey     = malloc(vrf->public_key_len);
        out->signature      = malloc(sign->signature_len);

        fread(out->kem_pubkey, 1, kem->public_key_len, f);
        fread(out->sign_pubkey, 1, sign->public_key_len, f);
        fread(out->vrf_pubkey, 1, vrf->public_key_len, f);
        fread(out->signature, 1, sign->signature_len, f);

        fclose(f);
        return SUCCESS;
    }

    // File not found, generate new keys
    out->version     = NODE_VERSION;
    out->timestamp   = (uint64_t)time(NULL);
    out->kem_algo    = KEM_MLKEM1024;
    out->sign_algo   = SIGN_FALCONPADDED512;
    out->vrf_algo    = SIGN_FALCONPADDED512;

    const pqc_algo_info_t *kem  = get_pqc_info(out->kem_algo);
    const pqc_algo_info_t *sign = get_pqc_info(out->sign_algo);
    const pqc_algo_info_t *vrf  = get_pqc_info(out->vrf_algo);

    // Allocate and generate keys
    uint8_t kem_sk[kem->private_key_len];
    uint8_t sign_sk[sign->private_key_len];
    uint8_t vrf_sk[vrf->private_key_len];

    out->kem_pubkey  = malloc(kem->public_key_len);
    out->sign_pubkey = malloc(sign->public_key_len);
    out->vrf_pubkey  = malloc(vrf->public_key_len);
    out->signature   = malloc(sign->signature_len);

    kem_generate_keypair(out->kem_pubkey, kem_sk, out->kem_algo);
    sgn_generate_keypair(out->sign_pubkey, sign_sk, out->sign_algo);
    sgn_generate_keypair(out->vrf_pubkey, vrf_sk, out->vrf_algo);

    // Signature over metadata (version + timestamp + all pubkeys)
    uint8_t msg[1 + 8 + kem->public_key_len + sign->public_key_len + vrf->public_key_len];
    size_t offset = 0;
    msg[offset++] = out->version;
    memcpy(msg + offset, &out->timestamp, 8); offset += 8;
    memcpy(msg + offset, out->kem_pubkey, kem->public_key_len); offset += kem->public_key_len;
    memcpy(msg + offset, out->sign_pubkey, sign->public_key_len); offset += sign->public_key_len;
    memcpy(msg + offset, out->vrf_pubkey, vrf->public_key_len); offset += vrf->public_key_len;

    size_t siglen = 0;
    sgn_sign(out->signature, &siglen, msg, offset, sign_sk, out->sign_algo);

    // Save to file
    f = fopen(filepath, "wb");
    if (!f) return FAILURE_OPNFL;

    fwrite(NODE_FILE_MAGIC, 1, 8, f);
    fwrite(&out->version, sizeof(uint8_t), 1, f);
    fwrite(&out->timestamp, sizeof(uint64_t), 1, f);
    fwrite(&out->kem_algo, sizeof(algo_type_t), 1, f);
    fwrite(&out->sign_algo, sizeof(algo_type_t), 1, f);
    fwrite(&out->vrf_algo, sizeof(algo_type_t), 1, f);
    fwrite(out->kem_pubkey, 1, kem->public_key_len, f);
    fwrite(out->sign_pubkey, 1, sign->public_key_len, f);
    fwrite(out->vrf_pubkey, 1, vrf->public_key_len, f);
    fwrite(out->signature, 1, sign->signature_len, f);
    fclose(f);

    return 0;
}

void node_identity_free(node_identity_t *id) {
    if (!id) return;
    free(id->kem_pubkey);
    free(id->sign_pubkey);
    free(id->vrf_pubkey);
    free(id->signature);
    memset(id, 0, sizeof(*id));
}
