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
#elif defined(__OpenBSD__)
    #include <sys/unistd.h>
    #include <json-c/json_object.h>
    #include <json-c/json_tokener.h>
    #include <json-c/json_types.h>
#elif defined(__FreeBSD__)
    #include <sys/unistd.h>
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
#include "fips202.h"
#include "pqc.h"

static void internal_hash_bootstrap_nodes(bootstrap_nodes_t *nodes, uint8_t *out) {
    shake256incctx st;
    shake256_inc_init(&st);
    for (size_t i = 0; i < nodes->len; i++) {
        shake256_inc_absorb(&st, (uint8_t *)&nodes->addr[i].sin6_addr, 16);
        uint16_t p = nodes->addr[i].sin6_port;
        shake256_inc_absorb(&st, (uint8_t *)&p, 2);
    }
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(out, HASHES_BYTES, &st);
    shake256_inc_ctx_release(&st);
}

status_t read_listen_port_and_bootstrap_nodes_from_json(
    const char* label, 
    const char* filename, 
    uint16_t *listen_port,
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
    struct json_object *time_obj = NULL;
    uint8_t n_signature[SIGN_GENERATE_SIGNATURE_BBYTES];
    uint8_t c_signature[SIGN_GENERATE_SIGNATURE_BBYTES];
    uint8_t gns_publickey[SIGN_PUBLICKEY_BYTES];
    uint8_t n_hash[HASHES_BYTES];
    uint8_t c_hash[HASHES_BYTES];
    size_t sgnlen = SIGN_GENERATE_SIGNATURE_BBYTES;
    
    if (access(filename, F_OK) == 0) {
        fp = fopen(filename, "r");
        if (fp == NULL) {
            LOG_ERROR("%sGagal membuka file konfigurasi: %s", label, strerror(errno));
            return FAILURE;
        }
        memset(buffer, 0, MAX_BOOTSTRAP_FILE_SIZE);
        size_t bytes_read = fread(buffer, 1, MAX_BOOTSTRAP_FILE_SIZE - 1, fp);
        if (bytes_read == 0 && !feof(fp)) {
            LOG_ERROR("%sGagal membaca file atau file kosong: %s", label, filename);
            fclose(fp);
            return FAILURE;
        }
        fclose(fp);
        buffer[bytes_read] = '\0';
        root_obj = json_tokener_parse((const char *)buffer);
        if (root_obj == NULL) {
            LOG_ERROR("%sGagal mem-parsing JSON dari file: %s", label, filename);
            return FAILURE;
        }
        if (json_object_object_get_ex(root_obj, "timestamp", &time_obj)) {
            const char *config_time = json_object_get_string(time_obj);
            if (strcmp(config_time, GENESIS_MIN_TSTMP) < 0) {
                LOG_ERROR("%sKonfigurasi terlalu lama (outdated). Minimal: %s", label, GENESIS_MIN_TSTMP);
                json_object_put(root_obj);
                return FAILURE;
            }
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
        if (array_len > MAX_BOOTSTRAP_NODES) array_len = MAX_BOOTSTRAP_NODES;
        bootstrap_nodes->len = 0;
        for (int i = 0; i < array_len; i++) {
            struct json_object *node_obj = json_object_array_get_idx(bnodes_obj, i);
            struct json_object *ip_obj = NULL, *port_obj = NULL;
            if (json_object_object_get_ex(node_obj, "ip", &ip_obj) && 
                json_object_object_get_ex(node_obj, "port", &port_obj)) {
                const char *ip_str = json_object_get_string(ip_obj);
                int port = json_object_get_int(port_obj);
                if (convert_str_to_sockaddr_in6(ip_str, port, &bootstrap_nodes->addr[bootstrap_nodes->len]) == SUCCESS) {
                    bootstrap_nodes->len++;
                }
            }
        }
        if (json_object_object_get_ex(bootstrap_obj, "signature", &bsignature_obj)) {
            const char *hex = json_object_get_string(bsignature_obj);
            if (hexs2bin(hex, strlen(hex), n_signature, SIGN_GENERATE_SIGNATURE_BBYTES) == -1) {
                LOG_ERROR("%sSignature bootstrap tidak valid.", label);
                json_object_put(root_obj);
                return FAILURE;
            }
        }
        if (json_object_object_get_ex(root_obj, "signature", &signature_obj)) {
            const char *hex = json_object_get_string(signature_obj);
            if (hexs2bin(hex, strlen(hex), c_signature, SIGN_GENERATE_SIGNATURE_BBYTES) == -1) {
                LOG_ERROR("%sSignature config tidak valid.", label);
                json_object_put(root_obj);
                return FAILURE;
            }
        }
        const char *gns_publickey_hex = GENESIS_PUBLICKEY;
        if (hexs2bin(gns_publickey_hex, strlen(gns_publickey_hex), gns_publickey, SIGN_PUBLICKEY_BYTES) == -1) {
            LOG_ERROR("%spublickey tidak valid", label);
            json_object_put(root_obj);
            return FAILURE;
        }
        internal_hash_bootstrap_nodes(bootstrap_nodes, n_hash);
        if (SIGN_VERIFY_SIGNATURE(n_signature, sgnlen, n_hash, HASHES_BYTES, gns_publickey) == -1) {
            LOG_ERROR("%ssignature bootstrap node tidak valid", label);
            json_object_put(root_obj);
            return FAILURE;
        }
        json_object_object_del(root_obj, "signature");
        const char *plain_json = json_object_to_json_string_ext(root_obj, JSON_C_TO_STRING_PLAIN);
        kdf(c_hash, HASHES_BYTES, (uint8_t*)plain_json, strlen(plain_json), (uint8_t*)"config_hash", 11);
        if (SIGN_VERIFY_SIGNATURE(c_signature, sgnlen, c_hash, HASHES_BYTES, gns_publickey) == -1) {
            LOG_ERROR("%ssignature config tidak valid", label);
            json_object_put(root_obj);
            return FAILURE;
        }
        json_object_put(root_obj);
    } else {
        uint8_t gns_privatekey[SIGN_PRIVATEKEY_BYTES];
        char gns_publickey_hex[SIGN_PUBLICKEY_BYTES * 2 + 1];
        char gns_privatekey_hex[SIGN_PRIVATEKEY_BYTES * 2 + 1];
        
        FILE *wfp;
        if (access("GENESIS_PUBLICKEY", F_OK) != 0 && access("GENESIS_PRIVATEKEY_SAVE_IN_SAFEST_PLACE", F_OK) != 0) {
            SIGN_GENERATE_KEYPAIR(gns_publickey, gns_privatekey);
            bin2hexs(gns_publickey, SIGN_PUBLICKEY_BYTES, gns_publickey_hex);
            bin2hexs(gns_privatekey, SIGN_PRIVATEKEY_BYTES, gns_privatekey_hex);
            wfp = fopen("GENESIS_PUBLICKEY", "w");
            if (wfp) {
                fputs(gns_publickey_hex, wfp);
                fclose(wfp);
                LOG_INFO("%sBerhasil membuat file : %s", label, "GENESIS_PUBLICKEY");
            } else {
                LOG_ERROR("%sGagal menulis file: %s", label, strerror(errno));
                return FAILURE;
            }
            wfp = fopen("GENESIS_PRIVATEKEY_SAVE_IN_SAFEST_PLACE", "w");
            if (wfp) {
                fputs(gns_privatekey_hex, wfp);
                fclose(wfp);
                LOG_INFO("%sBerhasil membuat file : %s", label, "GENESIS_PRIVATEKEY_SAVE_IN_SAFEST_PLACE");
            } else {
                LOG_ERROR("%sGagal menulis file: %s", label, strerror(errno));
                return FAILURE;
            }
        } else {
            FILE *rfp;
            size_t bytes_read = 0;
            rfp = fopen("GENESIS_PUBLICKEY", "r");
            if (rfp == NULL) {
                LOG_ERROR("%sGagal membuka file: %s", label, strerror(errno));
                return FAILURE;
            }
            bytes_read = fread(gns_publickey_hex, 1, SIGN_PUBLICKEY_BYTES * 2, rfp);
            if (bytes_read == 0 && !feof(rfp)) {
                LOG_ERROR("%sGagal membaca file: %s", label, "GENESIS_PUBLICKEY");
                fclose(rfp);
                return FAILURE;
            }
            fclose(rfp);
            gns_publickey_hex[SIGN_PUBLICKEY_BYTES * 2] = '\0';
            if (hexs2bin(gns_publickey_hex, strlen(gns_publickey_hex), gns_publickey, SIGN_PUBLICKEY_BYTES) == -1) {
                LOG_ERROR("%spublickey tidak valid", label);
                return FAILURE;
            }
            rfp = fopen("GENESIS_PRIVATEKEY_SAVE_IN_SAFEST_PLACE", "r");
            if (rfp == NULL) {
                LOG_ERROR("%sGagal membuka file: %s", label, strerror(errno));
                return FAILURE;
            }
            bytes_read = fread(gns_privatekey_hex, 1, SIGN_PRIVATEKEY_BYTES * 2, rfp);
            if (bytes_read == 0 && !feof(rfp)) {
                LOG_ERROR("%sGagal membaca file: %s", label, "GENESIS_PRIVATEKEY_SAVE_IN_SAFEST_PLACE");
                fclose(rfp);
                return FAILURE;
            }
            fclose(rfp);
            gns_privatekey_hex[SIGN_PRIVATEKEY_BYTES * 2] = '\0';
            if (hexs2bin(gns_privatekey_hex, strlen(gns_privatekey_hex), gns_privatekey, SIGN_PRIVATEKEY_BYTES) == -1) {
                LOG_ERROR("%sprivatekey tidak valid", label);
                return FAILURE;
            }
        }
        struct json_object *root = json_object_new_object();
        struct json_object *boot_wrapper = json_object_new_object();
        struct json_object *nodes_arr = json_object_new_array();

        char timebuf[32];
        get_time_str(timebuf, sizeof(timebuf));
        json_object_object_add(root, "timestamp", json_object_new_string(timebuf));
        json_object_object_add(root, "listen", json_object_new_int(8443));
        bootstrap_nodes->len = 0;
        for (int i = 0; i < 5; i++) {
            struct json_object *node = json_object_new_object();
            char *ip = "127.0.0.1";
            uint16_t port = 8443 + i;            
            json_object_object_add(node, "ip", json_object_new_string(ip));
            json_object_object_add(node, "port", json_object_new_int(port));
            json_object_array_add(nodes_arr, node);
            convert_str_to_sockaddr_in6(ip, port, &bootstrap_nodes->addr[bootstrap_nodes->len++]);
        }
        json_object_object_add(boot_wrapper, "nodes", nodes_arr);
//----------------------------------------------------------------------
        internal_hash_bootstrap_nodes(bootstrap_nodes, n_hash);
        SIGN_GENERATE_SIGNATURE(n_signature, &sgnlen, n_hash, HASHES_BYTES, gns_privatekey);
        char n_signature_hex[SIGN_GENERATE_SIGNATURE_BBYTES * 2 + 1];
        bin2hexs(n_signature, SIGN_GENERATE_SIGNATURE_BBYTES, n_signature_hex);
        json_object_object_add(boot_wrapper, "signature", json_object_new_string(n_signature_hex));
        json_object_object_add(root, "bootstrap", boot_wrapper);
//----------------------------------------------------------------------        
        const char *plain_json = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
        kdf(c_hash, HASHES_BYTES, (uint8_t*)plain_json, strlen(plain_json), (uint8_t*)"config_hash", 11);
        SIGN_GENERATE_SIGNATURE(c_signature, &sgnlen, c_hash, HASHES_BYTES, gns_privatekey);
        char c_signature_hex[SIGN_GENERATE_SIGNATURE_BBYTES * 2 + 1];
        bin2hexs(c_signature, SIGN_GENERATE_SIGNATURE_BBYTES, c_signature_hex);
        json_object_object_add(root, "signature", json_object_new_string(c_signature_hex));
//----------------------------------------------------------------------
        const char *pretty_json = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
        wfp = fopen(filename, "w");
        if (wfp) {
            fputs(pretty_json, wfp);
            fclose(wfp);
            LOG_INFO("%sBerhasil membuat file konfigurasi dengan hash awal: %s", label, filename);
        } else {
            LOG_ERROR("%sGagal menulis file: %s", label, strerror(errno));
            json_object_put(root);
            return FAILURE;
        }
        json_object_put(root);
        return read_listen_port_and_bootstrap_nodes_from_json(label, filename, listen_port, bootstrap_nodes);
    }
    return SUCCESS;
}
