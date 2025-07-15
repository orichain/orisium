#ifndef NODE_H
#define NODE_H

#include "types.h"
#include "constants.h"
#include "pqc.h"

typedef struct {
    uint8_t version;
    uint64_t timestamp;
    algo_type_t kem_algo;
    algo_type_t sign_algo;
    algo_type_t vrf_algo;
    uint8_t *kem_pubkey;
    uint8_t *sign_pubkey;
    uint8_t *vrf_pubkey;
    uint8_t *signature;
} node_identity_t;

status_t node_identity_init(const char *filepath, node_identity_t *out);
void node_identity_free(node_identity_t *id);

typedef struct {
    uint8_t ip[IP_ADDRESS_LEN];
    int port;
} node_info_t;

typedef struct {
    char node_id[20];
    int listen_port;
    node_info_t bootstrap_nodes[MAX_NODES];
    int num_bootstrap_nodes;
} node_config_t;

extern node_config_t node_config;

status_t read_network_config_from_json(const char* label, const char* filename, node_config_t* config_out);

#endif
