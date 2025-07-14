#ifndef NODE_H
#define NODE_H

#include "types.h"
#include "constants.h"

typedef struct {
    uint8_t  version;
    uint64_t timestamp;
    uint8_t  kem_pubkey[MLKEM1024_PUBKEY_LEN];
    uint8_t  sign_pubkey[FALCON_PUBKEY_LEN];
    uint8_t  vrf_pubkey[VRF_PUBKEY_LEN];
    uint8_t  signature[FALCON_SIGNATURE_LEN];
} node_identity_t;

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
