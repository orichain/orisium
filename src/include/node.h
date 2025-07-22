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
    uint16_t len;
    struct sockaddr_in6 addr[MAX_BOOTSTRAP_NODES];
} bootstrap_nodes_t;

status_t read_listen_port_and_bootstrap_nodes_from_json(const char* label, const char* filename, uint16_t *listen_port, bootstrap_nodes_t* bootstrap_nodes);

#endif
