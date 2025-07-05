#ifndef NODE_H
#define NODE_H

#include <arpa/inet.h>
#include "types.h"
#include "constants.h"

typedef struct {
    char ip[INET6_ADDRSTRLEN];
    int port;
} node_info_t;

typedef struct {
    char node_id[20];
    int listen_port;
    node_info_t bootstrap_nodes[MAX_NODES];
    int num_bootstrap_nodes;
} node_config_t;

extern node_config_t node_config;

status_t read_network_config_from_json(const char* filename, node_config_t* config_out);

#endif
