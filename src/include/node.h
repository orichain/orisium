#ifndef NODE_H
#define NODE_H

#include <netinet/in.h>
#include <stdint.h>

#include "types.h"
#include "constants.h"

typedef struct {
    uint16_t len;
    struct sockaddr_in6 addr[MAX_BOOTSTRAP_NODES];
} bootstrap_nodes_t;

status_t read_listen_port_and_bootstrap_nodes_from_json(
    const char* label, 
    const char* filename, 
    uint16_t *listen_port,
    bootstrap_nodes_t* bootstrap_nodes
);

#endif
