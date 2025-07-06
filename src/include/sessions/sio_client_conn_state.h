#ifndef SESSIONS_SIO_CLIENT_CONN_STATE_H
#define SESSIONS_SIO_CLIENT_CONN_STATE_H

#include <stdbool.h>
#include <arpa/inet.h>

#include "types.h"

typedef struct sio_client_conn_state_t {
	int client_fd;
    bool in_use;
    uint64_t last_used;
    uint64_t last_ack;
    uint64_t correlation_id;
    uint8_t ip[INET6_ADDRSTRLEN];
} sio_client_conn_state_t;

#endif
