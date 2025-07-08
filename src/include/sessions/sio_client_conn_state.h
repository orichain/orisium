#ifndef SESSIONS_SIO_CLIENT_CONN_STATE_H
#define SESSIONS_SIO_CLIENT_CONN_STATE_H

#include <stdbool.h>

#include "types.h"
#include "constants.h"

typedef struct {
	int client_fd;
    bool in_use;
    uint64_t last_used;
    uint64_t last_ack;
    uint64_t correlation_id;
    uint8_t ip[IP_ADDRESS_LEN];
} sio_client_conn_state_t;

#endif
