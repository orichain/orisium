#ifndef SESSIONS_MASTER_CLIENT_SESSION_H
#define SESSIONS_MASTER_CLIENT_SESSION_H

#include <stdbool.h>
#include <arpa/inet.h>

#include "types.h"

typedef struct master_client_session_t {
	int sio_uds_fd;
    bool in_use;
    uint64_t last_used;
    uint64_t last_ack;
    uint64_t correlation_id;
    uint8_t ip[INET6_ADDRSTRLEN];
} master_client_session_t;

#endif
