#ifndef SESSIONS_H
#define SESSIONS_H

typedef struct {
    bool in_use;
    int client_fd;
    uint64_t correlation_id;
    uint8_t ip[INET6_ADDRSTRLEN];
    bool awaiting_challenge_response;
} client_conn_state_t;

typedef struct {
    bool in_use;
    uint64_t correlation_id;
    int sio_uds_fd;
    uint8_t ip[INET6_ADDRSTRLEN];
} master_client_session_t;

extern master_client_session_t master_client_sessions[MAX_MASTER_CONCURRENT_SESSIONS];

#endif
