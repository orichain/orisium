#ifndef SESSIONS_H
#define SESSIONS_H

typedef struct {
    bool in_use;
    int client_fd;
    long correlation_id; // Unique ID for this client session
    char client_ip[INET6_ADDRSTRLEN]; // Added to track client IP in SIO worker
    // For challenge-response or other stateful interactions
    bool awaiting_challenge_response;
    // Buffer for partial reads, if needed
} client_conn_state_t;

#endif
