#ifndef SESSIONS_H
#define SESSIONS_H

#include <stdbool.h>
#include <arpa/inet.h>

#include "types.h"
#include "constants.h"

typedef struct {
    bool in_use;
    int client_fd;
    uint64_t correlation_id;
    uint8_t ip[INET6_ADDRSTRLEN];
    bool awaiting_challenge_response;
} client_conn_state_t;

typedef struct closed_correlation_id_t {
    uint64_t correlation_id;
    struct closed_correlation_id_t *next;
} closed_correlation_id_t;

typedef struct {
	closed_correlation_id_t *r_closed_correlation_id_t;
	status_t status;
} closed_correlation_id_t_status_t;

typedef struct {
    bool in_use;
    uint64_t correlation_id;
    int sio_uds_fd;
    uint8_t ip[INET6_ADDRSTRLEN];
} master_client_session_t;

void add_closed_correlation_id(const char *label, closed_correlation_id_t **head, uint64_t id);
status_t delete_closed_correlation_id(const char *label, closed_correlation_id_t **head, uint64_t id);
closed_correlation_id_t_status_t find_closed_correlation_id(const char *label, closed_correlation_id_t *head, uint64_t id);
closed_correlation_id_t_status_t find_first_closed_correlation_id(const char *label, closed_correlation_id_t *head);
int_status_t count_closed_correlation_ids(const char *label, closed_correlation_id_t *head);
void display_closed_correlation_ids(const char *label, closed_correlation_id_t *head);
void free_closed_correlation_ids(const char *label, closed_correlation_id_t **head);

extern master_client_session_t master_client_sessions[MAX_MASTER_CONCURRENT_SESSIONS];
extern closed_correlation_id_t *closed_correlation_id_head;

#endif
