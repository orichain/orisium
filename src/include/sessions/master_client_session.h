#ifndef SESSIONS_MASTER_CLIENT_SESSION_H
#define SESSIONS_MASTER_CLIENT_SESSION_H

#include <stdbool.h>
#include <arpa/inet.h>

#include "types.h"
#include "constants.h"

typedef struct master_client_session_t {
	int sio_uds_fd;
    bool in_use;
    uint64_t last_used;
    uint64_t last_ack;
    uint64_t correlation_id;
    uint8_t ip[INET6_ADDRSTRLEN];
    struct master_client_session_t *next;
} master_client_session_t;

typedef struct {
	master_client_session_t *r_master_client_session_t;
	status_t status;
} master_client_session_t_status_t;

void add_master_client_session(const char *label, master_client_session_t **head, uint64_t id);
status_t delete_master_client_session(const char *label, master_client_session_t **head, uint64_t id);
master_client_session_t_status_t find_master_client_session(const char *label, master_client_session_t *head, uint64_t id);
master_client_session_t_status_t find_first_master_client_session(const char *label, master_client_session_t *head);
int_status_t count_master_client_sessions(const char *label, master_client_session_t *head);
void display_master_client_sessions(const char *label, master_client_session_t *head);
void free_master_client_sessions(const char *label, master_client_session_t **head);

extern master_client_session_t *master_client_session_head;

#endif
