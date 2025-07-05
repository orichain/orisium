#ifndef SESSIONS_SIO_CLIENT_CONN_STATE_H
#define SESSIONS_SIO_CLIENT_CONN_STATE_H

#include <stdbool.h>
#include <arpa/inet.h>

#include "types.h"
#include "constants.h"

typedef struct sio_client_conn_state_t {
	int client_fd;
    bool in_use;
    uint64_t last_used;
    uint64_t last_ack;
    uint64_t correlation_id;
    uint8_t ip[INET6_ADDRSTRLEN];
    struct sio_client_conn_state_t *next;
} sio_client_conn_state_t;

typedef struct {
	sio_client_conn_state_t *r_sio_client_conn_state_t;
	status_t status;
} sio_client_conn_state_t_status_t;

void add_sio_client_conn_state(const char *label, sio_client_conn_state_t **head, uint64_t id);
status_t delete_sio_client_conn_state(const char *label, sio_client_conn_state_t **head, uint64_t id);
sio_client_conn_state_t_status_t find_sio_client_conn_state(const char *label, sio_client_conn_state_t *head, uint64_t id);
sio_client_conn_state_t_status_t find_first_sio_client_conn_state(const char *label, sio_client_conn_state_t *head);
int_status_t count_sio_client_conn_states(const char *label, sio_client_conn_state_t *head);
void display_sio_client_conn_states(const char *label, sio_client_conn_state_t *head);
void free_sio_client_conn_states(const char *label, sio_client_conn_state_t **head);

#endif
