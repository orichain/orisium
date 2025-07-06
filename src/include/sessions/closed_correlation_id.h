#ifndef SESSIONS_CLOSED_CORRELATION_ID_H
#define SESSIONS_CLOSED_CORRELATION_ID_H

#include <stdbool.h>
#include <arpa/inet.h>

#include "types.h"
#include "constants.h"

typedef struct closed_correlation_id_t {
    uint64_t correlation_id;
    uint8_t ip[INET6_ADDRSTRLEN];
    uint64_t closed_time;
    struct closed_correlation_id_t *next;
} closed_correlation_id_t;

typedef struct {
	closed_correlation_id_t *r_closed_correlation_id_t;
	status_t status;
} closed_correlation_id_t_status_t;

status_t add_closed_correlation_id(const char *label, closed_correlation_id_t **head, uint64_t id, uint8_t host_ip[]);
status_t delete_closed_correlation_id(const char *label, closed_correlation_id_t **head, uint64_t id);
closed_correlation_id_t_status_t find_closed_correlation_id(const char *label, closed_correlation_id_t *head, uint64_t id);
closed_correlation_id_t_status_t find_first_ratelimited_closed_correlation_id(const char *label, closed_correlation_id_t *head, uint8_t host_ip[]);
int_status_t count_closed_correlation_ids(const char *label, closed_correlation_id_t *head);
void display_closed_correlation_ids(const char *label, closed_correlation_id_t *head);
void free_closed_correlation_ids(const char *label, closed_correlation_id_t **head);

extern closed_correlation_id_t *closed_correlation_id_head;

#endif
