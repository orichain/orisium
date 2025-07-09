#ifndef SESSIONS_WORKERS_SESSION_H
#define SESSIONS_WORKERS_SESSION_H

#include <stdbool.h>

#include "types.h"
#include "constants.h"

typedef struct {
	int client_fd;
	bool in_use;
    bool is_busy;
    uint8_t ip[IP_ADDRESS_LEN];
    uint64_t last_ack;
    uint8_t *buffer;
    size_t buffer_allocated_size;
    size_t current_pos;
    uint32_t total_expected_len;
    bool is_reading_prefix;   
} sio_c_state_t;

typedef struct {
	int client_fd;
	bool in_use;
    bool is_busy;
    uint8_t ip[IP_ADDRESS_LEN];
    uint64_t last_ack;
    uint8_t *buffer;
    size_t buffer_allocated_size;
    size_t current_pos;
    uint32_t total_expected_len;
    bool is_reading_prefix;   
} cow_c_state_t;

#endif
