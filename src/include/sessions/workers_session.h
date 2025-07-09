#ifndef SESSIONS_WORKERS_SESSION_H
#define SESSIONS_WORKERS_SESSION_H

#include <stdbool.h>

#include "types.h"
#include "constants.h"

typedef struct {
//======================================================================
// Untuk read parsial
//======================================================================	
    uint8_t *buffer;
    size_t buffer_allocated_size;
    size_t current_pos;
    uint32_t total_expected_len;
    bool is_reading_prefix;
//======================================================================
} state_reader_t;

typedef struct {
//======================================================================
// Untuk write parsial
//======================================================================	
    uint8_t *send_buffer;
    size_t send_buffer_len;
    size_t send_current_pos;
    bool is_writing;  
//======================================================================
} state_writer_t;    

typedef struct {
	int client_fd;
	bool in_use;
    uint8_t ip[IP_ADDRESS_LEN];
    uint64_t last_ack;
    state_reader_t reader; 
    state_writer_t writer; 
} sio_c_state_t; //Server socket

typedef struct {
	int client_fd;
	bool in_use;
    uint8_t ip[IP_ADDRESS_LEN];
    uint64_t last_ack;
    state_reader_t reader;
    state_writer_t writer; 
} cow_c_state_t; //Client socket

#endif
