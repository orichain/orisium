#ifndef SESSIONS_MASTER_SESSION_H
#define SESSIONS_MASTER_SESSION_H

#include <stdbool.h>

#include "types.h"
#include "constants.h"

//======================================================================
// new_avg = ((last_avg * count) + current_task_time) / (count + 1);
//======================================================================
typedef struct {
	int sio_uds_fd;
	bool in_use;
    bool is_busy;
	uint64_t last_ack;
	uint16_t task_count;
	uint64_t last_task_started;
	uint64_t last_task_finished;
	double longest_task_time;
	double avg_task_time;
} master_sio_state_t;

typedef struct {
	int logic_uds_fd;
	bool in_use;
    bool is_busy;
	uint64_t last_ack;
	uint16_t task_count;
	uint64_t last_task_started;
	uint64_t last_task_finished;
	double longest_task_time;
	double avg_task_time;
} master_logic_state_t;

typedef struct {
	int dbr_uds_fd;
	bool in_use;
    bool is_busy;
	uint64_t last_ack;
	uint16_t task_count;
	uint64_t last_task_started;
	uint64_t last_task_finished;
	double longest_task_time;
	double avg_task_time;
} master_dbr_state_t;
//======================================================================
// hanya ada 1 writer
// LMDB tidak bisa multi writer
// Master harus punya write cache dalam bentuk linked list
// Master harus punya timer untuk cek master_dbw_state_t in_use
// Saat in_use=false write cache dikirim ke dbw worker
// yang membuat in_use=false dan is_busy=true haruslah dbw worker
// untuk memastikan penulisan ditangani
//======================================================================
typedef struct {
	int dbw_uds_fd;
	bool in_use;
	bool is_busy;
	uint64_t last_ack;
	uint64_t last_task_started;
	uint64_t last_task_finished;
	double longest_task_time;
	double avg_task_time;
} master_dbw_state_t;

typedef struct {
	int cow_uds_fd;
    bool in_use;
    bool is_busy;
    uint8_t ip[IP_ADDRESS_LEN];
    uint16_t port;
    uint64_t last_ack;
    uint64_t last_task_started;
	uint64_t last_task_finished;
	double longest_task_time;
	double avg_task_time;
} master_cow_session_t;

typedef struct {
	int sio_uds_fd;
    bool in_use;
    bool is_busy;
    uint8_t ip[IP_ADDRESS_LEN];
    uint64_t last_ack;
    uint64_t last_task_started;
	uint64_t last_task_finished;
	double longest_task_time;
	double avg_task_time;
} master_sio_c_session_t;

typedef struct master_sio_dc_session_t {
    uint8_t ip[IP_ADDRESS_LEN];
    uint64_t dc_time;
    struct master_sio_dc_session_t *next;
} master_sio_dc_session_t;

typedef struct {
	master_sio_dc_session_t *r_master_sio_dc_session_t;
	status_t status;
} master_sio_dc_session_t_status_t;

status_t add_master_sio_dc_session(const char *label, master_sio_dc_session_t **head, uint8_t ip[]);
status_t delete_master_sio_dc_session(const char *label, master_sio_dc_session_t **head, uint8_t ip[]);
master_sio_dc_session_t_status_t find_master_sio_dc_session(const char *label, master_sio_dc_session_t *head, uint8_t ip[]);
master_sio_dc_session_t_status_t find_first_ratelimited_master_sio_dc_session(const char *label, master_sio_dc_session_t *head, uint8_t ip[]);
int_status_t count_master_sio_dc_sessions(const char *label, master_sio_dc_session_t *head);
void display_master_sio_dc_sessions(const char *label, master_sio_dc_session_t *head);
void free_master_sio_dc_sessions(const char *label, master_sio_dc_session_t **head);

extern master_sio_dc_session_t *master_sio_dc_session_head;

#endif
