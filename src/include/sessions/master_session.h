#ifndef SESSIONS_MASTER_SESSION_H
#define SESSIONS_MASTER_SESSION_H

#include <stdbool.h>

#include "types.h"
#include "constants.h"
#include "kalman.h"

//======================================================================
// new_avg = ((last_avg * count) + current_task_time) / (count + 1);
//======================================================================
typedef struct {
    double hbtime;
    double sum_hbtime;
    double count_ack;
    uint64_t last_ack;
    uint64_t last_checkhealthy;
    
    kalman_t health_kalman_filter;
    int kalman_initialized_count;
    float kalman_calibration_samples[KALMAN_CALIBRATION_SAMPLES];
    
    double carry_healthypct;
    double prior_healthypct;
    double healthypct;
    bool isactive;
    bool ishealthy;
    uint8_t first_check_healthy;
    uint64_t last_task_started;
    uint64_t last_task_finished;
    uint64_t longest_task_time;
    long double avg_task_time_per_empty_slot;
} worker_metrics_t;

typedef struct {
    uint16_t task_count;
	worker_metrics_t metrics;
} master_sio_state_t;

typedef struct {
    uint16_t task_count;
	worker_metrics_t metrics;
} master_logic_state_t;

typedef struct {
    uint16_t task_count;
	worker_metrics_t metrics;
} master_dbr_state_t;
//======================================================================
// hanya ada 1 writer
// LMDB tidak bisa multi writer
// Master harus punya write cache dalam bentuk linked list
// dbwriter memberi signal write complete dan akan mentrigger in_use=false dan flush cache 1 per satu sampai kosong
// untuk memastikan penulisan ditangani
//======================================================================
typedef struct {
	bool in_use;
	worker_metrics_t metrics;
} master_dbw_state_t;

typedef struct {
    bool in_use;
    worker_metrics_t metrics;
} master_cow_state_t;

typedef struct {
	int sio_index;
    bool in_use;
    uint8_t ip[IP_ADDRESS_LEN];
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

#endif
