#ifndef SESSIONS_MASTER_SESSION_H
#define SESSIONS_MASTER_SESSION_H

#include <stdbool.h>
#include "types.h"
#include "constants.h"
#include "kalman.h"

typedef struct {
    double hbtime;
    double sum_hbtime;
    double count_ack;
    uint64_t last_ack;
    uint8_t first_check_healthy;
    kalman_t health_kalman_filter;
    int health_kalman_initialized_count;
    float *health_kalman_calibration_samples; 
    float health_temp_ewma_value;
    bool isactive;
    bool ishealthy;
    uint64_t last_checkhealthy;  
    float healthypct;  
    uint8_t first_check_avgtt;
    kalman_t avgtt_kalman_filter;
    int avgtt_kalman_initialized_count;
    float *avgtt_kalman_calibration_samples;
    float avgtt_temp_ewma_value;    
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
    uint16_t task_count;
    worker_metrics_t metrics;
} master_cow_state_t;

typedef struct {
	int sio_index;
    bool in_use;
    struct sockaddr_in6 addr;
} master_sio_c_session_t;

typedef struct {
	int cow_index;
    bool in_use;
    struct sockaddr_in6 addr;
} master_cow_c_session_t;

typedef struct master_sio_dc_session_t {
    struct sockaddr_in6 addr;
    uint64_t dc_time;
    struct master_sio_dc_session_t *next;
} master_sio_dc_session_t;

typedef struct {
	master_sio_dc_session_t *r_master_sio_dc_session_t;
	status_t status;
} master_sio_dc_session_t_status_t;

status_t add_master_sio_dc_session(const char *label, master_sio_dc_session_t **head, struct sockaddr_in6 *addr);
status_t delete_master_sio_dc_session(const char *label, master_sio_dc_session_t **head, struct sockaddr_in6 *addr);
master_sio_dc_session_t_status_t find_master_sio_dc_session(const char *label, master_sio_dc_session_t *head, struct sockaddr_in6 *addr);
master_sio_dc_session_t_status_t find_first_ratelimited_master_sio_dc_session(const char *label, master_sio_dc_session_t *head, struct sockaddr_in6 *addr);
int_status_t count_master_sio_dc_sessions(const char *label, master_sio_dc_session_t *head);
void display_master_sio_dc_sessions(const char *label, master_sio_dc_session_t *head);
void free_master_sio_dc_sessions(const char *label, master_sio_dc_session_t **head);

#endif
