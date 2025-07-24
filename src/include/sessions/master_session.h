#ifndef SESSIONS_MASTER_SESSION_H
#define SESSIONS_MASTER_SESSION_H

#include <stdbool.h>
#include <crypto_kem/ml-kem-1024/clean/api.h>
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
} master_sio_session_t;

typedef struct {
    uint16_t task_count;
	worker_metrics_t metrics;
} master_logic_session_t;

typedef struct {
    uint16_t task_count;
	worker_metrics_t metrics;
} master_dbr_session_t;
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
} master_dbw_session_t;

typedef struct {
    uint16_t task_count;
    worker_metrics_t metrics;
} master_cow_session_t;

typedef struct {
	int sio_index;
    bool in_use;
    struct sockaddr_in6 old_client_addr;
    struct sockaddr_in6 client_addr;
    int sock_fd;
//======================================================================
// IDENTITY
//======================================================================    
	uint64_t client_id;
    uint8_t kem_privatekey[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t kem_publickey[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t kem_ciphertext[PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t kem_sharedsecret[32];
    uint64_t server_id;
    uint16_t port;    
//======================================================================
// HELLO SOCK
//======================================================================
    bool hello1_rcvd;
    uint64_t hello1_rcvd_time;
    bool hello1_ack_sent;
    int hello1_ack_sent_try_count;
    uint64_t hello1_ack_sent_time;
    int hello1_ack_timer_fd;
    double interval_hello1_ack_timer_fd;
//======================================================================    
    bool hello2_rcvd;
    uint64_t hello2_rcvd_time;    
    bool hello2_ack_sent;
    int hello2_ack_sent_try_count;
    uint64_t hello2_ack_sent_time;
    int hello2_ack_timer_fd;
    double interval_hello2_ack_timer_fd;
//======================================================================    
    bool hello3_ack_rcvd;
    uint64_t hello3_ack_rcvd_time;
    bool hello3_ack_sent;
    int hello3_ack_sent_try_count;
    uint64_t hello3_ack_sent_time;
    int hello3_ack_timer_fd;
    double interval_hello3_ack_timer_fd;
//======================================================================    
    bool hello_end_rcvd;
    uint64_t hello_end_rcvd_time;
    bool sock_ready_sent;
    int sock_ready_sent_try_count;
    uint64_t sock_ready_sent_time;
//======================================================================
// RTT
//======================================================================    
    uint8_t first_check_rtt;
    kalman_t rtt_kalman_filter;
    int rtt_kalman_initialized_count;
    float *rtt_kalman_calibration_samples; 
    float rtt_temp_ewma_value;
//======================================================================
// RETRY
//======================================================================    
    uint8_t first_check_retry;
    kalman_t retry_kalman_filter;
    int retry_kalman_initialized_count;
    float *retry_kalman_calibration_samples; 
    float retry_temp_ewma_value;
} master_sio_c_session_t;

typedef struct {
	int cow_index;
    bool in_use;
    struct sockaddr_in6 server_addr;
} master_cow_c_session_t;

typedef struct master_sio_dc_session_t {
    struct sockaddr_in6 client_addr;
    uint64_t dc_time;
    struct master_sio_dc_session_t *next;
} master_sio_dc_session_t;

typedef struct {
	master_sio_dc_session_t *r_master_sio_dc_session_t;
	status_t status;
} master_sio_dc_session_t_status_t;

status_t add_master_sio_dc_session(const char *label, master_sio_dc_session_t **head, struct sockaddr_in6 *client_addr);
status_t delete_master_sio_dc_session(const char *label, master_sio_dc_session_t **head, struct sockaddr_in6 *client_addr);
master_sio_dc_session_t_status_t find_master_sio_dc_session(const char *label, master_sio_dc_session_t *head, struct sockaddr_in6 *client_addr);
master_sio_dc_session_t_status_t find_first_ratelimited_master_sio_dc_session(const char *label, master_sio_dc_session_t *head, struct sockaddr_in6 *client_addr);
int_status_t count_master_sio_dc_sessions(const char *label, master_sio_dc_session_t *head);
void display_master_sio_dc_sessions(const char *label, master_sio_dc_session_t *head);
void free_master_sio_dc_sessions(const char *label, master_sio_dc_session_t **head);

#endif
