#ifndef SESSIONS_MASTER_SESSION_H
#define SESSIONS_MASTER_SESSION_H

#include <stdbool.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>

#include "types.h"
#include "constants.h"
#include "kalman.h"
#include "pqc.h"
#include "orilink/protocol.h"
#include "async.h"

typedef struct {
    double hbtime;
    double sum_hbtime;
    double count_ack;
    uint64_t last_ack;
    uint64_t last_checkhealthy;
    uint64_t last_task_started;
    uint64_t last_task_finished;
    uint64_t longest_task_time;
} worker_metrics_t;

typedef int uds_pair[2];

typedef struct {
	uds_pair uds;
	pid_t pid;
} uds_pair_pid_t;

typedef struct {
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
    uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
    uint8_t local_nonce[AES_NONCE_BYTES];
    uint32_t local_ctr;
    uint8_t remote_nonce[AES_NONCE_BYTES];
    uint32_t remote_ctr;
} worker_security_t;

typedef struct {
    bool isactive;
    bool ishealthy;
    bool isready;
    uint16_t task_count;
    uds_pair_pid_t upp;
	worker_metrics_t metrics;
    oricle_double_t healthy;
    oricle_long_double_t avgtt;
    worker_security_t security;
} master_sio_session_t;

typedef struct {
    bool isactive;
    bool ishealthy;
    bool isready;
    uint16_t task_count;
    uds_pair_pid_t upp;
	worker_metrics_t metrics;
    oricle_double_t healthy;
    oricle_long_double_t avgtt;
    worker_security_t security;
} master_logic_session_t;

typedef struct {
    bool isactive;
    bool ishealthy;
    bool isready;
    uint16_t task_count;
    uds_pair_pid_t upp;
	worker_metrics_t metrics;
    oricle_double_t healthy;
    oricle_long_double_t avgtt;
    worker_security_t security;
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
    bool isactive;
    bool ishealthy;
    bool isready;
    uds_pair_pid_t upp;
	worker_metrics_t metrics;
    oricle_double_t healthy;
    oricle_long_double_t avgtt;
    worker_security_t security;
} master_dbw_session_t;

typedef struct {
    bool isactive;
    bool ishealthy;
    bool isready;
    uint16_t task_count;
    uds_pair_pid_t upp;
    worker_metrics_t metrics;
    oricle_double_t healthy;
    oricle_long_double_t avgtt;
    worker_security_t security;
} master_cow_session_t;

typedef struct {
    bool rcvd;
    uint64_t rcvd_time;
    bool ack_sent;
    int ack_sent_try_count;
    uint64_t ack_sent_time;
    int ack_timer_fd;
    double interval_ack_timer_fd;
} hello_ack_t;

typedef struct {
	int sio_index;
    bool in_use;
    int sock_fd;
//======================================================================
// IDENTITY
//======================================================================    
	orilink_identity_t identity;
    uint8_t client_kem_publickey[KEM_PUBLICKEY_BYTES];
    uint8_t encrypted_server_id_port[AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t) + AES_TAG_BYTES];
    uint8_t temp_kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
//======================================================================
// HELLO SOCK
//======================================================================
    hello_ack_t hello1_ack;
    hello_ack_t hello2_ack;
    hello_ack_t hello3_ack;
    hello_ack_t sock_ready;
} master_sio_c_session_t;

typedef struct {
	int cow_index;
    bool in_use;
    struct sockaddr_in6 server_addr;
} master_cow_c_session_t;

void cleanup_hello_ack(const char *label, async_type_t *async, hello_ack_t *h);
void setup_hello_ack(hello_ack_t *h);

#endif
