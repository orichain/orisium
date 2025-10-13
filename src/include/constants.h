#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stdint.h>

#define MAX_EVENTS 1000
#define MAX_BOOTSTRAP_NODES 313
#define MAX_BOOTSTRAP_FILE_SIZE 1024

#define MAX_SIO_WORKERS 2
#define MAX_LOGIC_WORKERS 6
#define MAX_COW_WORKERS 6
#define MAX_DBR_WORKERS 6
#define MAX_DBW_WORKERS 1
#define MAX_CONNECTION_PER_SIO_WORKER 25
#define MAX_CONNECTION_PER_COW_WORKER 55
#define MAX_MASTER_SIO_SESSIONS (MAX_SIO_WORKERS * MAX_CONNECTION_PER_SIO_WORKER)
#define MAX_MASTER_COW_SESSIONS (MAX_COW_WORKERS * MAX_CONNECTION_PER_COW_WORKER)
#define MAX_DOWNSTREAM_NODES_LIMIT 25

//----------------------------------------------------------------------
#define KALMAN_CALIBRATION_SAMPLES 50
//----------------------------------------------------------------------
/**
* @def RETRY_TIMER_CREATE_DELAY_NS
* @brief Forced I/O delay interval for the creator timer during Heartbeat failure.
*
* This value serves as a critical I/O safety margin against kernel race conditions.
* The observed worst-case RTT to the remote peer (VPS) is ~300ms. After factoring 
* in kernel processing time for I/O cleanup (file descriptor closing, event loop flush), 
* the total critical time is approx. 350ms.
*
* We use 600ms (0.6 seconds) to provide a generous 250ms margin, ensuring the kernel 
* fully completes all asynchronous operations related to the previous Heartbeat 
* attempt before scheduling the next retry. This prevents 'Heartbeat Received Already' 
* errors caused by I/O timing ambiguities.
*/
#define POLLING_1MS_MAX_CNT 600
//----------------------------------------------------------------------
#define NODE_HEARTBEAT_INTERVAL 10
#define NODE_CHECK_HEALTHY_X 3
//----------------------------------------------------------------------
#define NODE_CHECK_HEALTHY NODE_CHECK_HEALTHY_X * 2 * NODE_HEARTBEAT_INTERVAL
//----------------------------------------------------------------------
#define WORKER_HEARTBEAT_INTERVAL 3
#define WORKER_CHECK_HEALTHY_X 3
#define WORKER_CHECK_HEALTHY WORKER_CHECK_HEALTHY_X * WORKER_HEARTBEAT_INTERVAL
//----------------------------------------------------------------------
#define HEARTBEAT_JITTER_PERCENTAGE 0.2
#define RAND_MAX_DOUBLE ((double)RAND_MAX)
#define INITIAL_MILISECONDS_PER_UNIT 5
//----------------------------------------------------------------------
// rekeying tiap 24 jam
// berdasarkan hb timer (9 detik) * 9600 = 86400 detik = 24 jam
//----------------------------------------------------------------------
#define REKEYING_HB_TIMES 9600
//----------------------------------------------------------------------
#define WORKER_RECREATE_SEC 1

#define IPV6_ADDRESS_LEN 16
#define IPV4_ADDRESS_LEN 4
#define SOCKADDR_IN6_SIZE (2 + 2 + 4 + 16 + 4)
#define DOUBLE_ARRAY_SIZE 8

#define IPC_LENGTH_PREFIX_BYTES sizeof(uint32_t)

#define IPC_VERSION_BYTES 2
#define IPC_VERSION_MAJOR 0x00
#define IPC_VERSION_MINOR 0x01

#define KALMAN_ALPHA_EWMA 0.2
#define HEALTHY_THRESHOLD 75

#define HASHES_BYTES 32
#define AES_NONCE_BYTES 12
#define AES_IV_BYTES 16
#define AES_TAG_BYTES 16

#define MAX_RETRY 5
#define MAX_RTT_SEC 1
//======================================================================
// OriLink
//======================================================================
#define ORILINK_VERSION_BYTES 2
#define ORILINK_VERSION_MAJOR 0x00
#define ORILINK_VERSION_MINOR 0x01
//======================================================================
// 1200 Paling aman dari fragmentasi
//======================================================================
#define ORILINK_MAX_PACKET_SIZE 1200

#define MAX_SESSIONS 10
#define MAX_EPOLL_EVENTS 10
#define PACKET_TIMEOUT_SEC 2
#define CUBIC_BETA 0.7
#define CUBIC_C 0.4
#define NUM_STREAMS 2

#define MAX_PAYLOAD_SIZE 1384
#define KEEPALIVE_INTERVAL_SEC 15

#define RTT_ALPHA 0.125
#define RTT_BETA  0.25
#define RTO_MIN   0.2
#define RTO_MAX   60.0
//======================================================================

#define NODE_VERSION 1
#define NODE_FILE_MAGIC "NODEKEYS"
#define NODE_KEYFILE_PATH "./database/NODE.keys"

#endif
