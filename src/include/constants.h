#ifndef CONSTANTS_H
#define CONSTANTS_H

#define GENESIS_PUBLICKEY "099d89e1421eae8108862e139f5ecc941afc530f63e96cb28fbad82f32a6a2b166c9917e770c48b886413c1d3e3641ede160454004ea72437313789575b8e0b243819da5bf5cbf90688a70024b774f98524afee3e835998a29a644a376f622e6a3d888a4e1dd9548cb39a6a9604a010f8e197221d148debb78b6a98b286ae01dbdc09ab69f5c618efa6a686ad9bcf114589a41180ed98610a69da30a7ec5ca075af77d48e093d59ce35ca0df239ad065763c8f4464927f4bdc1e58e345f87af664f8ce1a9c466120ab9c4545604851a5740684abe6fbe5ff5078117ccd41e7a935176426976086498e7cfa734ee9e4314a7da0770a259144113b83da393bdcc6e2a66b296a3c0a36368dd3ae0c6512bf9a30796de5767ed8a1a3fe3622b843f759688cf93faf0b2ca40d355aed37976e14f7341c355390b459f59bac4cbd1fc124ec73207595294ceb4c9c90f05577d77773ceb7163185fbb4eeaaaa0e45d277d5e9796a4917b96ee0b5a759a29abec64a1391f475d1041770115210cc35a19405e9991e7317ef196a1b68a30a17df0c5f5d985079db0a16126946598b5d256cd1c2e0882bbf30c8c50b568d1ed473210960cf8fa64b76b06d85544d4a71128c9573f0837bd3cf9e2bed2382e3501855b992756617ab5ec6d5e5905fb73c115689505e4abdc521e8690cd45b9cc3cb33e5bd89d137618441596caa236b4b5dd5114a1aab5cee2fbade10db8e2b587c041c153541294addb931711e2122ce6c3a9f913778914a07d14b77579910007a5fb18246163a7b19c09feaaef3de0c114a01b67774cb4d7305510bfe1e837b02e07bc42b54a5a544d255cb6c489a6d49cc8ec70a0650a27c54049d592d17a7c7b00452e290b9c16189a1c92559d544789ce39abfa135406ea136215ab07be845c659c3901b62aed19d0a22b66cac8768abf581d85815234d5890a920d76a837f2db80da3672c59b4ea5731b2a2fdb92c10bbdd483b0fcd003927e46e442160face627f992207885ee34311fd91f72ae0e680ac96170c040033b54403aec2320368fd704f845a233468e2d94f4a7ef87d863952184ebda9f38b6a22a895076847954863e10f965b43405b0a8d720e0610b5bd1484c64a02bfd24996ebaba5442e1f59e49388a4445274c9e5166f590ac7481e457c50ae88e3434614f265a9cd2fe8b25e9b0263a49a58fd0fc15709001b7ceb953319ba1e4488b1f01750a172ca740c0176bcd24d2bae22cc7344c7a84adfed"
#define GENESIS_MIN_TSTMP "2025-11-20 00:00:00"

#define MAX_EVENTS 1000
#define MAX_BOOTSTRAP_NODES 313
#define MAX_BOOTSTRAP_FILE_SIZE (100 * 1024)

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

#define MASTER_ARENA_SIZE (5 * 1024 * 1024)
#define WORKER_ARENA_SIZE (10 * 1024 * 1024)

#define NODEKEYS_PATH "./nodekeys"
#define NODEKEYS_MAPSIZE (10ULL * 1024ULL * 1024ULL)
#define NODEKEYS_TABLES 1
#define NODEKEYS_NODEKEYS_NAME "keys"
#define NODEKEYS_VERSION_MAJOR 0x00
#define NODEKEYS_VERSION_MINOR 0x01

#define DATABASE_PATH "./database"
#define DATABASE_MAPSIZE -1
#define DATABASE_TABLES 64
#define DATABASE_ERA_NAME "era"
#define ERA_VERSION_MAJOR 0x00
#define ERA_VERSION_MINOR 0x01

#define AB_COUNT 10
#define DPR_COUNT 10

#define PARALLEL_DATA_WINDOW_SIZE 256

#define ORILINK_DECRYPT_HEADER
//#undef ORILINK_DECRYPT_HEADER
#define ACCRCY_TEST
#undef ACCRCY_TEST
#define LONGINTV_TEST
#undef LONGINTV_TEST

#define MAX_TIMER_SHARD 15
#define WHEEL_SIZE 1024
#define MIN_GAP_US 1000
//----------------------------------------------------------------------
#define KALMAN_CALIBRATION_SAMPLES 50
//----------------------------------------------------------------------
#define MAX_RETRY_CNT 5
#define MIN_RETRY_SEC 1
//----------------------------------------------------------------------
#define NODE_HEARTBEAT_INTERVAL 0.020
#define NODE_CHECK_HEALTHY_X 3
//----------------------------------------------------------------------
#define NODE_CHECK_HEALTHY NODE_CHECK_HEALTHY_X * 2 * NODE_HEARTBEAT_INTERVAL
//----------------------------------------------------------------------
#define WORKER_HEARTBEAT_INTERVAL 5
#define WORKER_CHECK_HEALTHY_X 3
#define WORKER_CHECK_HEALTHY WORKER_CHECK_HEALTHY_X * WORKER_HEARTBEAT_INTERVAL
//----------------------------------------------------------------------
#define JITTER_PERCENTAGE 0.2
#define RAND_MAX_DOUBLE ((double)RAND_MAX)
#define INITIAL_MILISECONDS_PER_UNIT 5
//----------------------------------------------------------------------
// rekeying tiap 24 jam
// berdasarkan hb timer (15 detik) * 5760 = 86400 detik = 24 jam
//----------------------------------------------------------------------
#define REKEYING_HB_TIMES 5760
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
//#define AES_NONCE_BYTES 12
//#define AES_IV_BYTES 16
//#define AES_TAG_BYTES 16
#define AES_NONCE_BYTES 8
#define AES_IV_BYTES 12
#define AES_TAG_BYTES 16

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
#define IPC_MAX_PACKET_SIZE (1024 * 1024)

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
#define ORISORT_THRESHOLD_INSERTION 32
#define ORISORT_THRESHOLD_SHELL 100

#define NODE_VERSION 1
#define NODE_FILE_MAGIC "NODEKEYS"
#define NODE_KEYFILE_PATH "./database/NODE.keys"

#endif
