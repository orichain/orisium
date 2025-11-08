#ifndef TYPES_H
#define TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
//----------------------------------------------------------------------
    SUCCESS = (uint8_t)0x00,
//----------------------------------------------------------------------
    SUCCESS_WRKSRDY = (uint8_t)0x01,
//----------------------------------------------------------------------
    FAILURE_NOTFOUND = (uint8_t)0xe5,
    FAILURE_IVLDTRY = (uint8_t)0xe6,
    FAILURE_MAXTRY = (uint8_t)0xe7,
//----------------------------------------------------------------------
    FAILURE_EBADF = (uint8_t)0xe8,
    FAILURE_CTRMSMTCH = (uint8_t)0xe9,
    FAILURE_MACMSMTCH = (uint8_t)0xea,
    FAILURE_DIFCLID = (uint8_t)0xeb,
    FAILURE_IVLDHDLD = (uint8_t)0xec,
    FAILURE_CHKSUM = (uint8_t)0xed,
    FAILURE_OPYLD = (uint8_t)0xee,
    FAILURE_IVLDMODE = (uint8_t)0xef,
    FAILURE_DPLCT = (uint8_t)0xf0,
    FAILURE_OPNFL = (uint8_t)0xf1,
    FAILURE_NDFLMGC = (uint8_t)0xf2,
    FAILURE_RATELIMIT = (uint8_t)0xf3,
    FAILURE_IVLDPORT = (uint8_t)0xf3,
    FAILURE_IVLDIP = (uint8_t)0xf4,
    FAILURE_NOSLOT = (uint8_t)0xf5,
    FAILURE_MAXREACHD = (uint8_t)0xf6,
    FAILURE_ALRDYCONTD = (uint8_t)0xf7,
    FAILURE_EAGNEWBLK = (uint8_t)0xf8,
    FAILURE_EINTR = (uint8_t)0xf9,
    FAILURE_BAD_PROTOCOL = (uint8_t)0xfa,
    FAILURE_NOMEM = (uint8_t)0xfb,
    FAILURE_IPYLD = (uint8_t)0xfc,
    FAILURE_OOBUF = (uint8_t)0xfd,
    FAILURE_OOIDX = (uint8_t)0xfe,
//----------------------------------------------------------------------
    FAILURE = (uint8_t)0xff
//----------------------------------------------------------------------
} status_t;

typedef enum {
	UNKNOWN = (uint8_t)0x00,
    SIO = (uint8_t)0x01,
    LOGIC = (uint8_t)0x02,
    COW = (uint8_t)0x03,
    DBR = (uint8_t)0x04,
    DBW = (uint8_t)0x05
} worker_type_t;

typedef enum {
	IT_READY = (uint8_t)0x00,
    IT_SHUTDOWN = (uint8_t)0x01,
    IT_REKEYING = (uint8_t)0x02,
    
    IT_WAKEUP = (uint8_t)0xff
} info_type_t;

typedef enum {
    CDT_NOACTION = (uint8_t)0x00,
    CDT_RESET = (uint8_t)0x01,
    CDT_FREE = (uint8_t)0x02
} clean_data_type_t;

typedef enum {
    TIT_SECURE = (uint8_t)0x00,
	TIT_TIMEOUT = (uint8_t)0xff
} task_info_type_t;

typedef enum {
	CONNECTED = (uint8_t)0x00,
    CANNOTCONNECT = (uint8_t)0x01,
    DISCONNECTED = (uint8_t)0x02
} connection_type_t;

typedef enum {
	MLKEM1024 = (uint8_t)0x00,
	FALCONPADDED512 = (uint8_t)0x01,
	MLDSA87 = (uint8_t)0x02,
} pqc_algo_type_t;

typedef struct {
	size_t r_size_t;
	status_t status;
} size_t_status_t;

typedef struct {
	ssize_t r_ssize_t;
	status_t status;
} ssize_t_status_t;

typedef struct {
	uint32_t r_uint32_t;
	status_t status;
} uint32_t_status_t;

typedef struct {
	uint8_t *r_puint8_t;
    size_t r_size_t;
	status_t status;
} puint8_t_size_t_status_t;

typedef struct {
	int r_int;
	status_t status;
} int_status_t;

typedef struct {
	uint64_t r_uint64_t;
	status_t status;
} uint64_t_status_t;

typedef struct {
    uint64_t value;
    int index;
} uint64_t_value_index_t;

#endif
