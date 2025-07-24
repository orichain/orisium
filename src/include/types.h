#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>
#include "constants.h"

typedef enum {
    SUCCESS = (uint8_t)0x00,
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
    FAILURE = (uint8_t)0xff
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
	IMMEDIATELY = (uint8_t)0x00
} shutdown_type_t;

typedef struct {
	int index;
	worker_type_t r_worker_type_t;
	status_t status;
} worker_type_t_status_t;

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
	int r_int;
	status_t status;
} int_status_t;

typedef struct {
	uint64_t r_uint64_t;
	status_t status;
} uint64_t_status_t;

#endif
