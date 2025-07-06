#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

typedef enum {
    SUCCESS = (uint8_t)0x00,
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
