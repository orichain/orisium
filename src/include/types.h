#ifndef TYPES_H
#define TYPES_H

typedef enum {
    SUCCESS = (uint8_t)0x00,
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

#endif
