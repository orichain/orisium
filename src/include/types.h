#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>
#include "constants.h"

typedef enum {
    SUCCESS = (uint8_t)0x00,
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
    PT_SYN = (uint8_t)0x00,
    PT_SYN_ACK = (uint8_t)0x01,
    PT_ACK = (uint8_t)0x02,
    PT_DATA = (uint8_t)0x03,
    PT_FIN = (uint8_t)0x04,
    PT_KEEPALIVE = (uint8_t)0x05
} udp_packet_type_t;

typedef enum {
	IMMEDIATELY = (uint8_t)0xfe
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

typedef struct {
    uint32_t connection_id;
    uint32_t sequence_number;
    uint8_t packet_type;
    uint16_t payload_length;
    uint32_t checksum;
    uint16_t stream_id;
    uint32_t stream_sequence_number;
} udp_packet_header_t;

typedef struct {
    udp_packet_header_t header;
    uint8_t payload[];
} udp_packet_t;

typedef struct {
    udp_packet_header_t header;
    uint32_t total_packets;
} udp_syn_packet_t;

typedef struct {
    uint32_t start_seq;
    uint32_t end_seq;
} udp_sack_block_t;

typedef struct {
    udp_packet_header_t header;
    uint32_t last_acked_seq;
    uint16_t sack_block_count;
    uint32_t available_receive_window;
    udp_sack_block_t sack_blocks[];
} udp_sack_packet_t;

typedef struct {
    uint32_t global_sequence_number;
    uint16_t stream_id;
    uint32_t stream_sequence_number;
    uint8_t data[MAX_BUFFER_SIZE];
    size_t data_len;
} udp_received_packet_t;

typedef struct {
    uint32_t connection_id;
    struct sockaddr_in6 client_addr;
    socklen_t client_addr_len;
    uint32_t next_expected_seq;
    udp_received_packet_t **recv_buffer;
    int buffer_count;
    int max_recv_buffer_size;
    uint32_t total_packets;
    uint32_t available_receive_window;
    uint64_t last_active_time;
    int is_handshake_complete;
    int is_fin_received;
} udp_session_t;

typedef struct {
    uint32_t global_sequence_number;
    uint16_t stream_id;
    uint32_t stream_sequence_number;
    udp_packet_t *packet;
    uint64_t last_sent_time;
    int retransmissions;
    int is_acked;
    uint64_t sent_time;
} udp_sent_packet_t;

#endif
