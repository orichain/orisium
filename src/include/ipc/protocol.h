#ifndef IPC_PROTOCOL_H
#define IPC_PROTOCOL_H

#include <arpa/inet.h>
#include "types.h"

#define VERSION_BYTES 2
#define VERSION_MAJOR 0x00
#define VERSION_MINOR 0x01

typedef enum {
    IPC_CLIENT_REQUEST_TASK = (uint8_t)0x01,        // From SIO Worker to Master (new client request)
    IPC_LOGIC_TASK = (uint8_t)0x02,                 // From Master to Logic Worker (forward client request)
    IPC_LOGIC_RESPONSE_TO_SIO = (uint8_t)0x03,      // From Logic Worker to Master (response for original client)
    IPC_OUTBOUND_TASK = (uint8_t)0x04,              // From Logic Worker to Master (request to contact another node)
    IPC_OUTBOUND_RESPONSE = (uint8_t)0x05,          // From Client Outbound Worker to Master (response from another node)
    IPC_MASTER_ACK = (uint8_t)0x06,                 // Generic ACK from Master
    IPC_WORKER_ACK = (uint8_t)0x07,                 // Generic ACK from Worker
    IPC_CLIENT_DISCONNECTED = (uint8_t)0x08         // From SIO Worker to Master (client disconnected)
} ipc_protocol_type_t;

typedef struct {
    uint64_t correlation_id;
    uint8_t ip[INET6_ADDRSTRLEN];
    uint16_t len;
    uint8_t data[];
} ipc_client_request_task_t;

typedef struct {
    uint64_t correlation_id;
    uint8_t ip[INET6_ADDRSTRLEN];
} ipc_client_disconnect_info_t;

typedef struct {
    uint64_t correlation_id;
    uint16_t len;
    uint8_t data[];
} ipc_logic_response_t;

typedef struct {
    uint64_t correlation_id;
    uint8_t ip[INET6_ADDRSTRLEN];
    uint16_t port;
    uint16_t len;
    uint8_t data[];
} ipc_outbound_task_t;

typedef struct {
    uint64_t correlation_id;
    uint8_t success;
    uint16_t len;
    uint8_t data[];
} ipc_outbound_response_t;

typedef struct {
	uint8_t version[VERSION_BYTES];
	ipc_protocol_type_t type;
	union {
		ipc_client_request_task_t *ipc_client_request_task;
		ipc_client_disconnect_info_t *ipc_client_disconnect_info;
		ipc_logic_response_t *ipc_logic_response;
		ipc_outbound_task_t *ipc_outbound_task;
		ipc_outbound_response_t *ipc_outbound_response;
	} payload;
} ipc_protocol_t;

#define CLOSE_IPC_PAYLOAD(x) do { if ((x)) { free(x); (x) = NULL; } } while(0)    

#define CLOSE_IPC_PROTOCOL(x) \
    do { \
        if (x) { \
			if (x->type == IPC_CLIENT_REQUEST_TASK) { \
                CLOSE_IPC_PAYLOAD(x->payload.ipc_client_request_task); \
            } else if (x->type == IPC_CLIENT_DISCONNECTED) { \
                CLOSE_IPC_PAYLOAD(x->payload.ipc_client_disconnect_info); \
            } else if (x->type == IPC_LOGIC_RESPONSE_TO_SIO) { \
                CLOSE_IPC_PAYLOAD(x->payload.ipc_logic_response); \
            } \
            free(x); \
            x = NULL; \
        } \
    } while(0)

typedef struct {
	ipc_protocol_t *r_ipc_protocol_t;
	status_t status;
} ipc_protocol_t_status_t;

#include "client_request_task.h"
#include "client_disconnect_info.h"
#include "logic_response.h"

size_t_status_t calculate_ipc_payload_size(ipc_protocol_type_t type);
size_t_status_t calculate_ipc_payload_buffer(const uint8_t* buffer, size_t len);
ssize_t_status_t ipc_serialize(const ipc_protocol_t* p, uint8_t** ptr_buffer, size_t* buffer_size);
ipc_protocol_t_status_t ipc_deserialize(const uint8_t* buffer, size_t len);
ssize_t_status_t send_ipc_protocol_message(int *uds_fd, const ipc_protocol_t* p, int *fd_to_pass);
ipc_protocol_t_status_t receive_and_deserialize_ipc_message(int *uds_fd, int *actual_fd_received);

#endif
