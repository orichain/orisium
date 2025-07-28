#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <endian.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/master_sio_orilink_identity.h"
#include "constants.h"
#include "pqc.h"

struct sockaddr_in6;

status_t ipc_serialize_master_sio_orilink_identity(const char *label, const ipc_master_sio_orilink_identity_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    /*
    struct sockaddr_in6 server_addr;
    uint64_t server_id;
    uint64_t client_id;
    uint16_t port;
    uint8_t kem_privatekey[KEM_PRIVATEKEY_BYTES];
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
    uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
    uint8_t local_nonce[AES_NONCE_BYTES];
    uint32_t local_ctr;
    uint8_t remote_nonce[AES_NONCE_BYTES];
    uint32_t remote_ctr;
    
    size_t PSIZE = 
        SOCKADDR_IN6_SIZE +
        sizeof(uint64_t) + 
        sizeof(uint64_t) + 
        sizeof(uint16_t) + 
        KEM_PRIVATEKEY_BYTES + 
        KEM_PUBLICKEY_BYTES + 
        KEM_CIPHERTEXT_BYTES + 
        KEM_SHAREDSECRET_BYTES + 
        AES_NONCE_BYTES +
        sizeof(uint32_t) +
        AES_NONCE_BYTES +
        sizeof(uint32_t);    
    */
    if (CHECK_BUFFER_BOUNDS(current_offset_local, SOCKADDR_IN6_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t remote_addr_be[SOCKADDR_IN6_SIZE];
    serialize_sockaddr_in6(&payload->remote_addr, remote_addr_be);    
    memcpy(current_buffer + current_offset_local, remote_addr_be, SOCKADDR_IN6_SIZE);
    current_offset_local += SOCKADDR_IN6_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint64_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint64_t server_id_be = htobe64(payload->server_id);
    memcpy(current_buffer + current_offset_local, &server_id_be, sizeof(uint64_t));
    current_offset_local += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint64_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint64_t client_id_be = htobe64(payload->client_id);
    memcpy(current_buffer + current_offset_local, &client_id_be, sizeof(uint64_t));
    current_offset_local += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint16_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint16_t port_be = htobe16(payload->port);
    memcpy(current_buffer + current_offset_local, &port_be, sizeof(uint16_t));
    current_offset_local += sizeof(uint16_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, KEM_PRIVATEKEY_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->kem_privatekey, KEM_PRIVATEKEY_BYTES);
    current_offset_local += KEM_PRIVATEKEY_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, KEM_PUBLICKEY_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->kem_publickey, KEM_PUBLICKEY_BYTES);
    current_offset_local += KEM_PUBLICKEY_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, KEM_CIPHERTEXT_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->kem_ciphertext, KEM_CIPHERTEXT_BYTES);
    current_offset_local += KEM_CIPHERTEXT_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, KEM_SHAREDSECRET_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->kem_ciphertext, KEM_SHAREDSECRET_BYTES);
    current_offset_local += KEM_SHAREDSECRET_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, AES_NONCE_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->local_nonce, AES_NONCE_BYTES);
    current_offset_local += AES_NONCE_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint32_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint32_t local_ctr_be = htobe32(payload->local_ctr);
    memcpy(current_buffer + current_offset_local, &local_ctr_be, sizeof(uint32_t));
    current_offset_local += sizeof(uint32_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, AES_NONCE_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->remote_nonce, AES_NONCE_BYTES);
    current_offset_local += AES_NONCE_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint32_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint32_t remote_ctr_be = htobe32(payload->remote_ctr);
    memcpy(current_buffer + current_offset_local, &remote_ctr_be, sizeof(uint32_t));
    current_offset_local += sizeof(uint32_t);
    *offset = current_offset_local;
    return SUCCESS;
}

status_t ipc_deserialize_master_sio_orilink_identity(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_master_sio_orilink_identity) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_master_sio_orilink_identity_t *payload = p->payload.ipc_master_sio_orilink_identity;
    if (current_offset + SOCKADDR_IN6_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_addr.", label);
        return FAILURE_OOBUF;
    }
    uint8_t remote_addr_be[SOCKADDR_IN6_SIZE];
    memcpy(remote_addr_be, cursor, SOCKADDR_IN6_SIZE);
    deserialize_sockaddr_in6(remote_addr_be, &payload->remote_addr);
    cursor += SOCKADDR_IN6_SIZE;
    current_offset += SOCKADDR_IN6_SIZE;
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading server_id.", label);
        return FAILURE_OOBUF;
    }
    uint64_t server_id_be;
    memcpy(&server_id_be, cursor, sizeof(uint64_t));
    payload->server_id = be64toh(server_id_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading client_id.", label);
        return FAILURE_OOBUF;
    }
    uint64_t client_id_be;
    memcpy(&client_id_be, cursor, sizeof(uint64_t));
    payload->client_id = be64toh(client_id_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
    if (current_offset + sizeof(uint16_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading port.", label);
        return FAILURE_OOBUF;
    }
    uint16_t port_be;
    memcpy(&port_be, cursor, sizeof(uint16_t));
    payload->port = be16toh(port_be);
    cursor += sizeof(uint16_t);
    current_offset += sizeof(uint16_t);
    if (current_offset + KEM_PRIVATEKEY_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading KEM_PRIVATEKEY_BYTES.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->kem_privatekey, cursor, KEM_PRIVATEKEY_BYTES);
    cursor += KEM_PRIVATEKEY_BYTES;
    current_offset += KEM_PRIVATEKEY_BYTES;
    if (current_offset + KEM_PUBLICKEY_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading KEM_PUBLICKEY_BYTES.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->kem_publickey, cursor, KEM_PUBLICKEY_BYTES);
    cursor += KEM_PUBLICKEY_BYTES;
    current_offset += KEM_PUBLICKEY_BYTES;
    if (current_offset + KEM_CIPHERTEXT_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading KEM_CIPHERTEXT_BYTES.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->kem_ciphertext, cursor, KEM_CIPHERTEXT_BYTES);
    cursor += KEM_CIPHERTEXT_BYTES;
    current_offset += KEM_CIPHERTEXT_BYTES;
    if (current_offset + KEM_SHAREDSECRET_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading KEM_SHAREDSECRET_BYTES.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->kem_sharedsecret, cursor, KEM_SHAREDSECRET_BYTES);
    cursor += KEM_SHAREDSECRET_BYTES;
    current_offset += KEM_SHAREDSECRET_BYTES;
    
    if (current_offset + AES_NONCE_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading local_nonce.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->local_nonce, cursor, AES_NONCE_BYTES);
    cursor += AES_NONCE_BYTES;
    current_offset += AES_NONCE_BYTES;
    if (current_offset + sizeof(uint32_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading local_ctr.", label);
        return FAILURE_OOBUF;
    }
    uint32_t local_ctr_be;
    memcpy(&local_ctr_be, cursor, sizeof(uint32_t));
    payload->local_ctr = be32toh(local_ctr_be);
    cursor += sizeof(uint32_t);
    current_offset += sizeof(uint32_t);
    if (current_offset + AES_NONCE_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_nonce.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->remote_nonce, cursor, AES_NONCE_BYTES);
    cursor += AES_NONCE_BYTES;
    current_offset += AES_NONCE_BYTES;
    if (current_offset + sizeof(uint32_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_ctr.", label);
        return FAILURE_OOBUF;
    }
    uint32_t remote_ctr_be;
    memcpy(&remote_ctr_be, cursor, sizeof(uint32_t));
    payload->remote_ctr = be32toh(remote_ctr_be);
    cursor += sizeof(uint32_t);
    current_offset += sizeof(uint32_t);
    *offset_ptr = current_offset;
    return SUCCESS;
}

ipc_protocol_t_status_t ipc_prepare_cmd_master_sio_orilink_identity(
    const char *label,
    struct sockaddr_in6 *remote_addr,
    uint64_t server_id,
    uint64_t client_id,
    uint16_t port,
    uint8_t *kem_privatekey,
    uint8_t *kem_publickey,
    uint8_t *kem_ciphertext,
    uint8_t *kem_sharedsecret,
    uint8_t *local_nonce,
    uint32_t local_ctr,
    uint8_t *remote_nonce,
    uint32_t remote_ctr
)
{
	ipc_protocol_t_status_t result;
	result.r_ipc_protocol_t = (ipc_protocol_t *)malloc(sizeof(ipc_protocol_t));
	result.status = FAILURE;
	if (!result.r_ipc_protocol_t) {
		LOG_ERROR("%sFailed to allocate ipc_protocol_t. %s", label, strerror(errno));
		return result;
	}
	memset(result.r_ipc_protocol_t, 0, sizeof(ipc_protocol_t));
	result.r_ipc_protocol_t->version[0] = IPC_VERSION_MAJOR;
	result.r_ipc_protocol_t->version[1] = IPC_VERSION_MINOR;
	result.r_ipc_protocol_t->type = IPC_MASTER_SIO_ORILINK_IDENTITY;
	ipc_master_sio_orilink_identity_t *payload = (ipc_master_sio_orilink_identity_t *)calloc(1, sizeof(ipc_master_sio_orilink_identity_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_master_sio_orilink_identity_t payload. %s", label, strerror(errno));
		CLOSE_IPC_PROTOCOL(&result.r_ipc_protocol_t);
		return result;
	}
    memcpy(&payload->remote_addr, remote_addr, SOCKADDR_IN6_SIZE);
    payload->server_id = server_id;
    payload->client_id = client_id;
    payload->port = port;
    memcpy(&payload->kem_privatekey, kem_privatekey, KEM_PRIVATEKEY_BYTES);
    memcpy(&payload->kem_publickey, kem_publickey, KEM_PUBLICKEY_BYTES);
    memcpy(&payload->kem_ciphertext, kem_ciphertext, KEM_CIPHERTEXT_BYTES);
    memcpy(&payload->kem_sharedsecret, kem_sharedsecret, KEM_SHAREDSECRET_BYTES);
    memcpy(&payload->local_nonce, local_nonce, AES_NONCE_BYTES);
    payload->local_ctr = local_ctr;
    memcpy(&payload->remote_nonce, remote_nonce, AES_NONCE_BYTES);
    payload->remote_ctr = remote_ctr;
	result.r_ipc_protocol_t->payload.ipc_master_sio_orilink_identity = payload;
	result.status = SUCCESS;
	return result;
}
