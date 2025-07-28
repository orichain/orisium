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
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t rtt_pn_be[8];
    double_to_uint8_be(payload->rtt_pn, rtt_pn_be);
    memcpy(current_buffer + current_offset_local, rtt_pn_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t rtt_mn_be[8];
    double_to_uint8_be(payload->rtt_mn, rtt_mn_be);
    memcpy(current_buffer + current_offset_local, rtt_mn_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t rtt_ee_be[8];
    double_to_uint8_be(payload->rtt_ee, rtt_ee_be);
    memcpy(current_buffer + current_offset_local, rtt_ee_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t rtt_se_be[8];
    double_to_uint8_be(payload->rtt_se, rtt_se_be);
    memcpy(current_buffer + current_offset_local, rtt_se_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->rtt_ii, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->rtt_fc, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->rtt_kic, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t rtt_iv_be[8];
    double_to_uint8_be(payload->rtt_iv, rtt_iv_be);
    memcpy(current_buffer + current_offset_local, rtt_iv_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t rtt_tev_be[8];
    double_to_uint8_be(payload->rtt_tev, rtt_tev_be);
    memcpy(current_buffer + current_offset_local, rtt_tev_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t rtt_vp_be[8];
    double_to_uint8_be(payload->rtt_vp, rtt_vp_be);
    memcpy(current_buffer + current_offset_local, rtt_vp_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t retry_pn_be[8];
    double_to_uint8_be(payload->retry_pn, retry_pn_be);
    memcpy(current_buffer + current_offset_local, retry_pn_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t retry_mn_be[8];
    double_to_uint8_be(payload->retry_mn, retry_mn_be);
    memcpy(current_buffer + current_offset_local, retry_mn_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t retry_ee_be[8];
    double_to_uint8_be(payload->retry_ee, retry_ee_be);
    memcpy(current_buffer + current_offset_local, retry_ee_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t retry_se_be[8];
    double_to_uint8_be(payload->retry_se, retry_se_be);
    memcpy(current_buffer + current_offset_local, retry_se_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->retry_ii, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->retry_fc, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->retry_kic, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t retry_iv_be[8];
    double_to_uint8_be(payload->retry_iv, retry_iv_be);
    memcpy(current_buffer + current_offset_local, retry_iv_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t retry_tev_be[8];
    double_to_uint8_be(payload->retry_tev, retry_tev_be);
    memcpy(current_buffer + current_offset_local, retry_tev_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t retry_vp_be[8];
    double_to_uint8_be(payload->retry_vp, retry_vp_be);
    memcpy(current_buffer + current_offset_local, retry_vp_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->rtt_kcs_len, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->retry_kcs_len, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (payload->rtt_kcs_len > 0) {
        for (uint8_t icl=0;icl<payload->rtt_kcs_len;++icl) {
            if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
            uint8_t rtt_kcs_be[8];
            double_to_uint8_be(payload->rtt_retry_kcs[icl], rtt_kcs_be);
            memcpy(current_buffer + current_offset_local, rtt_kcs_be, DOUBLE_ARRAY_SIZE);
            current_offset_local += DOUBLE_ARRAY_SIZE;
        }
    }
    if (payload->retry_kcs_len > 0) {
        for (uint8_t icl=0;icl<payload->retry_kcs_len;++icl) {
            if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
            uint8_t retry_kcs_be[8];
            double_to_uint8_be(payload->rtt_retry_kcs[payload->rtt_kcs_len+icl], retry_kcs_be);
            memcpy(current_buffer + current_offset_local, retry_kcs_be, DOUBLE_ARRAY_SIZE);
            current_offset_local += DOUBLE_ARRAY_SIZE;
        }
    }
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
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading rtt_pn.", label);
        return FAILURE_OOBUF;
    }
    uint8_t rtt_pn_be[8];
    memcpy(rtt_pn_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->rtt_pn = uint8_be_to_double(rtt_pn_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading rtt_mn.", label);
        return FAILURE_OOBUF;
    }
    uint8_t rtt_mn_be[8];
    memcpy(rtt_mn_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->rtt_mn = uint8_be_to_double(rtt_mn_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading rtt_ee.", label);
        return FAILURE_OOBUF;
    }
    uint8_t rtt_ee_be[8];
    memcpy(rtt_ee_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->rtt_ee = uint8_be_to_double(rtt_ee_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading rtt_se.", label);
        return FAILURE_OOBUF;
    }
    uint8_t rtt_se_be[8];
    memcpy(rtt_se_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->rtt_se = uint8_be_to_double(rtt_se_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading rtt_ii.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->rtt_ii, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading rtt_fc.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->rtt_fc, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading rtt_kic.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->rtt_kic, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading rtt_iv.", label);
        return FAILURE_OOBUF;
    }
    uint8_t rtt_iv_be[8];
    memcpy(rtt_iv_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->rtt_iv = uint8_be_to_double(rtt_iv_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading rtt_tev.", label);
        return FAILURE_OOBUF;
    }
    uint8_t rtt_tev_be[8];
    memcpy(rtt_tev_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->rtt_tev = uint8_be_to_double(rtt_tev_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading rtt_vp.", label);
        return FAILURE_OOBUF;
    }
    uint8_t rtt_vp_be[8];
    memcpy(rtt_vp_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->rtt_vp = uint8_be_to_double(rtt_vp_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading retry_pn.", label);
        return FAILURE_OOBUF;
    }
    uint8_t retry_pn_be[8];
    memcpy(retry_pn_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->retry_pn = uint8_be_to_double(retry_pn_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading retry_mn.", label);
        return FAILURE_OOBUF;
    }
    uint8_t retry_mn_be[8];
    memcpy(retry_mn_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->retry_mn = uint8_be_to_double(retry_mn_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading retry_ee.", label);
        return FAILURE_OOBUF;
    }
    uint8_t retry_ee_be[8];
    memcpy(retry_ee_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->retry_ee = uint8_be_to_double(retry_ee_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading retry_se.", label);
        return FAILURE_OOBUF;
    }
    uint8_t retry_se_be[8];
    memcpy(retry_se_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->retry_se = uint8_be_to_double(retry_se_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading retry_ii.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->retry_ii, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading retry_fc.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->retry_fc, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading retry_kic.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->retry_kic, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading retry_iv.", label);
        return FAILURE_OOBUF;
    }
    uint8_t retry_iv_be[8];
    memcpy(retry_iv_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->retry_iv = uint8_be_to_double(retry_iv_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading retry_tev.", label);
        return FAILURE_OOBUF;
    }
    uint8_t retry_tev_be[8];
    memcpy(retry_tev_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->retry_tev = uint8_be_to_double(retry_tev_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading retry_vp.", label);
        return FAILURE_OOBUF;
    }
    uint8_t retry_vp_be[8];
    memcpy(retry_vp_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->retry_vp = uint8_be_to_double(retry_vp_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading rtt_kcs_len.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->rtt_kcs_len, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading retry_kcs_len.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->retry_kcs_len, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (payload->rtt_kcs_len > 0) {
        for (uint8_t icl=0;icl<payload->rtt_kcs_len;++icl) {
            if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
                LOG_ERROR("%sOut of bounds reading rtt_kcs.", label);
                return FAILURE_OOBUF;
            }
            uint8_t rtt_kcs_be[8];
            memcpy(rtt_kcs_be, cursor, DOUBLE_ARRAY_SIZE);
            payload->rtt_retry_kcs[icl] = uint8_be_to_double(rtt_kcs_be);
            cursor += DOUBLE_ARRAY_SIZE;
            current_offset += DOUBLE_ARRAY_SIZE;
        }
    }
    if (payload->retry_kcs_len > 0) {
        for (uint8_t icl=0;icl<payload->retry_kcs_len;++icl) {
            if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
                LOG_ERROR("%sOut of bounds reading retry_kcs.", label);
                return FAILURE_OOBUF;
            }
            uint8_t retry_kcs_be[8];
            memcpy(retry_kcs_be, cursor, DOUBLE_ARRAY_SIZE);
            payload->rtt_retry_kcs[payload->rtt_kcs_len + icl] = uint8_be_to_double(retry_kcs_be);
            cursor += DOUBLE_ARRAY_SIZE;
            current_offset += DOUBLE_ARRAY_SIZE;
        }
    }
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
    uint32_t remote_ctr,
    double rtt_pn,
    double rtt_mn,
    double rtt_ee,
    double rtt_se,
    uint8_t rtt_ii,    
    uint8_t rtt_fc,
    uint8_t rtt_kic,
    double rtt_iv,
    double rtt_tev,
    double rtt_vp,
    double retry_pn,
    double retry_mn,
    double retry_ee,
    double retry_se,
    uint8_t retry_ii,    
    uint8_t retry_fc,
    uint8_t retry_kic,
    double retry_iv,
    double retry_tev,
    double retry_vp,
    uint8_t rtt_kcs_len,
    uint8_t retry_kcs_len,
    double *rtt_retry_kcs
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
	ipc_master_sio_orilink_identity_t *payload = (ipc_master_sio_orilink_identity_t *)calloc(1, sizeof(ipc_master_sio_orilink_identity_t) + (rtt_kcs_len * sizeof(double)) + (retry_kcs_len * sizeof(double)));
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
    payload->rtt_pn = rtt_pn;
    payload->rtt_mn = rtt_mn;
    payload->rtt_ee = rtt_ee;
    payload->rtt_se = rtt_se;
    payload->rtt_ii = rtt_ii;    
    payload->rtt_fc = rtt_fc;
    payload->rtt_kic = rtt_kic;
    payload->rtt_iv = rtt_iv;
    payload->rtt_tev = rtt_tev;
    payload->rtt_vp = rtt_vp;
    payload->retry_pn = retry_pn;
    payload->retry_mn = retry_mn;
    payload->retry_ee = retry_ee;
    payload->retry_se = retry_se;
    payload->retry_ii = retry_ii;    
    payload->retry_fc = retry_fc;
    payload->retry_kic = retry_kic;
    payload->retry_iv = retry_iv;
    payload->retry_tev = retry_tev;
    payload->retry_vp = retry_vp;
    payload->rtt_kcs_len = rtt_kcs_len;
    payload->retry_kcs_len = retry_kcs_len;
    if (rtt_kcs_len > 0 && rtt_retry_kcs) memcpy(payload->rtt_retry_kcs, rtt_retry_kcs, rtt_kcs_len * sizeof(double));
    if (retry_kcs_len > 0 && rtt_retry_kcs) memcpy(payload->rtt_retry_kcs + (rtt_kcs_len * sizeof(double)), rtt_retry_kcs + (rtt_kcs_len * sizeof(double)), retry_kcs_len * sizeof(double));
	result.r_ipc_protocol_t->payload.ipc_master_sio_orilink_identity = payload;
	result.status = SUCCESS;
	return result;
}
