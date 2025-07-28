#include <common/aes.h>
#include <endian.h>
#include <stdint.h>
#include <string.h>

#include "log.h"
#include "types.h"
#include "orilink/protocol.h"
#include "orilink/hello1_ack.h"
#include "orilink/hello2_ack.h"
#include "orilink/hello3_ack.h"
#include "sessions/master_session.h"
#include "poly1305-donna.h"
#include "constants.h"

status_t hello1_ack(const char *label, int *listen_sock, master_sio_c_session_t *session) {
	orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello1_ack(label, session->identity.client_id, session->hello1_ack.ack_sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, 
        session->identity.kem_sharedsecret, session->identity.local_nonce, session->identity.local_ctr,
        listen_sock, (const struct sockaddr *)&session->identity.remote_addr, cmd_result.r_orilink_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent hello1_ack to Client.", label);
        CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent hello1_ack to Client.", label);
    }
    CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
    return SUCCESS;
}

status_t hello2_ack(const char *label, int *listen_sock, master_sio_c_session_t *session) {
	orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello2_ack(label, session->identity.client_id, session->identity.kem_ciphertext, session->hello2_ack.ack_sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, 
        session->identity.kem_sharedsecret, session->identity.local_nonce, session->identity.local_ctr,
        listen_sock, (const struct sockaddr *)&session->identity.remote_addr, cmd_result.r_orilink_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent hello2_ack to Client.", label);
        CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent hello2_ack to Client.", label);
    }
    CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
    return SUCCESS;
}

status_t hello3_ack(const char *label, int *listen_sock, master_sio_c_session_t *session) {
//======================================================================    
    uint8_t server_id_port[sizeof(uint64_t) + sizeof(uint16_t)];
    uint8_t encrypted_server_id_port[sizeof(uint64_t) + sizeof(uint16_t)];   
    uint8_t encrypted_server_id_port1[AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t)];
    uint8_t encrypted_server_id_port2[AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t) + AES_TAG_BYTES];
    memcpy(encrypted_server_id_port1, session->identity.local_nonce, AES_NONCE_BYTES);
    uint64_t server_id_be = htobe64(session->identity.server_id);
    memcpy(server_id_port, &server_id_be, sizeof(uint64_t));
    uint16_t port_be = htobe16(session->identity.port);
    memcpy(server_id_port + sizeof(uint64_t), &port_be, sizeof(uint16_t));
//======================================================================    
    aes256ctx ctx;
    aes256_ctr_keyexp(&ctx, session->temp_kem_sharedsecret);
//=========================================IV===========================    
    uint8_t keystream_buffer[sizeof(uint64_t) + sizeof(uint16_t)];
    uint8_t iv[AES_IV_BYTES];
    memcpy(iv, session->identity.local_nonce, AES_NONCE_BYTES);
    uint32_t local_ctr_be = htobe32(session->identity.local_ctr);
    memcpy(iv + AES_NONCE_BYTES, &local_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr(keystream_buffer, sizeof(uint64_t) + sizeof(uint16_t), iv, &ctx);
    for (size_t i = 0; i < sizeof(uint64_t) + sizeof(uint16_t); i++) {
        encrypted_server_id_port[i] = server_id_port[i] ^ keystream_buffer[i];
    }
    aes256_ctx_release(&ctx);
//======================================================================    
    memcpy(encrypted_server_id_port1 + AES_NONCE_BYTES, encrypted_server_id_port, sizeof(uint64_t) + sizeof(uint16_t));
//======================================================================    
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context ctxx;
	poly1305_init(&ctxx, session->temp_kem_sharedsecret);
	poly1305_update(&ctxx, encrypted_server_id_port1, AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t));
	poly1305_finish(&ctxx, mac);
//====================================================================== 
    memcpy(encrypted_server_id_port2, encrypted_server_id_port1, AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t));
    memcpy(encrypted_server_id_port2 + AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t), mac, AES_TAG_BYTES);
//======================================================================
// Prinsip Local Crt dan Remote Crt
// Tambah Local Counter Jika Berhasil Encrypt    
// Tambah Remote Counter Jika Mac Cocok dan Berhasil Decrypt
//======================================================================
    session->identity.local_ctr++;
//======================================================================    
    orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello3_ack(label, session->identity.client_id, session->identity.kem_ciphertext, encrypted_server_id_port2, session->hello3_ack.ack_sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, 
        session->identity.kem_sharedsecret, session->identity.local_nonce, session->identity.local_ctr,
        listen_sock, (const struct sockaddr *)&session->identity.remote_addr, cmd_result.r_orilink_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent hello3_ack to Client.", label);
        CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent hello3_ack to Client.", label);
    }
    CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
    return SUCCESS;
}
