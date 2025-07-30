#include <endian.h>
#include <stdint.h>
#include <string.h>

#include "log.h"
#include "types.h"
#include "orilink/protocol.h"
#include "orilink/hello1.h"
#include "orilink/hello2.h"
#include "orilink/hello3.h"
#include "orilink/hello_end.h"
#include "sessions/workers_session.h"
#include "poly1305-donna.h"
#include "utilities.h"
#include "aes.h"
#include "constants.h"

status_t hello1(const char *label, cow_c_session_t *session) {
	orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello1(label, session->identity.client_id, session->identity.kem_publickey, session->hello1.sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, 
        session->identity.kem_sharedsecret, session->identity.local_nonce, session->identity.local_ctr,
        &session->sock_fd, (const struct sockaddr *)&session->identity.remote_addr, cmd_result.r_orilink_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent hello1 to Server.", label);
        CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent hello1 to Server.", label);
    }
    CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
    return SUCCESS;
}

status_t hello2(const char *label, cow_c_session_t *session) {
	orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello2(label, session->identity.client_id, session->identity.kem_publickey, session->hello2.sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, 
        session->identity.kem_sharedsecret, session->identity.local_nonce, session->identity.local_ctr,
        &session->sock_fd, (const struct sockaddr *)&session->identity.remote_addr, cmd_result.r_orilink_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent hello2 to Server.", label);
        CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent hello2 to Server.", label);
    }
    CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
    return SUCCESS;
}

status_t hello3(const char *label, cow_c_session_t *session) {
	orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello3(label, session->identity.client_id, session->hello3.sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, 
        session->identity.kem_sharedsecret, session->identity.local_nonce, session->identity.local_ctr,
        &session->sock_fd, (const struct sockaddr *)&session->identity.remote_addr, cmd_result.r_orilink_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent hello3 to Server.", label);
        CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent hello3 to Server.", label);
    }
    CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
    return SUCCESS;
}

status_t hello_end(const char *label, cow_c_session_t *session) {
//====================================================================== 
    status_t stat_genid = generate_connection_id(label, &session->new_client_id);
    if (stat_genid != SUCCESS) {
        LOG_ERROR("%sFailed to generate_connection_id.", label);
        return stat_genid;
    }
    uint8_t server_id_new_client_id[sizeof(uint64_t) + sizeof(uint64_t)];
    uint8_t encrypted_server_id_new_client_id[sizeof(uint64_t) + sizeof(uint64_t)];   
    uint8_t encrypted_server_id_new_client_id1[AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint64_t)];
    uint8_t encrypted_server_id_new_client_id2[AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint64_t) + AES_TAG_BYTES];
    memcpy(encrypted_server_id_new_client_id1, session->identity.local_nonce, AES_NONCE_BYTES);
    uint64_t server_id_be = htobe64(session->identity.server_id);
    memcpy(server_id_new_client_id, &server_id_be, sizeof(uint64_t));
    uint64_t new_client_id_be = htobe64(session->new_client_id);
    memcpy(server_id_new_client_id + sizeof(uint64_t), &new_client_id_be, sizeof(uint64_t));
//======================================================================    
    aes256ctx aes_ctx;
    aes256_ctr_keyexp(&aes_ctx, session->identity.kem_sharedsecret);
//=========================================IV===========================    
    uint8_t keystream_buffer[sizeof(uint64_t) + sizeof(uint64_t)];
    uint8_t iv[AES_IV_BYTES];
    memcpy(iv, session->identity.local_nonce, AES_NONCE_BYTES);
    uint32_t local_ctr_be = htobe32(session->identity.local_ctr);
    memcpy(iv + AES_NONCE_BYTES, &local_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr(keystream_buffer, sizeof(uint64_t) + sizeof(uint64_t), iv, &aes_ctx);
    for (size_t i = 0; i < sizeof(uint64_t) + sizeof(uint64_t); i++) {
        encrypted_server_id_new_client_id[i] = server_id_new_client_id[i] ^ keystream_buffer[i];
    }
    aes256_ctx_release(&aes_ctx);
//======================================================================    
    memcpy(encrypted_server_id_new_client_id1 + AES_NONCE_BYTES, encrypted_server_id_new_client_id, sizeof(uint64_t) + sizeof(uint64_t));
//======================================================================    
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context mac_ctx;
	poly1305_init(&mac_ctx, session->identity.kem_sharedsecret);
	poly1305_update(&mac_ctx, encrypted_server_id_new_client_id1, AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint64_t));
	poly1305_finish(&mac_ctx, mac);
//====================================================================== 
    memcpy(encrypted_server_id_new_client_id2, encrypted_server_id_new_client_id1, AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint64_t));
    memcpy(encrypted_server_id_new_client_id2 + AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint64_t), mac, AES_TAG_BYTES);
//======================================================================
// Prinsip Local Crt dan Remote Crt
// Tambah Local Counter Jika Berhasil Encrypt    
// Tambah Remote Counter Jika Mac Cocok dan Berhasil Decrypt
//======================================================================
    increment_ctr(&session->identity.local_ctr, session->identity.local_nonce);
//======================================================================
	orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello_end(label, session->identity.client_id, encrypted_server_id_new_client_id2, session->hello_end.sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, 
        session->identity.kem_sharedsecret, session->identity.local_nonce, session->identity.local_ctr,
        &session->sock_fd, (const struct sockaddr *)&session->identity.remote_addr, cmd_result.r_orilink_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent hello_end to Server.", label);
        CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent hello_end to Server.", label);
    }
    CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
    return SUCCESS;
}
