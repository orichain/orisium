#include "log.h"
#include "types.h"
#include "orilink/protocol.h"
#include "orilink/hello1_ack.h"
#include "orilink/hello2_ack.h"
#include "sessions/master_session.h"

status_t hello1_ack(const char *label, int *listen_sock, master_sio_c_session_t *session) {
	orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello1_ack(label, session->identity.client_id, session->hello1_ack.ack_sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, listen_sock, (const struct sockaddr *)&session->old_client_addr, cmd_result.r_orilink_protocol_t);
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
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, listen_sock, (const struct sockaddr *)&session->old_client_addr, cmd_result.r_orilink_protocol_t);
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
    /*
	orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello3_ack(label, session->identity.client_id, session->identity.kem_ciphertext, session->raw_server_id_port, session->hello3_ack.ack_sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, listen_sock, (const struct sockaddr *)&session->old_client_addr, cmd_result.r_orilink_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent hello3_ack to Client.", label);
        CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent hello3_ack to Client.", label);
    }
    CLOSE_ORILINK_PROTOCOL(&cmd_result.r_orilink_protocol_t);
    */
    return SUCCESS;
}
