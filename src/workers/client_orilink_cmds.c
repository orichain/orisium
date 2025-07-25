#include "log.h"
#include "types.h"
#include "orilink/protocol.h"
#include "orilink/hello1.h"
#include "orilink/hello2.h"
#include "sessions/workers_session.h"

status_t hello1(const char *label, cow_c_session_t *session) {
	orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello1(label, session->client_id, session->kem_publickey, session->hello1_sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, &session->sock_fd, (const struct sockaddr *)&session->old_server_addr, cmd_result.r_orilink_protocol_t);
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
	orilink_protocol_t_status_t cmd_result = orilink_prepare_cmd_hello2(label, session->client_id, session->kem_publickey, session->hello2_sent_try_count);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_orilink_protocol_packet(label, &session->sock_fd, (const struct sockaddr *)&session->old_server_addr, cmd_result.r_orilink_protocol_t);
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
