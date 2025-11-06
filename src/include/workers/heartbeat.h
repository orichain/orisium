#ifndef WORKERS_HEARTBEAT_H
#define WORKERS_HEARTBEAT_H

#include <inttypes.h>

#include "types.h"
#include "workers/workers.h"
#include "workers/worker_ipc.h"
#include "utilities.h"
#include "orilink/heartbeat.h"
#include "orilink/protocol.h"
#include "orilink.h"
#include "stdbool.h"
#include "orilink/heartbeat_ack.h"
#include "timer.h"
#include "constants.h"

static inline status_t send_heartbeat(worker_context_t *worker_ctx, void *xsession, orilink_protocol_type_t orilink_protocol) {
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
            cow_c_session_t *session = (cow_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
//======================================================================
            double hb_interval = node_hb_interval_with_jitter_ms(session->rtt.value_prediction, session->retry.value_prediction);
//======================================================================
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                return FAILURE;
            }
//----------------------------------------------------------------------
            session->heartbeat.sent_try_count++;
            session->heartbeat.sent_time = current_time.r_uint64_t;
            uint8_t l_inc_ctr = 0x01;
            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat(
                worker_ctx->label,
                l_inc_ctr,
                identity->remote_wot,
                identity->remote_index,
                identity->remote_session_index,
                identity->local_wot,
                identity->local_index,
                identity->local_session_index,
                identity->id_connection,
                identity->local_id,
                identity->remote_id,
                hb_interval,
                session->heartbeat.sent_try_count
            );
            if (orilink_cmd_result.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            session->heartbeat.udp_data = create_orilink_raw_protocol_packet(
                worker_ctx->label,
                security->aes_key,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr,
                orilink_cmd_result.r_orilink_protocol_t
            );
            CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
            if (session->heartbeat.udp_data.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            //print_hex("COW Sending Heartbeat ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
            if (worker_master_udp_data_send_ipc(
                    worker_ctx->label, 
                    worker_ctx, 
                    identity->local_wot, 
                    identity->local_index, 
                    identity->local_session_index, 
                    (uint8_t)orilink_protocol,
                    session->heartbeat.sent_try_count,
                    &session->identity.remote_addr, 
                    &session->heartbeat
                ) != SUCCESS
            )
            {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            session->heartbeat.sent = true;
            session->heartbeat.ack_rcvd = false;
            session->heartbeat_ack.rcvd = false;
//----------------------------------------------------------------------
// Allow Heartbeat Base On Schedule
//----------------------------------------------------------------------
            status_t otmr = htw_add_event(&worker_ctx->timer, session->heartbeat_openner_timer_id, hb_interval - (double)OPENNER_MARGIN_MS);
            if (otmr != SUCCESS) {
                return FAILURE;
            }
//----------------------------------------------------------------------
            break;
        }
        case SIO: {
            sio_c_session_t *session = (sio_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
//======================================================================
            double hb_interval = node_hb_interval_with_jitter_ms(session->rtt.value_prediction, session->retry.value_prediction);
//======================================================================
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                return FAILURE;
            }
//----------------------------------------------------------------------
            session->heartbeat.sent_try_count++;
            session->heartbeat.sent_time = current_time.r_uint64_t;
            uint8_t l_inc_ctr = 0x01;
            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat(
                worker_ctx->label,
                l_inc_ctr,
                identity->remote_wot,
                identity->remote_index,
                identity->remote_session_index,
                identity->local_wot,
                identity->local_index,
                identity->local_session_index,
                identity->id_connection,
                identity->local_id,
                identity->remote_id,
                hb_interval,
                session->heartbeat.sent_try_count
            );
            if (orilink_cmd_result.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            session->heartbeat.udp_data = create_orilink_raw_protocol_packet(
                worker_ctx->label,
                security->aes_key,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr,
                orilink_cmd_result.r_orilink_protocol_t
            );
            CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
            if (session->heartbeat.udp_data.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            //print_hex("SIO Sending Heartbeat ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
            if (worker_master_udp_data_send_ipc(
                    worker_ctx->label, 
                    worker_ctx, 
                    identity->local_wot, 
                    identity->local_index, 
                    identity->local_session_index, 
                    (uint8_t)orilink_protocol,
                    session->heartbeat.sent_try_count,
                    &session->identity.remote_addr, 
                    &session->heartbeat
                ) != SUCCESS
            )
            {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            session->heartbeat.sent = true;
            session->heartbeat.ack_rcvd = false;
            session->heartbeat_ack.rcvd = false;
//----------------------------------------------------------------------
// Allow Heartbeat Base On Schedule
//----------------------------------------------------------------------
            status_t otmr = htw_add_event(&worker_ctx->timer, session->heartbeat_openner_timer_id, hb_interval - (double)OPENNER_MARGIN_MS);
            if (otmr != SUCCESS) {
                return FAILURE;
            }
//----------------------------------------------------------------------
            break;
        }
        default:
            return FAILURE;
    }
    return SUCCESS;
}

static inline status_t send_heartbeat_ack(worker_context_t *worker_ctx, void *xsession, orilink_protocol_type_t orilink_protocol) {
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
            cow_c_session_t *session = (cow_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
//======================================================================
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                return FAILURE;
            }
            session->heartbeat_ack.ack_sent_try_count++;
            session->heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
//----------------------------------------------------------------------
            uint8_t l_inc_ctr = 0x01;
            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat_ack(
                worker_ctx->label,
                l_inc_ctr,
                identity->remote_wot,
                identity->remote_index,
                identity->remote_session_index,
                identity->local_wot,
                identity->local_index,
                identity->local_session_index,
                identity->id_connection,
                identity->local_id,
                identity->remote_id,
                session->heartbeat_ack.ack_sent_try_count
            );
            if (orilink_cmd_result.status != SUCCESS) {
                return FAILURE;
            }
            session->heartbeat_ack.udp_data = create_orilink_raw_protocol_packet(
                worker_ctx->label,
                security->aes_key,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr,
                orilink_cmd_result.r_orilink_protocol_t
            );
            CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
            if (session->heartbeat_ack.udp_data.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            if (worker_master_udp_data_ack_send_ipc(
                    worker_ctx->label, 
                    worker_ctx, 
                    identity->local_wot, 
                    identity->local_index, 
                    identity->local_session_index, 
                    (uint8_t)ORILINK_HEARTBEAT_ACK,
                    session->heartbeat_ack.ack_sent_try_count,
                    &identity->remote_addr, 
                    &session->heartbeat_ack
                ) != SUCCESS
            )
            {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            if (session->heartbeat_ack.ack_sent_try_count > (uint8_t)0) {
                double try_count = (double)session->heartbeat_ack.ack_sent_try_count-(double)1;
                calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
            }
            //cleanup_control_packet_ack(&session->heartbeat_ack, false, CDT_NOACTION);
            session->heartbeat.sent = false;
            session->heartbeat_ack.ack_sent = false;
            break;
        }
        case SIO: {
            sio_c_session_t *session = (sio_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
//======================================================================
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                return FAILURE;
            }
            session->heartbeat_ack.ack_sent_try_count++;
            session->heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
//----------------------------------------------------------------------
            uint8_t l_inc_ctr = 0x01;
            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat_ack(
                worker_ctx->label,
                l_inc_ctr,
                identity->remote_wot,
                identity->remote_index,
                identity->remote_session_index,
                identity->local_wot,
                identity->local_index,
                identity->local_session_index,
                identity->id_connection,
                identity->local_id,
                identity->remote_id,
                session->heartbeat_ack.ack_sent_try_count
            );
            if (orilink_cmd_result.status != SUCCESS) {
                return FAILURE;
            }
            session->heartbeat_ack.udp_data = create_orilink_raw_protocol_packet(
                worker_ctx->label,
                security->aes_key,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr,
                orilink_cmd_result.r_orilink_protocol_t
            );
            CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
            if (session->heartbeat_ack.udp_data.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            if (worker_master_udp_data_ack_send_ipc(
                    worker_ctx->label, 
                    worker_ctx, 
                    identity->local_wot, 
                    identity->local_index, 
                    identity->local_session_index, 
                    (uint8_t)ORILINK_HEARTBEAT_ACK,
                    session->heartbeat_ack.ack_sent_try_count,
                    &identity->remote_addr, 
                    &session->heartbeat_ack
                ) != SUCCESS
            )
            {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            if (session->heartbeat_cnt != 0x00) {
                if (session->heartbeat_ack.ack_sent_try_count > (uint8_t)0) {
                    double try_count = (double)session->heartbeat_ack.ack_sent_try_count-(double)1;
                    calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
                }
                //cleanup_control_packet_ack(&session->heartbeat_ack, false, CDT_NOACTION);
                session->heartbeat.sent = false;
                if (session->heartbeat_cnt == 0x01) {
                    session->heartbeat_cnt += 0x01;
                }
                session->heartbeat_ack.ack_sent = false;
            }
            break;
        }
        default:
            return FAILURE;
    }
    return SUCCESS;
}

#endif
