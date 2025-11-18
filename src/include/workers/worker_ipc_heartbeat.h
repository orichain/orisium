#ifndef WORKERS_WORKER_IPC_HEARTBEAT_H
#define WORKERS_WORKER_IPC_HEARTBEAT_H

#include <inttypes.h>
#include <stdio.h>

#include "constants.h"
#include "ipc/protocol.h"
#include "log.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/worker_ipc.h"
#include "utilities.h"
#include "orilink/heartbeat.h"
#include "orilink/protocol.h"
#include "orilink.h"
#include "stdbool.h"
#include "orilink/heartbeat_ack.h"

struct sockaddr_in6;

static inline status_t send_heartbeat(worker_context_t *worker_ctx, void *xsession, orilink_protocol_type_t orilink_protocol) {
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
            cow_c_session_t *session = (cow_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
//======================================================================
            double hb_interval = node_hb_interval_with_jitter_us(session->rtt.value_prediction, session->retry.value_prediction);
            session->heartbeat.last_send_heartbeat_interval = hb_interval;
//======================================================================
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                return FAILURE;
            }
//----------------------------------------------------------------------
            session->heartbeat.heartbeat.sent_try_count++;
            session->heartbeat.heartbeat.sent_time = current_time.r_uint64_t;
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
                session->heartbeat.heartbeat.sent_try_count
            );
            if (orilink_cmd_result.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            session->heartbeat.heartbeat.udp_data = create_orilink_raw_protocol_packet(
                worker_ctx->label,
                &session->orilink_p8zs_pool,
                security->aes_key,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr,
                orilink_cmd_result.r_orilink_protocol_t
            );
            CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
            if (session->heartbeat.heartbeat.udp_data->status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            //print_hex("COW Sending Heartbeat ", udp_data->data, udp_data->len, 1);
            if (worker_master_udp_data_send_ipc(
                    worker_ctx->label, 
                    worker_ctx, 
                    &session->orilink_p8zs_pool,
                    identity->local_wot, 
                    identity->local_index, 
                    identity->local_session_index, 
                    (uint8_t)orilink_protocol,
                    session->heartbeat.heartbeat.sent_try_count,
                    &session->identity.remote_addr, 
                    &session->heartbeat.heartbeat
                ) != SUCCESS
            )
            {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            session->heartbeat.heartbeat.sent = true;
            session->heartbeat.heartbeat.ack_rcvd = false;
            session->heartbeat.heartbeat_ack.rcvd = false;
            break;
        }
        case SIO: {
            sio_c_session_t *session = (sio_c_session_t *)xsession;
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
//======================================================================
            double hb_interval = node_hb_interval_with_jitter_us(session->rtt.value_prediction, session->retry.value_prediction);
            session->heartbeat.last_send_heartbeat_interval = hb_interval;
//======================================================================
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                return FAILURE;
            }
//----------------------------------------------------------------------
            session->heartbeat.heartbeat.sent_try_count++;
            session->heartbeat.heartbeat.sent_time = current_time.r_uint64_t;
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
                session->heartbeat.heartbeat.sent_try_count
            );
            if (orilink_cmd_result.status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            session->heartbeat.heartbeat.udp_data = create_orilink_raw_protocol_packet(
                worker_ctx->label,
                &session->orilink_p8zs_pool,
                security->aes_key,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr,
                orilink_cmd_result.r_orilink_protocol_t
            );
            CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
            if (session->heartbeat.heartbeat.udp_data->status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            //print_hex("SIO Sending Heartbeat ", udp_data->data, udp_data->len, 1);
            if (worker_master_udp_data_send_ipc(
                    worker_ctx->label, 
                    worker_ctx, 
                    &session->orilink_p8zs_pool,
                    identity->local_wot, 
                    identity->local_index, 
                    identity->local_session_index, 
                    (uint8_t)orilink_protocol,
                    session->heartbeat.heartbeat.sent_try_count,
                    &session->identity.remote_addr, 
                    &session->heartbeat.heartbeat
                ) != SUCCESS
            )
            {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            session->heartbeat.heartbeat.sent = true;
            session->heartbeat.heartbeat.ack_rcvd = false;
            session->heartbeat.heartbeat_ack.rcvd = false;
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
            session->heartbeat.heartbeat_ack.ack_sent_try_count++;
            session->heartbeat.heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
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
                session->heartbeat.heartbeat_ack.ack_sent_try_count
            );
            if (orilink_cmd_result.status != SUCCESS) {
                return FAILURE;
            }
            session->heartbeat.heartbeat_ack.udp_data = create_orilink_raw_protocol_packet(
                worker_ctx->label,
                &session->orilink_p8zs_pool,
                security->aes_key,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr,
                orilink_cmd_result.r_orilink_protocol_t
            );
            CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
            if (session->heartbeat.heartbeat_ack.udp_data->status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            if (worker_master_udp_data_ack_send_ipc(
                    worker_ctx->label, 
                    worker_ctx, 
                    &session->orilink_p8zs_pool,
                    identity->local_wot, 
                    identity->local_index, 
                    identity->local_session_index, 
                    (uint8_t)ORILINK_HEARTBEAT_ACK,
                    session->heartbeat.heartbeat_ack.ack_sent_try_count,
                    &identity->remote_addr, 
                    &session->heartbeat.heartbeat_ack
                ) != SUCCESS
            )
            {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            if (session->heartbeat.heartbeat_ack.ack_sent_try_count > (uint8_t)0) {
                double try_count = (double)session->heartbeat.heartbeat_ack.ack_sent_try_count-(double)1;
                calculate_retry(worker_ctx, session, identity->local_wot, try_count);
            }
            //cleanup_control_packet_ack(&session->orilink_p8zs_pool, &session->heartbeat.heartbeat_ack, false, CDT_NOACTION);
            session->heartbeat.heartbeat.sent = false;
            session->heartbeat.heartbeat_ack.ack_sent = false;
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
            session->heartbeat.heartbeat_ack.ack_sent_try_count++;
            session->heartbeat.heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
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
                session->heartbeat.heartbeat_ack.ack_sent_try_count
            );
            if (orilink_cmd_result.status != SUCCESS) {
                return FAILURE;
            }
            session->heartbeat.heartbeat_ack.udp_data = create_orilink_raw_protocol_packet(
                worker_ctx->label,
                &session->orilink_p8zs_pool,
                security->aes_key,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr,
                orilink_cmd_result.r_orilink_protocol_t
            );
            CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
            if (session->heartbeat.heartbeat_ack.udp_data->status != SUCCESS) {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            if (worker_master_udp_data_ack_send_ipc(
                    worker_ctx->label, 
                    worker_ctx, 
                    &session->orilink_p8zs_pool,
                    identity->local_wot, 
                    identity->local_index, 
                    identity->local_session_index, 
                    (uint8_t)ORILINK_HEARTBEAT_ACK,
                    session->heartbeat.heartbeat_ack.ack_sent_try_count,
                    &identity->remote_addr, 
                    &session->heartbeat.heartbeat_ack
                ) != SUCCESS
            )
            {
                if (l_inc_ctr != 0xFF) {
                    decrement_ctr(&security->local_ctr, security->local_nonce);
                }
                return FAILURE;
            }
            if (session->heartbeat.heartbeat_cnt != 0x00) {
                if (session->heartbeat.heartbeat_ack.ack_sent_try_count > (uint8_t)0) {
                    double try_count = (double)session->heartbeat.heartbeat_ack.ack_sent_try_count-(double)1;
                    calculate_retry(worker_ctx, session, identity->local_wot, try_count);
                }
                //cleanup_control_packet_ack(&session->orilink_p8zs_pool, &session->heartbeat.heartbeat_ack, false, CDT_NOACTION);
                session->heartbeat.heartbeat.sent = false;
                if (session->heartbeat.heartbeat_cnt == 0x01) {
                    session->heartbeat.heartbeat_cnt += 0x01;
                }
                session->heartbeat.heartbeat_ack.ack_sent = false;
            }
            break;
        }
        default:
            return FAILURE;
    }
    return SUCCESS;
}

static inline status_t first_heartbeat_finalization(worker_context_t *worker_ctx, sio_c_session_t *session, orilink_identity_t *identity, uint8_t *trycount) {
	if (session->heartbeat.heartbeat_cnt == 0x00) {
		uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
		if (current_time.status != SUCCESS) {
            LOG_ERROR("%sError get_monotonic_time_ns.", worker_ctx->label);
			return FAILURE;
		}
		session->heartbeat.heartbeat_ack.rcvd_time = current_time.r_uint64_t;
		uint64_t interval_ull;
		uint8_t strycount;
		if (!session->heartbeat.heartbeat_ack.rcvd) {
			session->heartbeat.heartbeat_ack.rcvd = true;
			interval_ull = session->heartbeat.heartbeat_ack.rcvd_time - session->hello4_ack.ack_sent_time;
			session->heartbeat.heartbeat_ack.ack_sent_time = session->hello4_ack.ack_sent_time;
			strycount = session->hello4_ack.ack_sent_try_count;
		} else {
			interval_ull = session->heartbeat.heartbeat_ack.rcvd_time - session->heartbeat.heartbeat_ack.ack_sent_time;
			strycount = session->heartbeat.heartbeat_ack.ack_sent_try_count;
		}
		if (strycount > (uint8_t)0) {
			double try_count = (double)strycount-(double)1;
			calculate_retry(worker_ctx, session, identity->local_wot, try_count);
		}
		double rtt_value = (double)interval_ull;
        calculate_rtt(worker_ctx, session, identity->local_wot, rtt_value);
        #if !defined(LONGINTV_TEST)
        printf("%sRTT Hello-4 Ack = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 "\n", worker_ctx->label, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr);
        #endif
//----------------------------------------------------------------------
		session->heartbeat.heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
		session->heartbeat.heartbeat_cnt += 0x01;
//----------------------------------------------------------------------
		session->hello4_ack.ack_sent = true;
//----------------------------------------------------------------------
        session->heartbeat.heartbeat_ack.ack_sent = false;
//----------------------------------------------------------------------
	}
    return SUCCESS;
}

static inline status_t handle_workers_ipc_udp_data_cow_heartbeat(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    bool isretry = false;
    bool from_retry_timer = false;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        LOG_ERROR("%sError orilink_check_mac.", worker_ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("SIO Receiving Heartbeat ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY_CNT) {
            LOG_ERROR("%sHeartbeat Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->heartbeat.heartbeat_ack.last_trycount) {
            LOG_ERROR("%sHeartbeat Try Count Invalid Last: %d, Rcvd: %d.", worker_ctx->label, session->heartbeat.heartbeat_ack.last_trycount, trycount);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
            return FAILURE_IVLDTRY;
        }
        bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (_1l_) {
            LOG_DEVEL_DEBUG("%sHeartbeat Retry From Peer", worker_ctx->label);
            isretry = true;
        } else {
            bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (!_same_) {
                bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
                if (_1g_) {
                    LOG_ERROR("%sCounter Is Greater.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                    return FAILURE;
                } else {
                    LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                    return FAILURE;
                }
            } else {
                LOG_DEVEL_DEBUG("%sHeartbeat From Peer's Retry Timer", worker_ctx->label);
                from_retry_timer = true;
            }
        }
//----------------------------------------------------------------------
        if (session->heartbeat.heartbeat_cnt == 0x01) {
            session->heartbeat.heartbeat_cnt = 0x00;
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                LOG_ERROR("%sError get_monotonic_time_ns.", worker_ctx->label);
                return FAILURE;
            }
            session->hello4_ack.ack_sent_time = current_time.r_uint64_t;
        }
//----------------------------------------------------------------------
    }
//----------------------------------------------------------------------
    session->heartbeat.heartbeat_ack.last_trycount = trycount;
//======================================================================
    if (!isretry && !from_retry_timer) {
        if (session->heartbeat.heartbeat_cnt == 0x00) {
            if (!session->hello4_ack.ack_sent) {
                LOG_ERROR("%sHeartbeat Not Openned Yet.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                return FAILURE;
            }
        } else {
            if (!session->heartbeat.heartbeat_ack.ack_sent) {
                LOG_ERROR("%sHeartbeat Not Openned Yet.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                return FAILURE;
            }
        }
        bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (_1l_) {
            LOG_ERROR("%sHeartbeat With Lower Counter.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
            return FAILURE;
        } else {
            bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (!_same_) {
                bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
                if (_1g_) {
                    LOG_ERROR("%sHeartbeat With Greater Counter.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                    return FAILURE;
                } else {
                    LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                    return FAILURE;
                }
            }
        }
    }
//----------------------------------------------------------------------
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        LOG_ERROR("%sError orilink_read_header.", worker_ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------
    inc_ctr = oudp_datao->inc_ctr;
//----------------------------------------------------------------------
    if (isretry) {
        if (session->heartbeat.heartbeat_ack.udp_data != NULL) {
            //print_hex("SIO Sending Heartbeat Ack Retry Response ", session->heartbeat.heartbeat_ack.data, session->heartbeat.heartbeat_ack.len, 1);
            if (retry_control_packet_ack(
                    worker_ctx, 
                    &session->orilink_p8zs_pool,
                    identity, 
                    security, 
                    &session->heartbeat.heartbeat_ack,
                    ORILINK_HEARTBEAT_ACK
                ) != SUCCESS
            )
            {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                LOG_ERROR("%sError retry_control_packet_ack.", worker_ctx->label);
                return FAILURE;
            }
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return first_heartbeat_finalization(
            worker_ctx, 
            session, 
            identity, 
            &trycount
        );
    }
//======================================================================
    if (!session->heartbeat.heartbeat.ack_rcvd) {
        LOG_ERROR("%sTry Again Until My Previous Heartbeat Ack Received.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    }
//======================================================================
    orilink_protocol_t_status_t deserialized_oudp_datao = orilink_deserialize(worker_ctx->label,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n
    );
    if (deserialized_oudp_datao.status != SUCCESS) {
        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_oudp_datao.status);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_heartbeat_t *oheartbeat = received_orilink_protocol->payload.orilink_heartbeat;
//======================================================================
// + Security
//======================================================================
    if (identity->local_id != oheartbeat->remote_id || identity->remote_id != oheartbeat->local_id) {
        LOG_ERROR("%sLocal Id And Or Remote Id Mismatch.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    session->heartbeat.heartbeat_interval = oheartbeat->hb_interval;
//======================================================================
    cleanup_control_packet_ack(&session->orilink_p8zs_pool, &session->heartbeat.heartbeat_ack, false, true);
    if (send_heartbeat_ack(worker_ctx, session, ORILINK_HEARTBEAT_ACK) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    status_t fle = first_heartbeat_finalization(
        worker_ctx, 
        session, 
        identity, 
        &trycount
    );
    if (fle != SUCCESS) {
        return fle;
    }
//======================================================================
//session->metrics.last_ack = current_time->r_uint64_t;
//session->metrics.count_ack += (double)1;
//session->metrics.sum_hb_interval += session->heartbeat.heartbeat_interval;
//session->metrics.hb_interval = session->heartbeat.heartbeat_interval;
//======================================================================
    return SUCCESS;
}

static inline status_t handle_workers_ipc_udp_data_cow_heartbeat_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = 0xFF;
    uint32_t trycount = oudp_datao->trycount;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("SIO Receiving Heartbeat Ack ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (!session->heartbeat.heartbeat.sent) {
        LOG_ERROR("%sReceive Heartbeat_Ack But This Worker Session Is Never Sending Heartbeat.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    if (session->heartbeat.heartbeat.ack_rcvd) {
        LOG_ERROR("%sHeartbeat_Ack Received Already.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    }
//======================================================================
    bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
    if (_1l_) {
        LOG_ERROR("%sPeer's Counter Is Lower. Try Count %d", worker_ctx->label, trycount);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    } else {
        bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (!_same_) {
            bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (_1g_) {
                LOG_ERROR("%sPeer's Counter Is Greater.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                return FAILURE;
            } else {
                LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                return FAILURE;
            }
        }
    }
//======================================================================
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    inc_ctr = oudp_datao->inc_ctr;
//======================================================================
    orilink_protocol_t_status_t deserialized_oudp_datao = orilink_deserialize(worker_ctx->label,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n
    );
    if (deserialized_oudp_datao.status != SUCCESS) {
        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_oudp_datao.status);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_heartbeat_ack_t *oheartbeat_ack = received_orilink_protocol->payload.orilink_heartbeat_ack;
//======================================================================
// + Security
//======================================================================
    if (identity->local_id != oheartbeat_ack->remote_id || identity->remote_id != oheartbeat_ack->local_id) {
        LOG_ERROR("%sLocal Id And Or Remote Id Mismatch.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    //async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat.heartbeat_sender_timer_fd);
    //CLOSE_FD(&session->heartbeat.heartbeat_sender_timer_fd);
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
// 
//----------------------------------------------------------------------
    if (session->heartbeat.heartbeat.sent_try_count > (uint8_t)0) {
        double try_count = (double)session->heartbeat.heartbeat.sent_try_count-(double)1;
        calculate_retry(worker_ctx, session, identity->local_wot, try_count);
    }
//======================================================================   
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        LOG_ERROR("%sError get_monotonic_time_ns.", worker_ctx->label);
        return FAILURE;
    }
    session->heartbeat.heartbeat.ack_rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull = session->heartbeat.heartbeat.ack_rcvd_time - session->heartbeat.heartbeat.sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx, session, identity->local_wot, rtt_value);
    char timebuf[32];
    get_time_str(timebuf, sizeof(timebuf));
    #if !defined(LONGINTV_TEST)
    printf("%s%s - RTT Heartbeat = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 ", trycount %d\n", worker_ctx->label, timebuf, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr, trycount);
    #endif
//======================================================================
    session->heartbeat.heartbeat.ack_rcvd = true;
    cleanup_control_packet(worker_ctx, &session->orilink_p8zs_pool, &session->heartbeat.heartbeat, false, true);
//======================================================================
    //session->metrics.last_ack = current_time.r_uint64_t;
    //session->metrics.count_ack += (double)1;
    //session->metrics.sum_hb_interval += session->heartbeat.heartbeat_interval;
    //session->metrics.hb_interval = session->heartbeat.heartbeat_interval;
//======================================================================
    return SUCCESS;
}

static inline status_t handle_workers_ipc_udp_data_sio_heartbeat(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    bool isretry = false;
    bool from_retry_timer = false;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        LOG_ERROR("%sError orilink_check_mac.", worker_ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("COW Receiving Heartbeat ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY_CNT) {
            LOG_ERROR("%sHeartbeat Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->heartbeat.heartbeat_ack.last_trycount) {
            LOG_ERROR("%sHeartbeat Try Count Invalid Last: %d, Rcvd: %d.", worker_ctx->label, session->heartbeat.heartbeat_ack.last_trycount, trycount);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
            return FAILURE_IVLDTRY;
        }
        bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (_1l_) {
            LOG_DEVEL_DEBUG("%sHeartbeat Retry From Peer", worker_ctx->label);
            isretry = true;
        } else {
            bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (!_same_) {
                bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
                if (_1g_) {
                    LOG_ERROR("%sCounter Is Greater.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                    return FAILURE;
                } else {
                    LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                    return FAILURE;
                }
            } else {
                LOG_DEVEL_DEBUG("%sHeartbeat From Peer's Retry Timer", worker_ctx->label);
                from_retry_timer = true;
            }
        }
    }
//----------------------------------------------------------------------
    session->heartbeat.heartbeat_ack.last_trycount = trycount;
//======================================================================
    if (!isretry && !from_retry_timer) {
        if (!session->heartbeat.heartbeat_ack.ack_sent) {
            LOG_ERROR("%sHeartbeat Not Openned Yet.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
            return FAILURE;
        }
        bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (_1l_) {
            LOG_ERROR("%sHeartbeat With Lower Counter.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
            return FAILURE;
        } else {
            bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (!_same_) {
                bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
                if (_1g_) {
                    LOG_ERROR("%sHeartbeat With Greater Counter.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                    return FAILURE;
                } else {
                    LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                    return FAILURE;
                }
            }
        }
    }
//----------------------------------------------------------------------
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        LOG_ERROR("%sError orilink_read_header.", worker_ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------
    inc_ctr = oudp_datao->inc_ctr;
//----------------------------------------------------------------------
    if (isretry) {
        if (session->heartbeat.heartbeat_ack.udp_data != NULL) {
            //print_hex("COW Sending Heartbeat Ack Retry Response ", session->heartbeat.heartbeat_ack.data, session->heartbeat.heartbeat_ack.len, 1);
            if (retry_control_packet_ack(
                    worker_ctx, 
                    &session->orilink_p8zs_pool,
                    identity, 
                    security, 
                    &session->heartbeat.heartbeat_ack,
                    ORILINK_HEARTBEAT_ACK
                ) != SUCCESS
            )
            {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                LOG_ERROR("%sError retry_control_packet_ack.", worker_ctx->label);
                return FAILURE;
            }
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return SUCCESS;
    }
//======================================================================
    if (!session->heartbeat.heartbeat.ack_rcvd) {
        LOG_ERROR("%sTry Again Until My Previous Heartbeat Ack Received.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    }
//======================================================================
    orilink_protocol_t_status_t deserialized_oudp_datao = orilink_deserialize(worker_ctx->label,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n
    );
    if (deserialized_oudp_datao.status != SUCCESS) {
        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_oudp_datao.status);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_heartbeat_t *oheartbeat = received_orilink_protocol->payload.orilink_heartbeat;
//======================================================================
// + Security
//======================================================================
    if (identity->local_id != oheartbeat->remote_id || identity->remote_id != oheartbeat->local_id) {
        LOG_ERROR("%sLocal Id And Or Remote Id Mismatch.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    session->heartbeat.heartbeat_interval = oheartbeat->hb_interval;
//======================================================================
    cleanup_control_packet_ack(&session->orilink_p8zs_pool, &session->heartbeat.heartbeat_ack, false, true);
    if (send_heartbeat_ack(worker_ctx, session, ORILINK_HEARTBEAT_ACK) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
//session->metrics.last_ack = current_time->r_uint64_t;
//session->metrics.count_ack += (double)1;
//session->metrics.sum_hb_interval += session->heartbeat.heartbeat_interval;
//session->metrics.hb_interval = session->heartbeat.heartbeat_interval;
//======================================================================
    return SUCCESS;
}

static inline status_t handle_workers_ipc_udp_data_sio_heartbeat_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = 0xFF;
    uint32_t trycount = oudp_datao->trycount;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("COW Receiving Heartbeat Ack ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (!session->heartbeat.heartbeat.sent) {
        LOG_ERROR("%sReceive Heartbeat_Ack But This Worker Session Is Never Sending Heartbeat.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    if (session->heartbeat.heartbeat.ack_rcvd) {
        LOG_ERROR("%sHeartbeat_Ack Received Already.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    }
//======================================================================
    bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
    if (_1l_) {
        LOG_ERROR("%sPeer's Counter Is Lower. Try Count %d", worker_ctx->label, trycount);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    } else {
        bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (!_same_) {
            bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (_1g_) {
                LOG_ERROR("%sPeer's Counter Is Greater.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                return FAILURE;
            } else {
                LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
                return FAILURE;
            }
        }
    }
//======================================================================
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    inc_ctr = oudp_datao->inc_ctr;
//======================================================================
    orilink_protocol_t_status_t deserialized_oudp_datao = orilink_deserialize(worker_ctx->label,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n
    );
    if (deserialized_oudp_datao.status != SUCCESS) {
        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_oudp_datao.status);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&session->orilink_raw_protocol_pool, &oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_heartbeat_ack_t *oheartbeat_ack = received_orilink_protocol->payload.orilink_heartbeat_ack;
//======================================================================
// + Security
//======================================================================
    if (identity->local_id != oheartbeat_ack->remote_id || identity->remote_id != oheartbeat_ack->local_id) {
        LOG_ERROR("%sLocal Id And Or Remote Id Mismatch.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    //async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat.heartbeat_sender_timer_fd);
    //CLOSE_FD(&session->heartbeat.heartbeat_sender_timer_fd);
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
// 
//----------------------------------------------------------------------
    if (session->heartbeat.heartbeat.sent_try_count > (uint8_t)0) {
        double try_count = (double)session->heartbeat.heartbeat.sent_try_count-(double)1;
        calculate_retry(worker_ctx, session, identity->local_wot, try_count);
    }
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    session->heartbeat.heartbeat.ack_rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull = session->heartbeat.heartbeat.ack_rcvd_time - session->heartbeat.heartbeat.sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx, session, identity->local_wot, rtt_value);
    char timebuf[32];
    get_time_str(timebuf, sizeof(timebuf));
    #if !defined(LONGINTV_TEST)
    printf("%s%s - RTT Heartbeat = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 ", trycount %d\n", worker_ctx->label, timebuf, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr, trycount);
    #endif
//======================================================================
    session->heartbeat.heartbeat.ack_rcvd = true;
    cleanup_control_packet(worker_ctx, &session->orilink_p8zs_pool, &session->heartbeat.heartbeat, false, true);
//======================================================================
    //session->metrics.last_ack = current_time.r_uint64_t;
    //session->metrics.count_ack += (double)1;
    //session->metrics.sum_hb_interval += session->heartbeat.heartbeat_interval;
    //session->metrics.hb_interval = session->heartbeat.heartbeat_interval;
//======================================================================
    return SUCCESS;
}

#endif
