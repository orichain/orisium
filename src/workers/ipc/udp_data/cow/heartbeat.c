#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "workers/workers.h"
#include "orilink/protocol.h"
#include "stdbool.h"
#include "orilink/heartbeat_ack.h"
#include "async.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "constants.h"

static inline status_t last_execution(worker_context_t *worker_ctx, sio_c_session_t *session, orilink_identity_t *identity, uint64_t_status_t *current_time, uint8_t *trycount) {
    if (async_create_timerfd(worker_ctx->label, &session->heartbeat_receiver_timer_fd) != SUCCESS) {
        return FAILURE;
    }
    if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat_receiver_timer_fd,
        (time_t)session->heartbeat_interval,
        (long)((session->heartbeat_interval - (time_t)session->heartbeat_interval) * 1e9),
        (time_t)session->heartbeat_interval,
        (long)((session->heartbeat_interval - (time_t)session->heartbeat_interval) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_receiver_timer_fd) != SUCCESS) {
        return FAILURE;
    }
//======================================================================
    if (session->is_first_heartbeat) {
        if (*trycount > (uint8_t)1) {
            double try_count = (double)session->hello4_ack.ack_sent_try_count;
            calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
            session->hello4_ack.rcvd = true;
            session->hello4_ack.rcvd_time = current_time->r_uint64_t;
        } else {
            double try_count = (double)session->hello4_ack.ack_sent_try_count-(double)1;
            calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
            session->hello4_ack.rcvd = true;
            session->hello4_ack.rcvd_time = current_time->r_uint64_t;
            uint64_t interval_ull = session->hello4_ack.rcvd_time - session->hello4_ack.ack_sent_time;
            double rtt_value = (double)interval_ull;
            calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
            cleanup_packet_ack(worker_ctx->label, &worker_ctx->async, &session->hello4_ack, false);
            
            printf("%sRTT Hello-4 Ack = %f\n", worker_ctx->label, session->rtt.value_prediction);
        }
    } else {
        if (*trycount > (uint8_t)1) {
            double try_count = (double)session->heartbeat_ack.ack_sent_try_count;
            calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
            session->heartbeat_ack.rcvd = true;
            session->heartbeat_ack.rcvd_time = current_time->r_uint64_t;
        } else {
            double try_count = (double)session->heartbeat_ack.ack_sent_try_count-(double)1;
            calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
            session->heartbeat_ack.rcvd = true;
            session->heartbeat_ack.rcvd_time = current_time->r_uint64_t;
            uint64_t interval_ull = session->heartbeat_ack.rcvd_time - session->heartbeat_ack.ack_sent_time;
            double rtt_value = (double)interval_ull;
            calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
            
            printf("%sSIO RTT Heartbeat = %f\n", worker_ctx->label, session->rtt.value_prediction);
        }
    }
//======================================================================
    if (session->is_first_heartbeat) {
        session->is_first_heartbeat = false;
        session->heartbeat_ack.ack_sent = true;
    } else {
        session->heartbeat_ack.ack_sent = true;
    }
//======================================================================
//session->metrics.last_ack = current_time->r_uint64_t;
//session->metrics.count_ack += (double)1;
//session->metrics.sum_hb_interval += session->heartbeat_interval;
//session->metrics.hb_interval = session->heartbeat_interval;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_cow_heartbeat(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
//======================================================================
// + Security
//======================================================================
    if (session->is_first_heartbeat) {
        if (!session->hello4_ack.ack_sent) {
            LOG_ERROR("%sReceive Heartbeat But This Worker Session Is Never Sending Hello4_Ack.", worker_ctx->label);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        if (session->hello4_ack.rcvd) {
            if (trycount > (uint8_t)MAX_RETRY) {
                LOG_ERROR("%sHeartbeat Received Already.", worker_ctx->label);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE_MAXTRY;
            }
            if (trycount <= session->hello4_ack.last_trycount) {
                LOG_ERROR("%sHeartbeat Received Already.", worker_ctx->label);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE_IVLDTRY;
            }
        }
        if (trycount > (uint8_t)1) {
            async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_receiver_timer_fd);
            CLOSE_FD(&session->heartbeat_receiver_timer_fd);
            session->hello4_ack.ack_sent = false;
        }
        session->hello4_ack.last_trycount = trycount;
    } else {
        if (!session->heartbeat_ack.ack_sent) {
            LOG_ERROR("%sReceive Heartbeat But This Worker Session Is Never Sending Heartbeat_Ack.", worker_ctx->label);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        if (session->heartbeat_ack.rcvd) {
            if (trycount > (uint8_t)MAX_RETRY) {
                LOG_ERROR("%sHeartbeat Received Already.", worker_ctx->label);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE_MAXTRY;
            }
            if (trycount <= session->heartbeat_ack.last_trycount) {
                LOG_ERROR("%sHeartbeat Received Already.", worker_ctx->label);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE_IVLDTRY;
            }
        }
        session->heartbeat_ack.last_trycount = trycount;
    }
//======================================================================
    if (trycount == (uint8_t)1) {
        status_t cmac = orilink_check_mac_ctr(
            worker_ctx->label, 
            security->aes_key, 
            security->mac_key, 
            security->remote_nonce,
            &security->remote_ctr, 
            oudp_datao
        );
        if (cmac != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return cmac;
        }
    } else {
        if (inc_ctr != 0xFF) {
            if (security->remote_ctr != oudp_datao->ctr) {
                uint8_t *tmp_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
                if (!tmp_nonce) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return FAILURE_NOMEM;
                }
                uint32_t tmp_ctr = security->remote_ctr;
                memcpy(tmp_nonce, security->remote_nonce, AES_NONCE_BYTES);
                decrement_ctr(&tmp_ctr, tmp_nonce);
                status_t cctr = orilink_check_ctr(worker_ctx->label, security->aes_key, &tmp_ctr, oudp_datao);
                if (cctr != SUCCESS) {
                    memset(tmp_nonce, 0, AES_NONCE_BYTES);
                    free(tmp_nonce);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return cctr;
                }
                memset(tmp_nonce, 0, AES_NONCE_BYTES);
                free(tmp_nonce);
            } else {
                status_t cctr = orilink_check_ctr(worker_ctx->label, security->aes_key, &security->remote_ctr, oudp_datao);
                if (cctr != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return cctr;
                }
            }
        }
        status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
        if (cmac != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return cmac;
        }
        async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_receiver_timer_fd);
        CLOSE_FD(&session->heartbeat_receiver_timer_fd);
        session->heartbeat_ack.ack_sent = false;
    }
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//======================================================================
    if (trycount > (uint8_t)1 && session->heartbeat_ack.data != NULL) {
        if (retry_packet_ack(worker_ctx, session, &session->heartbeat_ack) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return last_execution(
            worker_ctx, 
            session, 
            identity, 
            &current_time, 
            &trycount
        );
    }
//======================================================================
    orilink_protocol_t_status_t deserialized_oudp_datao = orilink_deserialize(worker_ctx->label,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n
    );
    if (deserialized_oudp_datao.status != SUCCESS) {
        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_oudp_datao.status);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
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
    session->heartbeat_interval = oheartbeat->hb_interval;
    if (session->heartbeat_interval < (double)NODE_HEARTBEAT_INTERVAL) {
        session->heartbeat_interval = (double)NODE_HEARTBEAT_INTERVAL;
    }
    if (session->heartbeat_interval > (double)NODE_CHECK_HEALTHY) {
        session->heartbeat_interval = (double)NODE_CHECK_HEALTHY;
    }
//======================================================================
    session->heartbeat_ack.ack_sent_try_count++;
//----------------------------------------------------------------------
// Use Delayed Timer session->heartbeat_receiver_timer_fd With Interval session->heartbeat_interval
//----------------------------------------------------------------------
//session->heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat_ack(
        worker_ctx->label,
        0x01,
        identity->remote_wot,
        identity->remote_index,
        identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        identity->local_id,
        identity->remote_id,
        session->heartbeat_interval,
        session->heartbeat_ack.ack_sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    l_inc_ctr = orilink_cmd_result.r_orilink_protocol_t->inc_ctr;
    puint8_t_size_t_status_t udp_data = create_orilink_raw_protocol_packet(
        worker_ctx->label,
        security->aes_key,
        security->mac_key,
        security->local_nonce,
        &security->local_ctr,
        orilink_cmd_result.r_orilink_protocol_t
    );
    CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
    if (udp_data.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        if (l_inc_ctr != 0xFF) {
            decrement_ctr(&security->local_ctr, security->local_nonce);
        }
        return FAILURE;
    }
    cleanup_packet_ack(worker_ctx->label, &worker_ctx->async, &session->heartbeat_ack, false);
//======================================================================
// Test Packet Dropped
//======================================================================
    session->test_drop_heartbeat_ack++;
    if (
        session->test_drop_heartbeat_ack == 3 ||
        session->test_drop_heartbeat_ack == 5 ||
        session->test_drop_heartbeat_ack == 7 ||
        session->test_drop_heartbeat_ack == 9
    )
    {
        printf("[Debug Here Helper]: Heartbeat Ack Packet Number %d. Sending To Fake Addr To Force Retry\n", session->test_drop_heartbeat_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &fake_addr, &udp_data, &session->heartbeat_ack) != SUCCESS) {
//----------------------------------------------------------------------
// No Error Here
// This Is A Test Drop Packet
//----------------------------------------------------------------------
        /*
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        if (l_inc_ctr != 0xFF) {
            decrement_ctr(&security->local_ctr, security->local_nonce);
        }
        return FAILURE;
        */
//----------------------------------------------------------------------
        }
    } else {
        if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data, &session->heartbeat_ack) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            if (inc_ctr != 0xFF) {
                decrement_ctr(&security->remote_ctr, security->remote_nonce);
            }
            if (l_inc_ctr != 0xFF) {
                decrement_ctr(&security->local_ctr, security->local_nonce);
            }
            return FAILURE;
        }
        if (session->test_drop_heartbeat_ack >= 1000000) {
            session->test_drop_heartbeat_ack = 0;
        }
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    status_t le = last_execution(
        worker_ctx, 
        session, 
        identity, 
        &current_time, 
        &trycount
    );
    if (le != SUCCESS) {
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        if (l_inc_ctr != 0xFF) {
            decrement_ctr(&security->local_ctr, security->local_nonce);
        }
    }
    return le;
}
