#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "ipc.h"
#include "ipc/protocol.h"
#include "ipc/udp_data.h"
#include "ipc/worker_master_heartbeat.h"
#include "ipc/worker_master_hello1.h"
#include "ipc/worker_master_hello2.h"
#include "ipc/worker_master_task_info.h"
#include "log.h"
#include "orilink.h"
#include "orilink/heartbeat.h"
#include "orilink/heartbeat_ack.h"
#include "orilink/hello1.h"
#include "orilink/hello1_ack.h"
#include "orilink/hello2.h"
#include "orilink/hello2_ack.h"
#include "orilink/hello3.h"
#include "orilink/hello3_ack.h"
#include "orilink/hello4.h"
#include "orilink/hello4_ack.h"
#include "orilink/protocol.h"
#include "pqc.h"
#include "stdbool.h"
#include "types.h"
#include "utilities.h"
#include "workers/polling.h"
#include "workers/workers.h"
#include "xorshiro128plus.h"

status_t worker_master_heartbeat(worker_context_t *ctx, double new_heartbeat_interval_double) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_heartbeat(
        ctx->label, 
        *ctx->wot, 
        *ctx->index, 
        new_heartbeat_interval_double
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (ctx->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(ctx->label, &queue_id) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(ctx->label, queue_id, *ctx->wot, *ctx->index, ctx->master_uds_fd, cmd_result.r_ipc_protocol_t, &ctx->rekeying_queue) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            ctx->label, 
            ctx->aes_key,
            ctx->mac_key,
            ctx->local_nonce,
            &ctx->local_ctr,
            ctx->master_uds_fd, 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent worker_master_heartbeat to Master.", ctx->label);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent worker_master_heartbeat to Master.", ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

status_t worker_master_hello1(worker_context_t *ctx) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello1(
        ctx->label, 
        *ctx->wot, 
        *ctx->index, 
        ctx->kem_publickey
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        ctx->label, 
        ctx->aes_key,
        ctx->mac_key,
        ctx->local_nonce,
        &ctx->local_ctr,
        ctx->master_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_hello1 to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_hello1 to Master.", ctx->label);
    }
    ctx->hello1_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t worker_master_hello2(worker_context_t *ctx, uint8_t encrypted_wot_index2[]) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello2(
        ctx->label, 
        *ctx->wot, 
        *ctx->index, 
        encrypted_wot_index2
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        ctx->label, 
        ctx->aes_key,
        ctx->mac_key,
        ctx->local_nonce,
        &ctx->local_ctr,
        ctx->master_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_hello2 to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_hello2 to Master.", ctx->label);
    }
    ctx->hello2_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t worker_master_udp_data_ack_send_ipc(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol, 
    uint8_t trycount,
    struct sockaddr_in6 *addr,
    control_packet_ack_t *h
) 
{
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data(
        label,
        wot,
        index,
        session_index,
        orilink_protocol,
        trycount,
        addr,
        h->len,
        h->data
    );
    if (cmd_result.status != SUCCESS) {
        memset(h->data, 0, h->len);
        free(h->data);
        h->data = NULL;
        h->len = 0;
        return FAILURE;
    }
    if (worker_ctx->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(worker_ctx->label, &queue_id) != SUCCESS) {
            memset(h->data, 0, h->len);
            free(h->data);
            h->data = NULL;
            h->len = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(worker_ctx->label, queue_id, *worker_ctx->wot, *worker_ctx->index, worker_ctx->master_uds_fd, cmd_result.r_ipc_protocol_t, &worker_ctx->rekeying_queue) != SUCCESS) {
            memset(h->data, 0, h->len);
            free(h->data);
            h->data = NULL;
            h->len = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            worker_ctx->label,
            worker_ctx->aes_key,
            worker_ctx->mac_key,
            worker_ctx->local_nonce,
            &worker_ctx->local_ctr,
            worker_ctx->master_uds_fd, 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
            free(h->data);
            h->data = NULL;
            h->len = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

status_t worker_master_udp_data_send_ipc(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol, 
    uint8_t trycount,
    struct sockaddr_in6 *addr,
    control_packet_t *h
) 
{
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data(
        label,
        wot,
        index,
        session_index,
        orilink_protocol,
        trycount,
        addr,
        h->len,
        h->data
    );
    if (cmd_result.status != SUCCESS) {
        memset(h->data, 0, h->len);
        free(h->data);
        h->data = NULL;
        h->len = 0;
        return FAILURE;
    }
    if (worker_ctx->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(worker_ctx->label, &queue_id) != SUCCESS) {
            memset(h->data, 0, h->len);
            free(h->data);
            h->data = NULL;
            h->len = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(worker_ctx->label, queue_id, *worker_ctx->wot, *worker_ctx->index, worker_ctx->master_uds_fd, cmd_result.r_ipc_protocol_t, &worker_ctx->rekeying_queue) != SUCCESS) {
            memset(h->data, 0, h->len);
            free(h->data);
            h->data = NULL;
            h->len = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            worker_ctx->label,
            worker_ctx->aes_key,
            worker_ctx->mac_key,
            worker_ctx->local_nonce,
            &worker_ctx->local_ctr,
            worker_ctx->master_uds_fd, 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
            free(h->data);
            h->data = NULL;
            h->len = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

status_t worker_master_udp_data(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol, 
    uint8_t trycount,
    struct sockaddr_in6 *addr,
    puint8_t_size_t_status_t *r,
    control_packet_t *h,
    uint8_t* key_mac,
    uint8_t *nonce,
    uint32_t *ctr
) 
{
    if (h->data != NULL) {
        memset(h->data, 0, h->len);
        free(h->data);
    }
    h->ctr = *(uint32_t *)ctr;
    h->len = r->r_size_t;
    h->data = r->r_puint8_t;
    r->r_puint8_t = NULL;
    r->r_size_t = 0;
    return worker_master_udp_data_send_ipc(
        label,
        worker_ctx,
        wot,
        index,
        session_index,
        orilink_protocol,
        trycount,
        addr,
        h
    );
}

status_t worker_master_udp_data_ack(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol, 
    uint8_t trycount,
    struct sockaddr_in6 *addr,
    puint8_t_size_t_status_t *r,
    control_packet_ack_t *h,
    uint8_t* key_mac,
    uint8_t *nonce,
    uint32_t *ctr
) 
{
    if (h->data != NULL) {
        memset(h->data, 0, h->len);
        free(h->data);
    }
    h->ctr = *(uint32_t *)ctr;
    h->len = r->r_size_t;
    h->data = r->r_puint8_t;
    r->r_puint8_t = NULL;
    r->r_size_t = 0;
    return worker_master_udp_data_ack_send_ipc(
        label,
        worker_ctx,
        wot,
        index,
        session_index,
        orilink_protocol,
        trycount,
        addr,
        h
    );
}

status_t worker_master_task_info(worker_context_t *ctx, uint8_t session_index, task_info_type_t flag) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_task_info(
        ctx->label, 
        *ctx->wot, 
        *ctx->index,
        session_index,
        flag
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (ctx->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(ctx->label, &queue_id) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(ctx->label, queue_id, *ctx->wot, *ctx->index, ctx->master_uds_fd, cmd_result.r_ipc_protocol_t, &ctx->rekeying_queue) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            ctx->label, 
            ctx->aes_key,
            ctx->mac_key,
            ctx->local_nonce,
            &ctx->local_ctr,
            ctx->master_uds_fd, 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent worker_master_task_info to Master.", ctx->label);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent worker_master_task_info to Master.", ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

status_t handle_workers_ipc_info(worker_context_t *worker_ctx, double *initial_delay_ms, ipc_raw_protocol_t_status_t *ircvdi) {
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
        worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_master_worker_info_t *iinfoi = received_protocol->payload.ipc_master_worker_info;
    switch (iinfoi->flag) {
        case IT_SHUTDOWN: {
            LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            worker_ctx->shutdown_requested = 1;
            break;
        }
        case IT_WAKEUP: {
            LOG_INFO("%sIT_WAKEUP received...", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case IT_READY: {
            LOG_INFO("%sMaster Ready ...", worker_ctx->label);
//----------------------------------------------------------------------
            if (*initial_delay_ms > 0) {
                LOG_DEBUG("%sApplying initial delay of %ld ms...", worker_ctx->label, *initial_delay_ms);
                sleep_ms(*initial_delay_ms);
            }
//----------------------------------------------------------------------
            if (KEM_GENERATE_KEYPAIR(worker_ctx->kem_publickey, worker_ctx->kem_privatekey) != 0) {
                LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", worker_ctx->label);
                worker_ctx->shutdown_requested = 1;
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            if (worker_master_hello1(worker_ctx) != SUCCESS) {
                LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
                worker_ctx->shutdown_requested = 1;
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case IT_REKEYING: {
            worker_ctx->is_rekeying = true;
            LOG_INFO("%sMaster Rekeying ...", worker_ctx->label);
//----------------------------------------------------------------------
            if (*initial_delay_ms > 0) {
                LOG_DEBUG("%sApplying initial delay of %ld ms...", worker_ctx->label, *initial_delay_ms);
                sleep_ms(*initial_delay_ms);
            }
//----------------------------------------------------------------------
            if (KEM_GENERATE_KEYPAIR(worker_ctx->kem_publickey, worker_ctx->kem_privatekey) != 0) {
                LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", worker_ctx->label);
                worker_ctx->shutdown_requested = 1;
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            worker_ctx->hello1_sent = false;
            worker_ctx->hello1_ack_rcvd = false;
            worker_ctx->hello2_sent = false;
            worker_ctx->hello2_ack_rcvd = false;
            if (worker_master_hello1(worker_ctx) != SUCCESS) {
                LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
                worker_ctx->shutdown_requested = 1;
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        default:
            LOG_ERROR("%sUnknown Info Flag %d from Master. Ignoring.", worker_ctx->label, iinfoi->flag);
            CLOSE_IPC_PROTOCOL(&received_protocol);
    }
    return SUCCESS;
}

status_t handle_workers_ipc_cow_connect(worker_context_t *worker_ctx, void *worker_sessions, ipc_raw_protocol_t_status_t *ircvdi) {
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
        worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_master_cow_connect_t *icow_connecti = received_protocol->payload.ipc_master_cow_connect;            
//----------------------------------------------------------------------
    uint16_t slot_found = icow_connecti->session_index;
    cow_c_session_t *cow_c_session = (cow_c_session_t *)worker_sessions;
    cow_c_session_t *session = &cow_c_session[slot_found];
    orilink_identity_t *identity = &session->identity;
    orilink_security_t *security = &session->security;
    memcpy(&identity->remote_addr, &icow_connecti->remote_addr, sizeof(struct sockaddr_in6));
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    }
    session->hello1.sent_try_count++;
    session->hello1.sent_time = current_time.r_uint64_t;
//======================================================================
    identity->id_connection = icow_connecti->id_connection;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello1(
        worker_ctx->label,
        0x01,
//----------------------------------------------------------------------
        //identity->remote_wot,
        //identity->remote_index,
        //identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
//----------------------------------------------------------------------
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        identity->local_id,
        security->kem_publickey,
        session->hello1.sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
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
        return FAILURE;
    }
    //print_hex("COW Sending Hello1 ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
    if (worker_master_udp_data(
            worker_ctx->label, 
            worker_ctx, 
            identity->local_wot, 
            identity->local_index, 
            identity->local_session_index, 
            (uint8_t)ORILINK_HELLO1,
            session->hello1.sent_try_count,
            &identity->remote_addr, 
            &udp_data, 
            &session->hello1,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//======================================================================
    session->hello1.sent = true;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_hello1_ack(worker_context_t *worker_ctx, ipc_raw_protocol_t_status_t *ircvdi) {
    if (!worker_ctx->hello1_sent) {
        LOG_ERROR("%sBelum pernah mengirim HELLO1", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    }
    if (worker_ctx->hello1_ack_rcvd) {
        LOG_ERROR("%sSudah ada HELLO1_ACK", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    }
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
        worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_master_worker_hello1_ack_t *ihello1_acki = received_protocol->payload.ipc_master_worker_hello1_ack;
    memcpy(worker_ctx->kem_ciphertext, ihello1_acki->kem_ciphertext, KEM_CIPHERTEXT_BYTES);
    if (KEM_DECODE_SHAREDSECRET(worker_ctx->kem_sharedsecret, worker_ctx->kem_ciphertext, worker_ctx->kem_privatekey) != 0) {
        LOG_ERROR("%sFailed to KEM_DECODE_SHAREDSECRET. Worker error. Initiating graceful shutdown...", worker_ctx->label);
        worker_ctx->shutdown_requested = 1;
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }    
//----------------------------------------------------------------------
// Temporary Key
//----------------------------------------------------------------------
    uint8_t aes_key[HASHES_BYTES];
    kdf1(worker_ctx->kem_sharedsecret, aes_key);
    uint8_t local_nonce[AES_NONCE_BYTES];
    if (generate_nonce(worker_ctx->label, local_nonce) != SUCCESS) {
        LOG_ERROR("%sFailed to generate_nonce. Worker error. Initiating graceful shutdown...", worker_ctx->label);
        worker_ctx->shutdown_requested = 1;
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    uint32_t local_ctr = (uint32_t)0;
//----------------------------------------------------------------------
// HELLO2 Memakai mac_key baru
//----------------------------------------------------------------------
    kdf2(aes_key, worker_ctx->mac_key);
//----------------------------------------------------------------------
    uint8_t wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
    uint8_t encrypted_wot_index1[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index2[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES];
    memcpy(encrypted_wot_index1, local_nonce, AES_NONCE_BYTES);
    memcpy(wot_index, (uint8_t *)worker_ctx->wot, sizeof(uint8_t));
    memcpy(wot_index + sizeof(uint8_t), worker_ctx->index, sizeof(uint8_t));
//======================================================================    
    const size_t data_len = sizeof(uint8_t) + sizeof(uint8_t);
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            local_nonce,
            &local_ctr,
            wot_index,
            encrypted_wot_index,
            data_len
        ) != SUCCESS
    )
    {
        worker_ctx->shutdown_requested = 1;
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//======================================================================    
    memcpy(encrypted_wot_index1 + AES_NONCE_BYTES, encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
//======================================================================    
    uint8_t mac[AES_TAG_BYTES];
    const size_t data_4mac_len = AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t);
    calculate_mac(worker_ctx->mac_key, encrypted_wot_index1, mac, data_4mac_len);
//====================================================================== 
    memcpy(encrypted_wot_index2, encrypted_wot_index1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
    memcpy(encrypted_wot_index2 + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t), mac, AES_TAG_BYTES);
//======================================================================
    if (worker_master_hello2(worker_ctx, encrypted_wot_index2) != SUCCESS) {
        LOG_ERROR("%sFailed to worker_master_hello2. Worker error. Initiating graceful shutdown...", worker_ctx->label);
        worker_ctx->shutdown_requested = 1;
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    memset(aes_key, 0, HASHES_BYTES);
    memcpy(worker_ctx->local_nonce, local_nonce, AES_NONCE_BYTES);
    memset(local_nonce, 0, AES_NONCE_BYTES);
    worker_ctx->local_ctr = local_ctr;
    memcpy(worker_ctx->remote_nonce, ihello1_acki->nonce, AES_NONCE_BYTES);
    worker_ctx->hello1_ack_rcvd = true;
    CLOSE_IPC_PROTOCOL(&received_protocol);
    return SUCCESS;
}

status_t handle_workers_ipc_hello2_ack(worker_context_t *worker_ctx, ipc_raw_protocol_t_status_t *ircvdi) {
    if (!worker_ctx->hello2_sent) {
        LOG_ERROR("%sBelum pernah mengirim HELLO2", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    }
    if (worker_ctx->hello2_ack_rcvd) {
        LOG_ERROR("%sSudah ada HELLO2_ACK", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    }
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
        worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_master_worker_hello2_ack_t *ihello2_acki = received_protocol->payload.ipc_master_worker_hello2_ack;
//======================================================================
// Ambil remote_nonce
// Set remote_ctr = 0
// Ambil encrypter wot+index
// Ambil Mac
// Cocokkan MAc
// Decrypt wot dan index
//======================================================================
    uint32_t remote_ctr = (uint32_t)0;
    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
    memcpy(encrypted_wot_index, ihello2_acki->encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
    uint8_t data_mac[AES_TAG_BYTES];
    memcpy(data_mac, ihello2_acki->encrypted_wot_index + sizeof(uint8_t) + sizeof(uint8_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// Tmp aes_key
//----------------------------------------------------------------------
    uint8_t aes_key[HASHES_BYTES];
    kdf1(worker_ctx->kem_sharedsecret, aes_key);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
    const size_t data_len_0 = sizeof(uint8_t) + sizeof(uint8_t);
    if (compare_mac(
            worker_ctx->mac_key,
            encrypted_wot_index,
            data_len_0,
            data_mac
        ) != SUCCESS
    )
    {
        LOG_ERROR("%sIPC Hello2 Ack Mac mismatch!", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE_MACMSMTCH;
    }
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
    uint8_t decrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
    const size_t data_len = sizeof(uint8_t) + sizeof(uint8_t);
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            worker_ctx->remote_nonce,
            &remote_ctr,
            encrypted_wot_index,
            decrypted_wot_index,
            data_len
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//======================================================================    
//----------------------------------------------------------------------
// Mencocokkan wot index
//----------------------------------------------------------------------
    worker_type_t data_wot;
    memcpy((uint8_t *)&data_wot, decrypted_wot_index, sizeof(uint8_t));
    if (*(uint8_t *)worker_ctx->wot != *(uint8_t *)&data_wot) {
        LOG_ERROR("%sberbeda wot. Worker error...", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    uint8_t data_index;
    memcpy(&data_index, decrypted_wot_index + sizeof(uint8_t), sizeof(uint8_t));
    if (*worker_ctx->index != data_index) {
        LOG_ERROR("%sberbeda index. Worker error...", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    if (!worker_ctx->is_rekeying) {
//----------------------------------------------------------------------
// Aktifkan Heartbeat Karna security/Enkripsi Sudah Ready
//---------------------------------------------------------------------- 
        status_t chst = create_timer_oneshot(worker_ctx->label, &worker_ctx->async, &worker_ctx->heartbeat_timer_fd, (double)WORKER_HEARTBEAT_INTERVAL);
        if (chst != SUCCESS) {
            LOG_ERROR("%sWorker error async_create_timerfd...", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            return FAILURE;
        }
    } else {
        worker_ctx->is_rekeying = false;
        ipc_protocol_queue_t *current = worker_ctx->rekeying_queue;
        ipc_protocol_queue_t *next;
        while (current != NULL) {
            next = current->next;
            ssize_t_status_t send_result = send_ipc_protocol_message(
                worker_ctx->label, 
                worker_ctx->aes_key,
                worker_ctx->mac_key,
                worker_ctx->local_nonce,
                &worker_ctx->local_ctr,
                current->uds_fd,
                current->p
            );
            if (send_result.status != SUCCESS) {
                LOG_ERROR("%sFailed to sent rekeying queue data to Master.", worker_ctx->label);
            } else {
                LOG_DEBUG("%sSent rekeying queue data to Master.", worker_ctx->label);
            }
            CLOSE_IPC_PROTOCOL(&current->p);
            free(current);
            current = next;
        }
        worker_ctx->rekeying_queue = NULL;
    }
//----------------------------------------------------------------------
// Menganggap data valid dengan integritas
//---------------------------------------------------------------------- 
    memcpy(worker_ctx->aes_key, aes_key, HASHES_BYTES);
    memset(aes_key, 0, HASHES_BYTES);
    worker_ctx->remote_ctr = remote_ctr;
    worker_ctx->hello2_ack_rcvd = true;
//---------------------------------------------------------------------- 
    CLOSE_IPC_PROTOCOL(&received_protocol);
    return SUCCESS;
}

void handle_workers_ipc_closed_event(worker_context_t *worker_ctx) {
    LOG_INFO("%sMaster disconnected. Initiating graceful shutdown...", worker_ctx->label);
    worker_ctx->shutdown_requested = 1;
}

status_t first_heartbeat_finalization(worker_context_t *worker_ctx, sio_c_session_t *session, orilink_identity_t *identity, uint8_t *trycount) {
	if (session->heartbeat_cnt == 0x00) {
		uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
		if (current_time.status != SUCCESS) {
            LOG_ERROR("%sError get_monotonic_time_ns.", worker_ctx->label);
			return FAILURE;
		}
		session->heartbeat_ack.rcvd_time = current_time.r_uint64_t;
        session->heartbeat_ack.rcvd_ctr = session->security.remote_ctr;
		uint64_t interval_ull;
		uint8_t strycount;
		if (!session->heartbeat_ack.rcvd) {
			session->heartbeat_ack.rcvd = true;
			interval_ull = session->heartbeat_ack.rcvd_time - session->hello4_ack.ack_sent_time;
			session->heartbeat_ack.ack_sent_time = session->hello4_ack.ack_sent_time;
			strycount = session->hello4_ack.ack_sent_try_count;
			cleanup_control_packet_ack(&session->hello4_ack, false, CDT_NOACTION);
		} else {
			interval_ull = session->heartbeat_ack.rcvd_time - session->heartbeat_ack.ack_sent_time;
			strycount = session->heartbeat_ack.ack_sent_try_count;
		}
		if (strycount > (uint8_t)0) {
			double try_count = (double)strycount-(double)1;
			calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
		}
		double rtt_value = (double)interval_ull;
        if (rtt_value <= (double)MAX_RETRY_CNT * session->retry.value_prediction) {
            calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
        } else {
            double try_count = (double)1;
            calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
        }
        printf("%sRTT Hello-4 Ack = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 "\n", worker_ctx->label, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr);
//----------------------------------------------------------------------
		session->heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
		session->heartbeat_cnt += 0x01;
//----------------------------------------------------------------------
		session->hello4_ack.ack_sent = true;
//----------------------------------------------------------------------
// Set session->heartbeat_ack.ack_sent = true; In Heartbeat Openner
//----------------------------------------------------------------------
        session->heartbeat_ack.ack_sent = false;
//----------------------------------------------------------------------
	}
    return SUCCESS;
}

status_t retry_control_packet_ack(
    worker_context_t *worker_ctx, 
    orilink_identity_t *identity, 
    orilink_security_t *security, 
    control_packet_ack_t *control_packet_ack,
    orilink_protocol_type_t orilink_protocol
)
{
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        memset(control_packet_ack->data, 0, control_packet_ack->len);
        free(control_packet_ack->data);
        return FAILURE;
    }
    control_packet_ack->ack_sent_try_count++;
    control_packet_ack->ack_sent_time = current_time.r_uint64_t;
//----------------------------------------------------------------------
// Update trycount
//----------------------------------------------------------------------
    const size_t trycount_offset = AES_TAG_BYTES +
                                   sizeof(uint32_t) +
                                   ORILINK_VERSION_BYTES +
                                   
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t) +
                                   
                                   sizeof(uint64_t) +
                                   
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t);
    memcpy(control_packet_ack->data + trycount_offset, &control_packet_ack->ack_sent_try_count, sizeof(uint8_t));
    uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
    if (memcmp(
            security->mac_key, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        const size_t data_4mac_offset = AES_TAG_BYTES;
        size_t data_4mac_len = control_packet_ack->len - AES_TAG_BYTES;
        uint8_t *data_4mac = control_packet_ack->data + data_4mac_offset;
        uint8_t mac[AES_TAG_BYTES];
        calculate_mac(security->mac_key, data_4mac, mac, data_4mac_len);
        memcpy(control_packet_ack->data, mac, AES_TAG_BYTES);
    } else {
        uint8_t rendom_mac[AES_TAG_BYTES];
        generate_fast_salt(rendom_mac, AES_TAG_BYTES);
        memcpy(control_packet_ack->data, rendom_mac, AES_TAG_BYTES);
    }
    free(key0);
//----------------------------------------------------------------------
    if (worker_master_udp_data_ack_send_ipc(
            worker_ctx->label, 
            worker_ctx, 
            identity->local_wot, 
            identity->local_index, 
            identity->local_session_index, 
            (uint8_t)orilink_protocol,
            control_packet_ack->ack_sent_try_count,
            &identity->remote_addr, 
            control_packet_ack
        ) != SUCCESS
    )
    {
        memset(control_packet_ack->data, 0, control_packet_ack->len);
        free(control_packet_ack->data);
        return FAILURE;
    }
//======================================================================
    return SUCCESS;
}

status_t retry_control_packet(
    worker_context_t *worker_ctx, 
    orilink_identity_t *identity, 
    orilink_security_t *security, 
    control_packet_t *control_packet,
    orilink_protocol_type_t orilink_protocol
)
{
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        memset(control_packet->data, 0, control_packet->len);
        free(control_packet->data);
        return FAILURE;
    }
    control_packet->sent_try_count++;
    control_packet->sent_time = current_time.r_uint64_t;
//----------------------------------------------------------------------
// Update trycount
//----------------------------------------------------------------------
    const size_t trycount_offset = AES_TAG_BYTES +
                                   sizeof(uint32_t) +
                                   ORILINK_VERSION_BYTES +
                                   
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t) +
                                   
                                   sizeof(uint64_t) +
                                   
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t);
    memcpy(control_packet->data + trycount_offset, &control_packet->sent_try_count, sizeof(uint8_t));
    uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
    if (memcmp(
            security->mac_key, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        const size_t data_4mac_offset = AES_TAG_BYTES;
        size_t data_4mac_len = control_packet->len - AES_TAG_BYTES;
        uint8_t *data_4mac = control_packet->data + data_4mac_offset;
        uint8_t mac[AES_TAG_BYTES];
        calculate_mac(security->mac_key, data_4mac, mac, data_4mac_len);
        memcpy(control_packet->data, mac, AES_TAG_BYTES);
    } else {
        uint8_t rendom_mac[AES_TAG_BYTES];
        generate_fast_salt(rendom_mac, AES_TAG_BYTES);
        memcpy(control_packet->data, rendom_mac, AES_TAG_BYTES);
    }
    free(key0);
//----------------------------------------------------------------------    
    if (worker_master_udp_data_send_ipc(
            worker_ctx->label, 
            worker_ctx, 
            identity->local_wot, 
            identity->local_index, 
            identity->local_session_index, 
            (uint8_t)orilink_protocol,
            control_packet->sent_try_count,
            &identity->remote_addr, 
            control_packet
        ) != SUCCESS
    )
    {
        memset(control_packet->data, 0, control_packet->len);
        free(control_packet->data);
        return FAILURE;
    }
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_cow_heartbeat_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = 0xFF;
    uint32_t trycount = oudp_datao->trycount;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("SIO Receiving Heartbeat Ack ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (!session->heartbeat.sent) {
        LOG_ERROR("%sReceive Heartbeat_Ack But This Worker Session Is Never Sending Heartbeat.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    /*
    if (session->heartbeat.ack_rcvd) {
        LOG_ERROR("%sHeartbeat_Ack Received Already.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    */
//======================================================================
    bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
    if (_1l_) {
        if (session->heartbeat.sent_try_count != 0x01) {
            LOG_ERROR("%sPeer's Counter Is Lower.", worker_ctx->label);
            session->greater_counter = true;
        } else {
            LOG_ERROR("%s XXX - Peer's Counter Is Lower.", worker_ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    } else {
        bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (!_same_) {
            bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (_1g_) {
                LOG_ERROR("%sPeer's Counter Is Greater.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE;
            } else {
                bool igc = false;
                if (session->greater_counter) {
                    igc = is_gc_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce);
                }
                if (igc) {
                    session->greater_counter = false;
                    session->heartbeat.ack_rcvd = true;
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return SUCCESS;
                } else {
                    LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return FAILURE;
                }
            }
        }
    }
//======================================================================
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
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
    //async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
    //CLOSE_FD(&session->heartbeat_sender_timer_fd);
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
// 
//----------------------------------------------------------------------
    if (session->heartbeat.sent_try_count > (uint8_t)0) {
        double try_count = (double)session->heartbeat.sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
//======================================================================   
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        LOG_ERROR("%sError get_monotonic_time_ns.", worker_ctx->label);
        return FAILURE;
    }
    session->heartbeat.ack_rcvd_time = current_time.r_uint64_t;
    session->heartbeat.ack_rcvd_ctr = security->remote_ctr;
    uint64_t interval_ull = session->heartbeat.ack_rcvd_time - session->heartbeat.sent_time;
    double rtt_value = (double)interval_ull;
    if (rtt_value <= (double)MAX_RETRY_CNT * session->retry.value_prediction) {
        calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    } else {
        double try_count = (double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    char timebuf[32];
    get_time_str(timebuf, sizeof(timebuf));
    printf("%s%s - RTT Heartbeat = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 ", trycount %d, rcvd ctr %" PRIu32 " \n", worker_ctx->label, timebuf, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr, trycount, session->heartbeat.ack_rcvd_ctr);
//======================================================================
    session->heartbeat.ack_rcvd = true;
//======================================================================
    //session->metrics.last_ack = current_time.r_uint64_t;
    //session->metrics.count_ack += (double)1;
    //session->metrics.sum_hb_interval += session->heartbeat_interval;
    //session->metrics.hb_interval = session->heartbeat_interval;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_cow_heartbeat(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = 0xFF;
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    bool isretry = false;
    bool from_retry_timer = false;
    bool isgc = false;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        LOG_ERROR("%sError orilink_check_mac.", worker_ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("SIO Receiving Heartbeat ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY_CNT) {
            LOG_ERROR("%sHeartbeat Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->heartbeat_ack.last_trycount) {
            LOG_ERROR("%sHeartbeat Try Count Invalid Last: %d, Rcvd: %d.", worker_ctx->label, session->heartbeat_ack.last_trycount, trycount);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
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
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return FAILURE;
                } else {
                    bool igc = is_gc_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce);
                    if (igc) {
                        isgc = true;
                    } else {
                        LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                        return FAILURE;
                    }
                }
            } else {
                LOG_DEVEL_DEBUG("%sHeartbeat From Peer's Retry Timer", worker_ctx->label);
                from_retry_timer = true;
            }
        }
//----------------------------------------------------------------------
        if (session->heartbeat_cnt == 0x01) {
            session->heartbeat_cnt = 0x00;
            uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
            if (current_time.status != SUCCESS) {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                LOG_ERROR("%sError get_monotonic_time_ns.", worker_ctx->label);
                return FAILURE;
            }
            session->hello4_ack.ack_sent_time = current_time.r_uint64_t;
        }
//----------------------------------------------------------------------
    }
//----------------------------------------------------------------------
    session->heartbeat_ack.last_trycount = trycount;
//======================================================================
    if (!isretry && !from_retry_timer) {
        if (session->heartbeat_cnt == 0x00) {
            if (!session->hello4_ack.ack_sent) {
                LOG_ERROR("%sReceive Heartbeat But This Worker Session Is Never Sending Hello4_Ack.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE;
            }
        } else {
            if (!session->heartbeat_ack.ack_sent) {
                LOG_ERROR("%sReceive Heartbeat But This Worker Session Is Never Sending Heartbeat_Ack.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE;
            }
        }
        bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (_1l_) {
            LOG_ERROR("%sHeartbeat With Lower Counter.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        } else {
            bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (!_same_) {
                bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
                if (_1g_) {
                    LOG_ERROR("%sHeartbeat With Greater Counter.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return FAILURE;
                } else {
                    bool igc = is_gc_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce);
                    if (igc) {
                        isgc = true;
                    } else {
                        LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                        return FAILURE;
                    }
                }
            }
        }
    }
    if (isgc) {
        LOG_ERROR("%sWe Have To Initiate New Heartbeat When ready.", worker_ctx->label);
        uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
        if (current_time.status != SUCCESS) {
            LOG_ERROR("%sError get_monotonic_time_ns.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        session->heartbeat_ack.ack_sent_try_count++;
        session->heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
        l_inc_ctr = 0x01;
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
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            LOG_ERROR("%sError orilink_prepare_cmd_heartbeat_ack.", worker_ctx->label);
            return FAILURE;
        }
        uint32_t hgc = 0xffffffff;
        uint8_t hgn[AES_NONCE_BYTES];
        memcpy(hgn, security->local_nonce, AES_NONCE_BYTES);
        puint8_t_size_t_status_t udp_data = create_orilink_raw_protocol_packet(
            worker_ctx->label,
            security->aes_key,
            security->mac_key,
            hgn,
            &hgc,
            orilink_cmd_result.r_orilink_protocol_t
        );
        CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
        if (udp_data.status != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            LOG_ERROR("%sError create_orilink_raw_protocol_packet.", worker_ctx->label);
            return FAILURE;
        }
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HEARTBEAT_ACK,
                session->heartbeat_ack.ack_sent_try_count,
                remote_addr, 
                &udp_data, 
                &session->heartbeat_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            LOG_ERROR("%sError worker_master_udp_data_ack.", worker_ctx->label);
            return FAILURE;
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        status_t fle = first_heartbeat_finalization(
            worker_ctx, 
            session, 
            identity, 
            &trycount
        );
        if (fle != SUCCESS) {
            return fle;
        }
        if (session->heartbeat_cnt != 0x00) {
            if (session->heartbeat_ack.ack_sent_try_count > (uint8_t)0) {
                double try_count = (double)session->heartbeat_ack.ack_sent_try_count-(double)1;
                calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
            }
            cleanup_control_packet_ack(&session->heartbeat_ack, false, CDT_NOACTION);
            session->heartbeat.sent = false;
            if (session->heartbeat_cnt == 0x01) {
                session->heartbeat_cnt += 0x01;
            }
            session->heartbeat_ack.ack_sent = false;
        }
        return SUCCESS;
    }
//----------------------------------------------------------------------
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        LOG_ERROR("%sError orilink_read_header.", worker_ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------
    inc_ctr = oudp_datao->inc_ctr;
//----------------------------------------------------------------------
    if (isretry) {
        if (session->heartbeat_ack.data != NULL) {
            //print_hex("SIO Sending Heartbeat Ack Retry Response ", session->heartbeat_ack.data, session->heartbeat_ack.len, 1);
            if (retry_control_packet_ack(
                    worker_ctx, 
                    identity, 
                    security, 
                    &session->heartbeat_ack,
                    ORILINK_HEARTBEAT_ACK
                ) != SUCCESS
            )
            {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                LOG_ERROR("%sError retry_control_packet_ack.", worker_ctx->label);
                return FAILURE;
            }
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return first_heartbeat_finalization(
            worker_ctx, 
            session, 
            identity, 
            &trycount
        );
    }
//======================================================================
    if (!session->heartbeat.ack_rcvd) {
        LOG_ERROR("%sTry Again Until My Previous Heartbeat Ack Received.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
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
    if (session->heartbeat_interval < (double)0.001) {
        session->heartbeat_interval = (double)0.001;
    }
    if (session->heartbeat_interval > (double)100) {
        session->heartbeat_interval = (double)100;
    }
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        LOG_ERROR("%sError get_monotonic_time_ns.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    session->heartbeat_ack.ack_sent_try_count++;
    session->heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
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
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        LOG_ERROR("%sError orilink_prepare_cmd_heartbeat_ack.", worker_ctx->label);
        return FAILURE;
    }
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
        LOG_ERROR("%sError create_orilink_raw_protocol_packet.", worker_ctx->label);
        return FAILURE;
    }
    //print_hex("SIO Sending Heartbeat Ack ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
//======================================================================
// Test Packet Dropped
//======================================================================
    //session->test_drop_heartbeat_ack++;
    if (
        session->test_drop_heartbeat_ack == 1 ||
        session->test_drop_heartbeat_ack == 3 ||
        session->test_drop_heartbeat_ack == 5 ||
        session->test_drop_heartbeat_ack == 7
    )
    {
        LOG_DEVEL_DEBUG("[Debug Here Helper]: Heartbeat Ack Packet Number %d. Sending To Fake Addr To Force Retry", session->test_drop_heartbeat_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HEARTBEAT_ACK,
                session->heartbeat_ack.ack_sent_try_count,
                &fake_addr, 
                &udp_data, 
                &session->heartbeat_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
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
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HEARTBEAT_ACK,
                session->heartbeat_ack.ack_sent_try_count,
                remote_addr, 
                &udp_data, 
                &session->heartbeat_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            if (inc_ctr != 0xFF) {
                decrement_ctr(&security->remote_ctr, security->remote_nonce);
            }
            if (l_inc_ctr != 0xFF) {
                decrement_ctr(&security->local_ctr, security->local_nonce);
            }
            LOG_ERROR("%sError worker_master_udp_data_ack.", worker_ctx->label);
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
    status_t fle = first_heartbeat_finalization(
        worker_ctx, 
        session, 
        identity, 
        &trycount
    );
    if (fle != SUCCESS) {
        return fle;
    }
    if (session->heartbeat_cnt != 0x00) {
        if (session->heartbeat_ack.ack_sent_try_count > (uint8_t)0) {
            double try_count = (double)session->heartbeat_ack.ack_sent_try_count-(double)1;
            calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
        }
        cleanup_control_packet_ack(&session->heartbeat_ack, false, CDT_NOACTION);
        session->heartbeat.sent = false;
        if (session->heartbeat_cnt == 0x01) {
            session->heartbeat_cnt += 0x01;
        }
//----------------------------------------------------------------------
// Set session->heartbeat_ack.ack_sent = true; In Heartbeat Openner
//----------------------------------------------------------------------
        session->heartbeat_ack.ack_sent = false;
//----------------------------------------------------------------------
    }
//======================================================================
//session->metrics.last_ack = current_time->r_uint64_t;
//session->metrics.count_ack += (double)1;
//session->metrics.sum_hb_interval += session->heartbeat_interval;
//session->metrics.hb_interval = session->heartbeat_interval;
//======================================================================
    double timer_interval = session->heartbeat_interval;
//======================================================================
    status_t chst = create_timer_oneshot(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd, timer_interval);
    if (chst != SUCCESS) {
        LOG_ERROR("%sError create_timer_oneshot.", worker_ctx->label);
        return FAILURE;
    }
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_cow_hello4(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    bool isretry = false;
    bool from_retry_timer = false;
    uint8_t aes_key[HASHES_BYTES];
    uint32_t remote_ctr = (uint32_t)0;
    uint32_t local_ctr = (uint32_t)0;
    uint8_t remote_nonce[AES_NONCE_BYTES];
//======================================================================
// + Security
//======================================================================
// Retry Initialization
//======================================================================
    if (trycount != (uint8_t)1) {
        memcpy(aes_key, security->aes_key, HASHES_BYTES);
        memcpy(remote_nonce, security->remote_nonce, AES_NONCE_BYTES);
        remote_ctr = security->remote_ctr;
        local_ctr = security->local_ctr;
        memset(security->aes_key, 0, HASHES_BYTES);
        memset(security->remote_nonce, 0, AES_NONCE_BYTES);
        security->remote_ctr = (uint32_t)0;
        security->local_ctr = (uint32_t)0;
    }
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("SIO Receiving Hello4 ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY_CNT) {
            LOG_ERROR("%sHello4 Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->hello4_ack.last_trycount) {
            LOG_ERROR("%sHello4 Try Count Invalid.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
        isretry = true;
        from_retry_timer = false;
    }
//----------------------------------------------------------------------
    session->hello4_ack.last_trycount = trycount;
//======================================================================
    if (!isretry && !from_retry_timer) {
        if (!session->hello3_ack.ack_sent) {
            LOG_ERROR("%sReceive Hello4 But This Worker Session Is Never Sending Hello3_Ack.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
    }
//----------------------------------------------------------------------
    if (isretry) {
        if (session->hello4_ack.data != NULL) {
            //print_hex("SIO Sending Hello4 Ack Retry Response ", session->hello4_ack.data, session->hello4_ack.len, 1);
            if (retry_control_packet_ack(
                    worker_ctx, 
                    identity, 
                    security, 
                    &session->hello4_ack,
                    ORILINK_HELLO4_ACK
                ) != SUCCESS
            )
            {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE;
            }
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
//======================================================================
        memcpy(security->aes_key, aes_key, HASHES_BYTES);
        memcpy(security->remote_nonce, remote_nonce, AES_NONCE_BYTES);
        security->remote_ctr = remote_ctr;
        security->local_ctr = local_ctr;
        memset(aes_key, 0, HASHES_BYTES);
        memset(remote_nonce, 0, AES_NONCE_BYTES);
        remote_ctr = (uint32_t)0;
        local_ctr = (uint32_t)0;
//----------------------------------------------------------------------
        return SUCCESS;
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
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_hello4_t *ohello4 = received_orilink_protocol->payload.orilink_hello4;
//======================================================================
// Ambil remote_nonce
// Set remote_ctr = 0
// Ambil encrypter wot+index
// Ambil Mac
// Cocokkan MAc
// Decrypt wot dan index
//======================================================================
    memcpy(remote_nonce, ohello4->encrypted_local_identity, AES_NONCE_BYTES);
    uint8_t encrypted_remote_identity_rcvd[
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    memcpy(encrypted_remote_identity_rcvd, ohello4->encrypted_local_identity + AES_NONCE_BYTES, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    uint8_t data_mac[AES_TAG_BYTES];
    memcpy(data_mac, ohello4->encrypted_local_identity + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// Temporary Key
//----------------------------------------------------------------------
    kdf1(security->kem_sharedsecret, aes_key);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
    uint8_t encrypted_remote_identity_rcvd1[
        AES_NONCE_BYTES +
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    memcpy(encrypted_remote_identity_rcvd1, ohello4->encrypted_local_identity, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    const size_t data_len_0 = AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    if (compare_mac(
            security->mac_key,
            encrypted_remote_identity_rcvd1,
            data_len_0,
            data_mac
        ) != SUCCESS
    )
    {
        LOG_ERROR("%sORILINK Hello4 Mac mismatch!", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
    uint8_t decrypted_remote_identity_rcvd[
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    const size_t data_len = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            remote_nonce,
            &remote_ctr,
            encrypted_remote_identity_rcvd,
            decrypted_remote_identity_rcvd,
            data_len
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
// + Security
//======================================================================
    worker_type_t data_wot;
    memcpy((uint8_t *)&data_wot, decrypted_remote_identity_rcvd, sizeof(uint8_t));
    if (*(uint8_t *)&identity->remote_wot != *(uint8_t *)&data_wot) {
        LOG_ERROR("%sberbeda wot.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    uint8_t data_index;
    memcpy(&data_index, decrypted_remote_identity_rcvd + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->remote_index != data_index) {
        LOG_ERROR("%sberbeda index.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    uint8_t data_session_index;
    memcpy(&data_session_index, decrypted_remote_identity_rcvd + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->remote_session_index != data_session_index) {
        LOG_ERROR("%sberbeda session_index.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }      
    uint64_t remote_id_be0;
    memcpy(&remote_id_be0, decrypted_remote_identity_rcvd + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint64_t));
    uint64_t remote_id = be64toh(remote_id_be0);
    if (remote_id != identity->remote_id) {
        LOG_ERROR("%sberbeda id.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    uint8_t remote_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    uint8_t encrypted_remote_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];   
    uint8_t encrypted_remote_identity1[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t) + AES_TAG_BYTES];
    memcpy(
        remote_identity, 
        (uint8_t *)&identity->remote_wot, 
        sizeof(uint8_t)
    );
    memcpy(
        remote_identity + sizeof(uint8_t), 
        (uint8_t *)&identity->remote_index, 
        sizeof(uint8_t)
    );
    memcpy(
        remote_identity + sizeof(uint8_t) + sizeof(uint8_t), 
        (uint8_t *)&identity->remote_session_index, 
        sizeof(uint8_t)
    );
    uint64_t remote_id_be1 = htobe64(remote_id);
    memcpy(
        remote_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), 
        &remote_id_be1, 
        sizeof(uint64_t)
    );
//======================================================================    
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            security->local_nonce,
            &local_ctr,
            remote_identity,
            encrypted_remote_identity,
            data_len
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================    
    uint8_t mac1[AES_TAG_BYTES];
    const size_t data_4mac_len = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    calculate_mac(security->mac_key, encrypted_remote_identity, mac1, data_4mac_len);
//====================================================================== 
    memcpy(encrypted_remote_identity1, encrypted_remote_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    memcpy(encrypted_remote_identity1 + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), mac1, AES_TAG_BYTES);
//======================================================================
    uint8_t local_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    uint8_t encrypted_local_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];   
    uint8_t encrypted_local_identity1[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t) + AES_TAG_BYTES];
    memcpy(
        local_identity, 
        (uint8_t *)&identity->local_wot, 
        sizeof(uint8_t)
    );
    memcpy(
        local_identity + sizeof(uint8_t), 
        (uint8_t *)&identity->local_index, 
        sizeof(uint8_t)
    );
    memcpy(
        local_identity + sizeof(uint8_t) + sizeof(uint8_t), 
        (uint8_t *)&identity->local_session_index, 
        sizeof(uint8_t)
    );
    uint64_t local_id_be = htobe64(identity->local_id);
    memcpy(
        local_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), 
        &local_id_be, 
        sizeof(uint64_t)
    );
//======================================================================    
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            security->local_nonce,
            &local_ctr,
            local_identity,
            encrypted_local_identity,
            data_len
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================    
    uint8_t mac2[AES_TAG_BYTES];
    calculate_mac(security->mac_key, encrypted_local_identity, mac2, data_4mac_len);
//====================================================================== 
    memcpy(encrypted_local_identity1, encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    memcpy(encrypted_local_identity1 + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), mac2, AES_TAG_BYTES);
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
    session->hello4_ack.ack_sent_try_count++;
    session->hello4_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello4_ack(
        worker_ctx->label,
        l_inc_ctr,
        identity->remote_wot,
        identity->remote_index,
        identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        encrypted_remote_identity1,
        encrypted_local_identity1,
        session->hello4_ack.ack_sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
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
        return FAILURE;
    }
    //print_hex("SIO Sending Hello4 Ack ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
//======================================================================
// Test Packet Dropped
//======================================================================
    //session->test_drop_hello4_ack++;
    if (
        session->test_drop_hello4_ack == 1
    )
    {
        printf("[Debug Here Helper]: Hello4 Ack Packet Number %d. Sending To Fake Addr To Force Retry\n", session->test_drop_hello4_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HELLO4_ACK,
                session->hello4_ack.ack_sent_try_count,
                &fake_addr, 
                &udp_data, 
                &session->hello4_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
//----------------------------------------------------------------------
// No Error Here
// This Is A Test Drop Packet
//----------------------------------------------------------------------
            /*
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
            */
        }
    } else {
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HELLO4_ACK,
                session->hello4_ack.ack_sent_try_count,
                remote_addr, 
                &udp_data, 
                &session->hello4_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
        }
        if (session->test_drop_hello4_ack >= 1000000) {
            session->test_drop_hello4_ack = 0;
        }
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    memcpy(security->aes_key, aes_key, HASHES_BYTES);
    memcpy(security->remote_nonce, remote_nonce, AES_NONCE_BYTES);
    security->remote_ctr = remote_ctr;
    security->local_ctr = local_ctr;
    memset(aes_key, 0, HASHES_BYTES);
    memset(remote_nonce, 0, AES_NONCE_BYTES);
//======================================================================
    session->hello4_ack.rcvd_time = current_time.r_uint64_t;
    session->hello4_ack.rcvd_ctr = security->remote_ctr;
    uint64_t interval_ull;
    uint8_t strycount;
    if (!session->hello4_ack.rcvd) {
        session->hello4_ack.rcvd = true;
        interval_ull = session->hello4_ack.rcvd_time - session->hello3_ack.ack_sent_time;
        session->hello4_ack.ack_sent_time = session->hello3_ack.ack_sent_time;
        strycount = session->hello3_ack.ack_sent_try_count;
        cleanup_control_packet_ack(&session->hello3_ack, false, CDT_NOACTION);
    } else {
        interval_ull = session->hello4_ack.rcvd_time - session->hello4_ack.ack_sent_time;
        strycount = session->hello4_ack.ack_sent_try_count;
    }
    if (strycount > (uint8_t)0) {
        double try_count = (double)strycount-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    double rtt_value = (double)interval_ull;
    if (rtt_value <= (double)MAX_RETRY_CNT * session->retry.value_prediction) {
        calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    } else {
        double try_count = (double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    printf("%sRTT Hello-3 Ack = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 "\n", worker_ctx->label, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr);
//======================================================================
    session->hello4_ack.ack_sent = true;
    session->heartbeat_cnt = 0x00;
    session->heartbeat.ack_rcvd = true;
    session->heartbeat.ack_rcvd_time = current_time.r_uint64_t;
    session->heartbeat.ack_rcvd_ctr = security->remote_ctr;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_cow_hello3(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    bool isretry = false;
    bool from_retry_timer = false;
    uint8_t tmp_local_nonce[AES_NONCE_BYTES];
    uint8_t tmp_aes_key[HASHES_BYTES];
//======================================================================
// + Security
//======================================================================
// Retry Initialization
//======================================================================
    if (trycount != (uint8_t)1) {
        memcpy(tmp_local_nonce, security->local_nonce, AES_NONCE_BYTES);
        memset(security->local_nonce, 0, AES_NONCE_BYTES);
        memset(security->mac_key, 0, HASHES_BYTES);
    }
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("SIO Receiving Hello3 ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY_CNT) {
            LOG_ERROR("%sHello3 Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->hello3_ack.last_trycount) {
            LOG_ERROR("%sHello3 Try Count Invalid.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
        isretry = true;
        from_retry_timer = false;
    }
//----------------------------------------------------------------------
    session->hello3_ack.last_trycount = trycount;
//======================================================================
    if (!isretry && !from_retry_timer) {
        if (!session->hello2_ack.ack_sent) {
            LOG_ERROR("%sReceive Hello2 But This Worker Session Is Never Sending Hello3_Ack.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
    }
//----------------------------------------------------------------------
    if (isretry) {
        if (session->hello3_ack.data != NULL) {
            //print_hex("SIO Sending Hello3 Ack Retry Response ", session->hello3_ack.data, session->hello3_ack.len, 1);
            if (retry_control_packet_ack(
                    worker_ctx, 
                    identity, 
                    security, 
                    &session->hello3_ack,
                    ORILINK_HELLO3_ACK
                ) != SUCCESS
            )
            {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE;
            }
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
//======================================================================
        memcpy(security->local_nonce, tmp_local_nonce, AES_NONCE_BYTES);
        memset(tmp_local_nonce, 0, AES_NONCE_BYTES);
        kdf1(security->kem_sharedsecret, tmp_aes_key);
        kdf2(tmp_aes_key, security->mac_key);
        memset(tmp_aes_key, 0, HASHES_BYTES);
//----------------------------------------------------------------------
        return SUCCESS;
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
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_hello3_t *ohello3 = received_orilink_protocol->payload.orilink_hello3;
    uint64_t remote_id = ohello3->local_id;
//======================================================================
// + Security
//======================================================================
    if (remote_id != identity->remote_id) {
        LOG_ERROR("%sReceive Different Id Between Hello3 And Hello2_Ack.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    uint8_t local_nonce[AES_NONCE_BYTES];
    if (generate_nonce(worker_ctx->label, local_nonce) != SUCCESS) {
        LOG_ERROR("%sFailed to generate_nonce.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
    session->hello3_ack.ack_sent_try_count++;
    session->hello3_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello3_ack(
        worker_ctx->label,
        l_inc_ctr,
        identity->remote_wot,
        identity->remote_index,
        identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        identity->remote_id,
        local_nonce,
        security->kem_ciphertext,
        session->hello3_ack.ack_sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
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
        return FAILURE;
    }
    //print_hex("SIO Sending Hello3 Ack ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
//======================================================================
// Test Packet Dropped
//======================================================================
    //session->test_drop_hello3_ack++;
    if (
        session->test_drop_hello3_ack == 1
    )
    {
        printf("[Debug Here Helper]: Hello3 Ack Packet Number %d. Sending To Fake Addr To Force Retry\n", session->test_drop_hello3_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HELLO3_ACK,
                session->hello3_ack.ack_sent_try_count,
                &fake_addr, 
                &udp_data, 
                &session->hello3_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
//----------------------------------------------------------------------
// No Error Here
// This Is A Test Drop Packet
//----------------------------------------------------------------------
            /*
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
            */
        }
    } else {
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HELLO3_ACK,
                session->hello3_ack.ack_sent_try_count,
                remote_addr, 
                &udp_data, 
                &session->hello3_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
        }
        if (session->test_drop_hello3_ack >= 1000000) {
            session->test_drop_hello3_ack = 0;
        }
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    memcpy(security->local_nonce, local_nonce, AES_NONCE_BYTES);
    memset(local_nonce, 0, AES_NONCE_BYTES);
    uint8_t aes_key[HASHES_BYTES];
    kdf1(security->kem_sharedsecret, aes_key);
//----------------------------------------------------------------------
// Di Remote COW
// 1. HELLO4 harus sudah pakai mac_key baru
// 2. HELLO4 harus masih memakai aes_key lama
//----------------------------------------------------------------------
    kdf2(aes_key, security->mac_key);
//----------------------------------------------------------------------
    memset(aes_key, 0, HASHES_BYTES);
//======================================================================
    session->hello3_ack.rcvd_time = current_time.r_uint64_t;
    session->hello3_ack.rcvd_ctr = security->remote_ctr;
    uint64_t interval_ull;
    uint8_t strycount;
    if (!session->hello3_ack.rcvd) {
        session->hello3_ack.rcvd = true;
        interval_ull = session->hello3_ack.rcvd_time - session->hello2_ack.ack_sent_time;
        session->hello3_ack.ack_sent_time = session->hello2_ack.ack_sent_time;
        strycount = session->hello2_ack.ack_sent_try_count;
        cleanup_control_packet_ack(&session->hello2_ack, false, CDT_NOACTION);
    } else {
        interval_ull = session->hello3_ack.rcvd_time - session->hello3_ack.ack_sent_time;
        strycount = session->hello3_ack.ack_sent_try_count;
    }
    if (strycount > (uint8_t)0) {
        double try_count = (double)strycount-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    double rtt_value = (double)interval_ull;
    if (rtt_value <= (double)MAX_RETRY_CNT * session->retry.value_prediction) {
        calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    } else {
        double try_count = (double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    printf("%sRTT Hello-2 Ack = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 "\n", worker_ctx->label, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr);
//======================================================================
    session->hello3_ack.ack_sent = true;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_cow_hello2(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    bool isretry = false;
    bool from_retry_timer = false;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("SIO Receiving Hello2 ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY_CNT) {
            LOG_ERROR("%sHello2 Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->hello2_ack.last_trycount) {
            LOG_ERROR("%sHello2 Try Count Invalid.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
        isretry = true;
        from_retry_timer = false;
    }
//----------------------------------------------------------------------
    session->hello2_ack.last_trycount = trycount;
//======================================================================
    if (!isretry && !from_retry_timer) {
        if (!session->hello1_ack.ack_sent) {
            LOG_ERROR("%sReceive Hello2 But This Worker Session Is Never Sending Hello1_Ack.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
    }
//----------------------------------------------------------------------
    if (isretry) {
        if (session->hello2_ack.data != NULL) {
            //print_hex("SIO Sending Hello2 Ack Retry Response ", session->hello2_ack.data, session->hello2_ack.len, 1);
            if (retry_control_packet_ack(
                    worker_ctx, 
                    identity, 
                    security, 
                    &session->hello2_ack,
                    ORILINK_HELLO2_ACK
                ) != SUCCESS
            )
            {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE;
            }
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return SUCCESS;
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
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_hello2_t *ohello2 = received_orilink_protocol->payload.orilink_hello2;
    uint64_t remote_id = ohello2->local_id;
//======================================================================
// + Security
//======================================================================
    if (remote_id != identity->remote_id) {
        LOG_ERROR("%sReceive Different Id Between Hello2 And Hello1_Ack.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
    uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
    memcpy(kem_publickey, security->kem_publickey, KEM_PUBLICKEY_BYTES / 2);
    memcpy(kem_publickey + (KEM_PUBLICKEY_BYTES / 2), ohello2->publickey2, KEM_PUBLICKEY_BYTES / 2);
    if (KEM_ENCODE_SHAREDSECRET(
        kem_ciphertext, 
        kem_sharedsecret, 
        kem_publickey
    ) != 0)
    {
        LOG_ERROR("%sFailed to KEM_ENCODE_SHAREDSECRET.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
    session->hello2_ack.ack_sent_try_count++;
    session->hello2_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello2_ack(
        worker_ctx->label,
        l_inc_ctr,
        identity->remote_wot,
        identity->remote_index,
        identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        identity->remote_id,
        kem_ciphertext,
        session->hello2_ack.ack_sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
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
        return FAILURE;
    }
    //print_hex("SIO Sending Hello2 Ack ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
//======================================================================
// Test Packet Dropped
//======================================================================
    //session->test_drop_hello2_ack++;
    if (
        session->test_drop_hello2_ack == 1
    )
    {
        printf("[Debug Here Helper]: Hello2 Ack Packet Number %d. Sending To Fake Addr To Force Retry\n", session->test_drop_hello2_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HELLO2_ACK,
                session->hello2_ack.ack_sent_try_count,
                &fake_addr, 
                &udp_data, 
                &session->hello2_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
//----------------------------------------------------------------------
// No Error Here
// This Is A Test Drop Packet
//----------------------------------------------------------------------
            /*
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
            */
        }
    } else {
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HELLO2_ACK,
                session->hello2_ack.ack_sent_try_count,
                remote_addr,
                &udp_data, 
                &session->hello2_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
        }
        if (session->test_drop_hello2_ack >= 1000000) {
            session->test_drop_hello2_ack = 0;
        }
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    memcpy(security->kem_publickey + (KEM_PUBLICKEY_BYTES / 2), kem_publickey + (KEM_PUBLICKEY_BYTES / 2), KEM_PUBLICKEY_BYTES / 2);
    memcpy(security->kem_ciphertext, kem_ciphertext, KEM_CIPHERTEXT_BYTES);
    memcpy(security->kem_sharedsecret, kem_sharedsecret, KEM_SHAREDSECRET_BYTES);
    memset(kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
//======================================================================
    session->hello2_ack.rcvd_time = current_time.r_uint64_t;
    session->hello2_ack.rcvd_ctr = security->remote_ctr;
    uint64_t interval_ull;
    uint8_t strycount;
    if (!session->hello2_ack.rcvd) {
        session->hello2_ack.rcvd = true;
        interval_ull = session->hello2_ack.rcvd_time - session->hello1_ack.ack_sent_time;
        session->hello2_ack.ack_sent_time = session->hello1_ack.ack_sent_time;
        strycount = session->hello1_ack.ack_sent_try_count;
        cleanup_control_packet_ack(&session->hello1_ack, false, CDT_NOACTION);
    } else {
        interval_ull = session->hello2_ack.rcvd_time - session->hello2_ack.ack_sent_time;
        strycount = session->hello2_ack.ack_sent_try_count;
    }
    if (strycount > (uint8_t)0) {
        double try_count = (double)strycount-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    printf("%sRTT Hello-1 Ack = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 "\n", worker_ctx->label, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr);
//======================================================================
    session->hello2_ack.ack_sent = true;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_cow_hello1(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    bool isretry = false;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("SIO Receiving Hello1 ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY_CNT) {
            LOG_ERROR("%sHello1 Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->hello1_ack.last_trycount) {
            LOG_ERROR("%sHello1 Try Count Invalid.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
        isretry = true;
    }
//----------------------------------------------------------------------
    session->hello1_ack.last_trycount = trycount;
//----------------------------------------------------------------------
    if (isretry) {
        if (session->hello1_ack.data != NULL) {
            //print_hex("SIO Sending Hello1 Ack Retry Response ", session->hello1_ack.data, session->hello1_ack.len, 1);
            if (retry_control_packet_ack(
                    worker_ctx, 
                    identity, 
                    security, 
                    &session->hello1_ack,
                    ORILINK_HELLO1_ACK
                ) != SUCCESS
            )
            {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE;
            }
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
//----------------------------------------------------------------------
        session->hello1_ack.ack_sent = true;
//----------------------------------------------------------------------
        return SUCCESS;
    }
//======================================================================
    worker_type_t remote_wot;
    uint8_t remote_index;
    uint8_t remote_session_index;
    uint64_t rcvd_id_connection;
    orilink_protocol_t_status_t deserialized_oudp_datao = orilink_deserialize(worker_ctx->label,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n
    );
    if (deserialized_oudp_datao.status != SUCCESS) {
        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_oudp_datao.status);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    } else {
        remote_wot = oudp_datao->local_wot;
        remote_index = oudp_datao->local_index;
        remote_session_index = oudp_datao->local_session_index;
        rcvd_id_connection = oudp_datao->id_connection;
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_hello1_t *ohello1 = received_orilink_protocol->payload.orilink_hello1;
    uint64_t remote_id = ohello1->local_id;
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES / 2];
    memcpy(kem_publickey, ohello1->publickey1, KEM_PUBLICKEY_BYTES / 2);
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
    session->hello1_ack.ack_sent_try_count++;
    session->hello1_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    identity->id_connection = rcvd_id_connection;
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello1_ack(
        worker_ctx->label,
        l_inc_ctr,
        remote_wot,
        remote_index,
        remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        remote_id,
        session->hello1_ack.ack_sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
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
        return FAILURE;
    }
    //print_hex("SIO Sending Hello1 Ack ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
//======================================================================
// Test Packet Dropped
//======================================================================
    //session->test_drop_hello1_ack++;
    if (
        session->test_drop_hello1_ack == 1
    )
    {
        printf("[Debug Here Helper]: Hello1 Ack Packet Number %d. Sending To Fake Addr To Force Retry\n", session->test_drop_hello1_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HELLO1_ACK,
                session->hello1_ack.ack_sent_try_count,
                &fake_addr, 
                &udp_data, 
                &session->hello1_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
//----------------------------------------------------------------------
// No Error Here
// This Is A Test Drop Packet
//----------------------------------------------------------------------
            /*
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
            */
        }
    } else {
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HELLO1_ACK,
                session->hello1_ack.ack_sent_try_count,
                remote_addr, 
                &udp_data, 
                &session->hello1_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
        }
        if (session->test_drop_hello1_ack >= 1000000) {
            session->test_drop_hello1_ack = 0;
        }
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    identity->remote_wot = remote_wot;
    identity->remote_index = remote_index;
    identity->remote_session_index = remote_session_index;
    identity->remote_id = remote_id;
    memcpy(security->kem_publickey, kem_publickey, KEM_PUBLICKEY_BYTES / 2);
    memset(kem_publickey, 0, KEM_PUBLICKEY_BYTES / 2);
//======================================================================
    session->hello1_ack.rcvd = true;
    session->hello1_ack.ack_sent = true;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_sio_heartbeat_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = 0xFF;
    uint32_t trycount = oudp_datao->trycount;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("COW Receiving Heartbeat Ack ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (!session->heartbeat.sent) {
        LOG_ERROR("%sReceive Heartbeat_Ack But This Worker Session Is Never Sending Heartbeat.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    /*
    if (session->heartbeat.ack_rcvd) {
        LOG_ERROR("%sHeartbeat_Ack Received Already.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    */
//======================================================================
    bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
    if (_1l_) {
        if (session->heartbeat.sent_try_count != 0x01) {
            LOG_ERROR("%sPeer's Counter Is Lower.", worker_ctx->label);
            session->greater_counter = true;
        } else {
            LOG_ERROR("%s XXX - Peer's Counter Is Lower.", worker_ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    } else {
        bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (!_same_) {
            bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (_1g_) {
                LOG_ERROR("%sPeer's Counter Is Greater.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE;
            } else {
                bool igc = false;
                if (session->greater_counter) {
                    igc = is_gc_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce);
                }
                if (igc) {
                    session->greater_counter = false;
                    session->heartbeat.ack_rcvd = true;
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return SUCCESS;
                } else {
                    LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return FAILURE;
                }
            }
        }
    }
//======================================================================
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
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
    //async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
    //CLOSE_FD(&session->heartbeat_sender_timer_fd);
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
// 
//----------------------------------------------------------------------
    if (session->heartbeat.sent_try_count > (uint8_t)0) {
        double try_count = (double)session->heartbeat.sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    session->heartbeat.ack_rcvd_time = current_time.r_uint64_t;
    session->heartbeat.ack_rcvd_ctr = security->remote_ctr;
    uint64_t interval_ull = session->heartbeat.ack_rcvd_time - session->heartbeat.sent_time;
    double rtt_value = (double)interval_ull;
    if (rtt_value <= (double)MAX_RETRY_CNT * session->retry.value_prediction) {
        calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    } else {
        double try_count = (double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    char timebuf[32];
    get_time_str(timebuf, sizeof(timebuf));
    printf("%s%s - RTT Heartbeat = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 ", trycount %d, rcvd ctr %" PRIu32 " \n", worker_ctx->label, timebuf, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr, trycount, session->heartbeat.ack_rcvd_ctr);
//======================================================================
    session->heartbeat.ack_rcvd = true;
//======================================================================
    //session->metrics.last_ack = current_time.r_uint64_t;
    //session->metrics.count_ack += (double)1;
    //session->metrics.sum_hb_interval += session->heartbeat_interval;
    //session->metrics.hb_interval = session->heartbeat_interval;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_sio_heartbeat(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = 0xFF;
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    bool isretry = false;
    bool from_retry_timer = false;
    bool isgc = false;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        LOG_ERROR("%sError orilink_check_mac.", worker_ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("COW Receiving Heartbeat ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY_CNT) {
            LOG_ERROR("%sHeartbeat Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->heartbeat_ack.last_trycount) {
            LOG_ERROR("%sHeartbeat Try Count Invalid Last: %d, Rcvd: %d.", worker_ctx->label, session->heartbeat_ack.last_trycount, trycount);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
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
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return FAILURE;
                } else {
                    bool igc = is_gc_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce);
                    if (igc) {
                        isgc = true;
                    } else {
                        LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                        return FAILURE;
                    }
                }
            } else {
                LOG_DEVEL_DEBUG("%sHeartbeat From Peer's Retry Timer", worker_ctx->label);
                from_retry_timer = true;
            }
        }
    }
//----------------------------------------------------------------------
    session->heartbeat_ack.last_trycount = trycount;
//======================================================================
    if (!isretry && !from_retry_timer) {
        if (!session->heartbeat_ack.ack_sent) {
            LOG_ERROR("%sReceive Heartbeat But This Worker Session Is Never Sending Heartbeat_Ack.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (_1l_) {
            LOG_ERROR("%sHeartbeat With Lower Counter.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        } else {
            bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (!_same_) {
                bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
                if (_1g_) {
                    LOG_ERROR("%sHeartbeat With Greater Counter.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return FAILURE;
                } else {
                    bool igc = is_gc_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce);
                    if (igc) {
                        isgc = true;
                    } else {
                        LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                        return FAILURE;
                    }
                }
            }
        }
    }
    if (isgc) {
        LOG_ERROR("%sWe Have To Initiate New Heartbeat When ready.", worker_ctx->label);
        uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
        if (current_time.status != SUCCESS) {
            LOG_ERROR("%sError get_monotonic_time_ns.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        session->heartbeat_ack.ack_sent_try_count++;
        session->heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
        l_inc_ctr = 0x01;
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
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            LOG_ERROR("%sError orilink_prepare_cmd_heartbeat_ack.", worker_ctx->label);
            return FAILURE;
        }
        uint32_t hgc = 0xffffffff;
        uint8_t hgn[AES_NONCE_BYTES];
        memcpy(hgn, security->local_nonce, AES_NONCE_BYTES);
        puint8_t_size_t_status_t udp_data = create_orilink_raw_protocol_packet(
            worker_ctx->label,
            security->aes_key,
            security->mac_key,
            hgn,
            &hgc,
            orilink_cmd_result.r_orilink_protocol_t
        );
        CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
        if (udp_data.status != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            LOG_ERROR("%sError create_orilink_raw_protocol_packet.", worker_ctx->label);
            return FAILURE;
        }
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HEARTBEAT_ACK,
                session->heartbeat_ack.ack_sent_try_count,
                remote_addr, 
                &udp_data, 
                &session->heartbeat_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            LOG_ERROR("%sError worker_master_udp_data_ack.", worker_ctx->label);
            return FAILURE;
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        if (session->heartbeat_ack.ack_sent_try_count > (uint8_t)0) {
            double try_count = (double)session->heartbeat_ack.ack_sent_try_count-(double)1;
            calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
        }
        cleanup_control_packet_ack(&session->heartbeat_ack, false, CDT_NOACTION);
        session->heartbeat.sent = false;
        session->heartbeat_ack.ack_sent = false;
        return SUCCESS;
    }
//----------------------------------------------------------------------
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        LOG_ERROR("%sError orilink_read_header.", worker_ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------
    inc_ctr = oudp_datao->inc_ctr;
//----------------------------------------------------------------------
    if (isretry) {
        if (session->heartbeat_ack.data != NULL) {
            //print_hex("COW Sending Heartbeat Ack Retry Response ", session->heartbeat_ack.data, session->heartbeat_ack.len, 1);
            if (retry_control_packet_ack(
                    worker_ctx, 
                    identity, 
                    security, 
                    &session->heartbeat_ack,
                    ORILINK_HEARTBEAT_ACK
                ) != SUCCESS
            )
            {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                LOG_ERROR("%sError retry_control_packet_ack.", worker_ctx->label);
                return FAILURE;
            }
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return SUCCESS;
    }
//======================================================================
    if (!session->heartbeat.ack_rcvd) {
        LOG_ERROR("%sTry Again Until My Previous Heartbeat Ack Received.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
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
    if (session->heartbeat_interval < (double)0.001) {
        session->heartbeat_interval = (double)0.001;
    }
    if (session->heartbeat_interval > (double)100) {
        session->heartbeat_interval = (double)100;
    }
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        LOG_ERROR("%sError get_monotonic_time_ns.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    session->heartbeat_ack.ack_sent_try_count++;
    session->heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
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
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        LOG_ERROR("%sError orilink_prepare_cmd_heartbeat_ack.", worker_ctx->label);
        return FAILURE;
    }
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
        LOG_ERROR("%sError create_orilink_raw_protocol_packet.", worker_ctx->label);
        return FAILURE;
    }
    //print_hex("COW Sending Heartbeat Ack ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
//======================================================================
// Test Packet Dropped
//======================================================================
    //session->test_drop_heartbeat_ack++;
    if (
        session->test_drop_heartbeat_ack == 1 ||
        session->test_drop_heartbeat_ack == 3 ||
        session->test_drop_heartbeat_ack == 5 ||
        session->test_drop_heartbeat_ack == 7
    )
    {
        LOG_DEVEL_DEBUG("[Debug Here Helper]: Heartbeat Ack Packet Number %d. Sending To Fake Addr To Force Retry", session->test_drop_heartbeat_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HEARTBEAT_ACK,
                session->heartbeat_ack.ack_sent_try_count,
                &fake_addr, 
                &udp_data, 
                &session->heartbeat_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
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
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HEARTBEAT_ACK,
                session->heartbeat_ack.ack_sent_try_count,
                remote_addr, 
                &udp_data, 
                &session->heartbeat_ack,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr
            ) != SUCCESS
        )
        {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            if (inc_ctr != 0xFF) {
                decrement_ctr(&security->remote_ctr, security->remote_nonce);
            }
            if (l_inc_ctr != 0xFF) {
                decrement_ctr(&security->local_ctr, security->local_nonce);
            }
            LOG_ERROR("%sError worker_master_udp_data_ack.", worker_ctx->label);
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
    if (session->heartbeat_ack.ack_sent_try_count > (uint8_t)0) {
        double try_count = (double)session->heartbeat_ack.ack_sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    cleanup_control_packet_ack(&session->heartbeat_ack, false, CDT_NOACTION);
    session->heartbeat.sent = false;
//----------------------------------------------------------------------
// Set session->heartbeat_ack.ack_sent = true; In Heartbeat Openner
//----------------------------------------------------------------------
    session->heartbeat_ack.ack_sent = false;
//======================================================================
//session->metrics.last_ack = current_time->r_uint64_t;
//session->metrics.count_ack += (double)1;
//session->metrics.sum_hb_interval += session->heartbeat_interval;
//session->metrics.hb_interval = session->heartbeat_interval;
//======================================================================
    double timer_interval = session->heartbeat_interval;
//======================================================================
    status_t chst = create_timer_oneshot(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd, timer_interval);
    if (chst != SUCCESS) {
        return FAILURE;
    }
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_sio_hello4_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t l_inc_ctr = 0xFF;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("COW Receiving Hello4 Ack ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (!session->hello4.sent) {
        LOG_ERROR("%sReceive Hello4_Ack But This Worker Session Is Never Sending Hello4.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    /*
    if (session->hello4.ack_rcvd) {
        LOG_ERROR("%sHello4_Ack Received Already.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    */
//----------------------------------------------------------------------
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
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
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_hello4_ack_t *ohello4_ack = received_orilink_protocol->payload.orilink_hello4_ack;
//======================================================================
// Ambil remote_nonce
// Set remote_ctr = 0
// Ambil encrypter wot+index
// Ambil Mac
// Cocokkan MAc
// Decrypt wot dan index
//======================================================================
    uint32_t remote_ctr = (uint32_t)0;
    uint8_t encrypted_local_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];   
    memcpy(encrypted_local_identity, ohello4_ack->encrypted_remote_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    uint8_t data_mac0[AES_TAG_BYTES];
    memcpy(data_mac0, ohello4_ack->encrypted_remote_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// Tmp aes_key
//----------------------------------------------------------------------
    uint8_t aes_key[HASHES_BYTES];
    kdf1(security->kem_sharedsecret, aes_key);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
    const size_t data_len_0 = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    if (compare_mac(
            security->mac_key,
            encrypted_local_identity,
            data_len_0,
            data_mac0
        ) != SUCCESS
    )
    {
        LOG_ERROR("%sORILINK Hello4 Ack Mac mismatch!", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
    uint8_t decrypted_local_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    const size_t data_len = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            security->remote_nonce,
            &remote_ctr,
            encrypted_local_identity,
            decrypted_local_identity,
            data_len
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
// + Security
//======================================================================
    worker_type_t data_wot0;
    memcpy((uint8_t *)&data_wot0, decrypted_local_identity, sizeof(uint8_t));
    if (*(uint8_t *)&identity->local_wot != *(uint8_t *)&data_wot0) {
        LOG_ERROR("%sberbeda wot %d <=> %d. Worker error...", worker_ctx->label, data_wot0, identity->local_wot);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    uint8_t data_index0;
    memcpy(&data_index0, decrypted_local_identity + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->local_index != data_index0) {
        LOG_ERROR("%sberbeda index. Worker error...", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    uint8_t data_session_index0;
    memcpy(&data_session_index0, decrypted_local_identity + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->local_session_index != data_session_index0) {
        LOG_ERROR("%sberbeda session_index.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }      
    uint64_t local_id_be;
    memcpy(&local_id_be, decrypted_local_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint64_t));
    uint64_t local_id = be64toh(local_id_be);
    if (local_id != identity->local_id) {
        LOG_ERROR("%sberbeda id.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    uint8_t encrypted_remote_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];   
    memcpy(encrypted_remote_identity, ohello4_ack->encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    uint8_t data_mac1[AES_TAG_BYTES];
    memcpy(data_mac1, ohello4_ack->encrypted_local_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
    if (compare_mac(
            security->mac_key,
            encrypted_remote_identity,
            data_len_0,
            data_mac1
        ) != SUCCESS
    )
    {
        LOG_ERROR("%sORILINK Hello4 Ack Mac mismatch!", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
    uint8_t decrypted_remote_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            security->remote_nonce,
            &remote_ctr,
            encrypted_remote_identity,
            decrypted_remote_identity,
            data_len
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
// Mencocokkan wot index
//----------------------------------------------------------------------
    worker_type_t data_wot1;
    memcpy((uint8_t *)&data_wot1, decrypted_remote_identity, sizeof(uint8_t));
    if (*(uint8_t *)&identity->remote_wot != *(uint8_t *)&data_wot1) {
        LOG_ERROR("%sberbeda wot %d <=> %d. Worker error...", worker_ctx->label, data_wot1, identity->local_wot);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    uint8_t data_index1;
    memcpy(&data_index1, decrypted_remote_identity + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->remote_index != data_index1) {
        LOG_ERROR("%sberbeda index. Worker error...", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    uint8_t data_session_index1;
    memcpy(&data_session_index1, decrypted_remote_identity + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->remote_session_index != data_session_index1) {
        LOG_ERROR("%sberbeda session_index.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    uint64_t remote_id_be;
    memcpy(&remote_id_be, decrypted_remote_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint64_t));
    uint64_t remote_id = be64toh(remote_id_be);
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    session->heartbeat.sent_try_count++;
    session->heartbeat.sent_time = current_time.r_uint64_t;
//======================================================================
    double hb_interval = node_hb_interval_with_jitter(session->rtt.value_prediction, session->retry.value_prediction);
    session->heartbeat_interval = hb_interval;
    printf("%sSend HB Interval %f\n", worker_ctx->label, hb_interval);
//======================================================================
    l_inc_ctr = 0x01;
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
        remote_id,
        hb_interval,
        session->heartbeat.sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    puint8_t_size_t_status_t udp_data = create_orilink_raw_protocol_packet(
        worker_ctx->label,
        aes_key,
        security->mac_key,
        security->local_nonce,
        &security->local_ctr,
        orilink_cmd_result.r_orilink_protocol_t
    );
    CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
    if (udp_data.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (l_inc_ctr != 0xFF) {
            decrement_ctr(&security->local_ctr, security->local_nonce);
        }
        return FAILURE;
    }
    if (worker_master_udp_data(
            worker_ctx->label, 
            worker_ctx, 
            identity->local_wot, 
            identity->local_index, 
            identity->local_session_index, 
            (uint8_t)ORILINK_HEARTBEAT,
            session->heartbeat.sent_try_count,
            remote_addr, 
            &udp_data, 
            &session->heartbeat,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (l_inc_ctr != 0xFF) {
            decrement_ctr(&security->local_ctr, security->local_nonce);
        }
        return FAILURE;
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    memcpy(security->aes_key, aes_key, HASHES_BYTES);
    memset(aes_key, 0, HASHES_BYTES);
    identity->remote_id = remote_id;
    security->remote_ctr = remote_ctr;
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
// 
//----------------------------------------------------------------------
    if (session->hello4.sent_try_count > (uint8_t)0) {
        double try_count = (double)session->hello4.sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
//======================================================================
    session->hello4.ack_rcvd_time = current_time.r_uint64_t;
    session->hello4.ack_rcvd_ctr = security->remote_ctr;
    uint64_t interval_ull = session->hello4.ack_rcvd_time - session->hello4.sent_time;
    double rtt_value = (double)interval_ull;
    if (rtt_value <= (double)MAX_RETRY_CNT * session->retry.value_prediction) {
        calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    } else {
        double try_count = (double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    printf("%sRTT Hello-4 = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 "\n", worker_ctx->label, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr);
//======================================================================
    session->hello4.ack_rcvd = true;
//======================================================================
// Heartbeat Ack Security 1 & Security 2 Open
//======================================================================
    session->heartbeat.sent = true;
    session->heartbeat.ack_rcvd = false;
//======================================================================
// Heartbeat Security 1 & Security 2 Open
//======================================================================
    session->heartbeat_ack.ack_sent = true;
    session->heartbeat_ack.rcvd = false;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_sio_hello3_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t l_inc_ctr = 0xFF;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("COW Receiving Hello3 Ack ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (!session->hello3.sent) {
        LOG_ERROR("%sReceive Hello3_Ack But This Worker Session Is Never Sending Hello3.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    /*
    if (session->hello3.ack_rcvd) {
        LOG_ERROR("%sHello3_Ack Received Already.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    */
//----------------------------------------------------------------------
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
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
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_hello3_ack_t *ohello3_ack = received_orilink_protocol->payload.orilink_hello3_ack;
    uint64_t local_id = ohello3_ack->remote_id;
//======================================================================
// + Security
//======================================================================
    if (local_id != identity->local_id) {
        LOG_ERROR("%sReceive Different Id Between Hello3_Ack And Hello3.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    uint8_t remote_nonce[AES_NONCE_BYTES];
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
    uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
    uint8_t aes_key[HASHES_BYTES];
    uint8_t mac_key[HASHES_BYTES];
    uint8_t local_nonce[AES_NONCE_BYTES];
    uint32_t local_ctr = (uint32_t)0;
    memcpy(remote_nonce, ohello3_ack->nonce, AES_NONCE_BYTES);
    memcpy(kem_ciphertext, security->kem_ciphertext, KEM_CIPHERTEXT_BYTES / 2);
    memcpy(kem_ciphertext + (KEM_CIPHERTEXT_BYTES / 2), ohello3_ack->ciphertext2, KEM_CIPHERTEXT_BYTES / 2);
    if (KEM_DECODE_SHAREDSECRET(kem_sharedsecret, kem_ciphertext, session->kem_privatekey) != 0) {
        LOG_ERROR("%sFailed to KEM_DECODE_SHAREDSECRET.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
// Temporary Key
//----------------------------------------------------------------------
    kdf1(kem_sharedsecret, aes_key);
    if (generate_nonce(worker_ctx->label, local_nonce) != SUCCESS) {
        LOG_ERROR("%sFailed to generate_nonce.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
// HELLO4 Memakai mac_key baru
//----------------------------------------------------------------------
    kdf2(aes_key, mac_key);
//----------------------------------------------------------------------
    uint8_t local_identity[
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    uint8_t encrypted_local_identity[
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];   
    uint8_t encrypted_local_identity1[
        AES_NONCE_BYTES +
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    uint8_t encrypted_local_identity2[
        AES_NONCE_BYTES +
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t) +
        AES_TAG_BYTES
    ];
    memcpy(encrypted_local_identity1, local_nonce, AES_NONCE_BYTES);
    memcpy(
        local_identity, 
        (uint8_t *)&identity->local_wot, 
        sizeof(uint8_t)
    );
    memcpy(
        local_identity + sizeof(uint8_t), 
        (uint8_t *)&identity->local_index, 
        sizeof(uint8_t)
    );
    memcpy(
        local_identity + sizeof(uint8_t) + sizeof(uint8_t), 
        (uint8_t *)&identity->local_session_index, 
        sizeof(uint8_t)
    );
    uint64_t local_id_be = htobe64(identity->local_id);
    memcpy(
        local_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), 
        &local_id_be, 
        sizeof(uint64_t)
    );
//======================================================================    
    const size_t data_len = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            local_nonce,
            &local_ctr,
            local_identity,
            encrypted_local_identity,
            data_len
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================    
    memcpy(encrypted_local_identity1 + AES_NONCE_BYTES, encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
//======================================================================
    uint8_t mac[AES_TAG_BYTES];
    const size_t data_4mac_len = AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    calculate_mac(mac_key, encrypted_local_identity1, mac, data_4mac_len);
//====================================================================== 
    memcpy(encrypted_local_identity2, encrypted_local_identity1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    memcpy(encrypted_local_identity2 + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), mac, AES_TAG_BYTES);
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    session->hello4.sent_try_count++;
    session->hello4.sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello4(
        worker_ctx->label,
        l_inc_ctr,
        identity->remote_wot,
        identity->remote_index,
        identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        encrypted_local_identity2,
        session->hello4.sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    puint8_t_size_t_status_t udp_data = create_orilink_raw_protocol_packet(
        worker_ctx->label,
        security->aes_key,
        mac_key,
        security->local_nonce,
        &security->local_ctr,
        orilink_cmd_result.r_orilink_protocol_t
    );
    CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
    if (udp_data.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    if (worker_master_udp_data(
            worker_ctx->label, 
            worker_ctx, 
            identity->local_wot, 
            identity->local_index, 
            identity->local_session_index, 
            (uint8_t)ORILINK_HELLO4,
            session->hello4.sent_try_count,
            remote_addr, 
            &udp_data, 
            &session->hello4,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    memcpy(security->remote_nonce, remote_nonce, AES_NONCE_BYTES);
    memcpy(security->kem_ciphertext + (KEM_CIPHERTEXT_BYTES / 2), kem_ciphertext + (KEM_CIPHERTEXT_BYTES / 2), KEM_CIPHERTEXT_BYTES / 2);
    memcpy(security->kem_sharedsecret, kem_sharedsecret, KEM_SHAREDSECRET_BYTES);
    memcpy(security->mac_key, mac_key, HASHES_BYTES);
    memcpy(security->local_nonce, local_nonce, AES_NONCE_BYTES);
    security->local_ctr = local_ctr;
    memset(remote_nonce, 0, AES_NONCE_BYTES);
    memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    memset(aes_key, 0, HASHES_BYTES);
    memset(mac_key, 0, HASHES_BYTES);
    memset(local_nonce, 0, AES_NONCE_BYTES);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
// 
//----------------------------------------------------------------------
    if (session->hello3.sent_try_count > (uint8_t)0) {
        double try_count = (double)session->hello3.sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
//======================================================================
    session->hello3.ack_rcvd_time = current_time.r_uint64_t;
    session->hello3.ack_rcvd_ctr = security->remote_ctr;
    uint64_t interval_ull = session->hello3.ack_rcvd_time - session->hello3.sent_time;
    double rtt_value = (double)interval_ull;
    if (rtt_value <= (double)MAX_RETRY_CNT * session->retry.value_prediction) {
        calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    } else {
        double try_count = (double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    printf("%sRTT Hello-3 = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 "\n", worker_ctx->label, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr);
//======================================================================
    session->hello3.ack_rcvd = true;
//======================================================================
    session->hello4.sent = true;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_sio_hello2_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t l_inc_ctr = 0xFF;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("COW Receiving Hello2 Ack ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (!session->hello2.sent) {
        LOG_ERROR("%sReceive Hello2_Ack But This Worker Session Is Never Sending Hello2.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    /*
    if (session->hello2.ack_rcvd) {
        LOG_ERROR("%sHello2_Ack Received Already.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    */
//----------------------------------------------------------------------
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
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
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_hello2_ack_t *ohello2_ack = received_orilink_protocol->payload.orilink_hello2_ack;
    uint64_t local_id = ohello2_ack->remote_id;
//======================================================================
// + Security
//======================================================================
    if (local_id != identity->local_id) {
        LOG_ERROR("%sReceive Different Id Between Hello2_Ack And Hello2.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES / 2];
    memcpy(kem_ciphertext, ohello2_ack->ciphertext1, KEM_CIPHERTEXT_BYTES / 2);
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    session->hello3.sent_try_count++;
    session->hello3.sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello3(
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
        session->hello3.sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
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
        return FAILURE;
    }
    if (worker_master_udp_data(
            worker_ctx->label, 
            worker_ctx, 
            identity->local_wot, 
            identity->local_index, 
            identity->local_session_index, 
            (uint8_t)ORILINK_HELLO3,
            session->hello3.sent_try_count,
            remote_addr, 
            &udp_data, 
            &session->hello3,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    memcpy(security->kem_ciphertext, kem_ciphertext, KEM_CIPHERTEXT_BYTES / 2);
    memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES / 2);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
// 
//----------------------------------------------------------------------
    if (session->hello2.sent_try_count > (uint8_t)0) {
        double try_count = (double)session->hello2.sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
//======================================================================
    session->hello2.ack_rcvd_time = current_time.r_uint64_t;
    session->hello2.ack_rcvd_ctr = security->remote_ctr;
    uint64_t interval_ull = session->hello2.ack_rcvd_time - session->hello2.sent_time;
    double rtt_value = (double)interval_ull;
    if (rtt_value <= (double)MAX_RETRY_CNT * session->retry.value_prediction) {
        calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    } else {
        double try_count = (double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    printf("%sRTT Hello-2 = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 "\n", worker_ctx->label, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr);
//======================================================================
    session->hello2.ack_rcvd = true;
//======================================================================
    session->hello3.sent = true;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_sio_hello1_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t l_inc_ctr = 0xFF;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("COW Receiving Hello1 Ack ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (!session->hello1.sent) {
        LOG_ERROR("%sReceive Hello1_Ack But This Worker Session Is Never Sending Hello1.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    /*
    if (session->hello1.ack_rcvd) {
        LOG_ERROR("%sHello1_Ack Received Already.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    */
//----------------------------------------------------------------------
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//======================================================================
    worker_type_t remote_wot;
    uint8_t remote_index;
    uint8_t remote_session_index;
    orilink_protocol_t_status_t deserialized_oudp_datao = orilink_deserialize(worker_ctx->label,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n
    );
    if (deserialized_oudp_datao.status != SUCCESS) {
        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_oudp_datao.status);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    } else {
        remote_wot = oudp_datao->local_wot;
        remote_index = oudp_datao->local_index;
        remote_session_index = oudp_datao->local_session_index;
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_hello1_ack_t *ohello1_ack = received_orilink_protocol->payload.orilink_hello1_ack;
    uint64_t local_id = ohello1_ack->remote_id;
//======================================================================
// + Security
//======================================================================
    if (local_id != identity->local_id) {
        LOG_ERROR("%sReceive Different Id Between Hello1_Ack And Hello1.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    session->hello2.sent_try_count++;
    session->hello2.sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello2(
        worker_ctx->label,
        l_inc_ctr,
        remote_wot,
        remote_index,
        remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        identity->local_id,
        security->kem_publickey,
        session->hello2.sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
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
        return FAILURE;
    }
    if (worker_master_udp_data(
            worker_ctx->label, 
            worker_ctx, 
            identity->local_wot, 
            identity->local_index, 
            identity->local_session_index, 
            (uint8_t)ORILINK_HELLO2,
            session->hello2.sent_try_count,
            remote_addr, 
            &udp_data, 
            &session->hello2,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    identity->remote_wot = remote_wot;
    identity->remote_index = remote_index;
    identity->remote_session_index = remote_session_index;
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
// 
//----------------------------------------------------------------------
    if (session->hello1.sent_try_count > (uint8_t)0) {
        double try_count = (double)session->hello1.sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
//======================================================================
    session->hello1.ack_rcvd_time = current_time.r_uint64_t;
    session->hello1.ack_rcvd_ctr = security->remote_ctr;
    uint64_t interval_ull = session->hello1.ack_rcvd_time - session->hello1.sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    printf("%sRTT Hello-1 = %lf ms, Remote Ctr %" PRIu32 ", Local Ctr %" PRIu32 "\n", worker_ctx->label, session->rtt.value_prediction / 1e6, session->security.remote_ctr, session->security.local_ctr);
//======================================================================
    session->hello1.ack_rcvd = true;
//======================================================================
    session->hello2.sent = true;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_sio(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol) {
    ipc_udp_data_t *iudp_datai = received_protocol->payload.ipc_udp_data;
    uint8_t session_index = iudp_datai->session_index;
    cow_c_session_t *cow_c_session = (cow_c_session_t *)worker_sessions;
    cow_c_session_t *session = &cow_c_session[session_index];
    orilink_identity_t *identity = &session->identity;
    orilink_security_t *security = &session->security;
//----------------------------------------------------------------------
    struct sockaddr_in6 remote_addr;
    memcpy(&remote_addr, &iudp_datai->remote_addr, sizeof(struct sockaddr_in6));
//----------------------------------------------------------------------
    orilink_raw_protocol_t *oudp_datao = (orilink_raw_protocol_t*)calloc(1, sizeof(orilink_raw_protocol_t));
    if (!oudp_datao) {
        LOG_ERROR("%sFailed to allocate orilink_raw_protocol_t. %s", worker_ctx->label, strerror(errno));
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE_NOMEM;
    }
    if (udp_data_to_orilink_raw_protocol_packet(worker_ctx->label, iudp_datai, oudp_datao) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    switch (oudp_datao->type) {
        case ORILINK_HELLO1_ACK: {
            if (handle_workers_ipc_udp_data_sio_hello1_ack(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HELLO2_ACK: {
            if (handle_workers_ipc_udp_data_sio_hello2_ack(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HELLO3_ACK: {
            if (handle_workers_ipc_udp_data_sio_hello3_ack(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HELLO4_ACK: {
            if (handle_workers_ipc_udp_data_sio_hello4_ack(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HEARTBEAT: {
            if (handle_workers_ipc_udp_data_sio_heartbeat(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HEARTBEAT_ACK: {
            if (handle_workers_ipc_udp_data_sio_heartbeat_ack(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        default:
            LOG_ERROR("%sUnknown ORILINK protocol type %d from Remote SIO-%d[%d]. Ignoring.", worker_ctx->label, oudp_datao->type, oudp_datao->local_index, oudp_datao->local_session_index);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_cow(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol) {
    ipc_udp_data_t *iudp_datai = received_protocol->payload.ipc_udp_data;
    uint8_t session_index = iudp_datai->session_index;
    sio_c_session_t *sio_c_session = (sio_c_session_t *)worker_sessions;
    sio_c_session_t *session = &sio_c_session[session_index];
    orilink_identity_t *identity = &session->identity;
    orilink_security_t *security = &session->security;
//----------------------------------------------------------------------
    struct sockaddr_in6 remote_addr;
    memcpy(&remote_addr, &iudp_datai->remote_addr, sizeof(struct sockaddr_in6));
//----------------------------------------------------------------------
    orilink_raw_protocol_t *oudp_datao = (orilink_raw_protocol_t*)calloc(1, sizeof(orilink_raw_protocol_t));
    if (!oudp_datao) {
        LOG_ERROR("%sFailed to allocate orilink_raw_protocol_t. %s", worker_ctx->label, strerror(errno));
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE_NOMEM;
    }
    if (udp_data_to_orilink_raw_protocol_packet(worker_ctx->label, iudp_datai, oudp_datao) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    switch (oudp_datao->type) {
        case ORILINK_HELLO1: {
            if (handle_workers_ipc_udp_data_cow_hello1(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HELLO2: {
            if (handle_workers_ipc_udp_data_cow_hello2(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HELLO3: {
            if (handle_workers_ipc_udp_data_cow_hello3(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HELLO4: {
            if (handle_workers_ipc_udp_data_cow_hello4(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HEARTBEAT: {
            if (handle_workers_ipc_udp_data_cow_heartbeat(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HEARTBEAT_ACK: {
            if (handle_workers_ipc_udp_data_cow_heartbeat_ack(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        default:
            LOG_ERROR("%sUnknown ORILINK protocol type %d from Remote COW-%d[%d]. Ignoring.", worker_ctx->label, oudp_datao->type, oudp_datao->local_index, oudp_datao->local_session_index);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data(worker_context_t *worker_ctx, void *worker_sessions, ipc_raw_protocol_t_status_t *ircvdi) {
    worker_type_t remote_wot = UNKNOWN;
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
        worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    } else {
        remote_wot = ircvdi->r_ipc_raw_protocol_t->wot;
        LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t *received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    switch (remote_wot) {
//----------------------------------------------------------------------
// UDP Data From Remote COW
//----------------------------------------------------------------------
        case COW: {
            if (handle_workers_ipc_udp_data_cow(worker_ctx, worker_sessions, received_protocol) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
//----------------------------------------------------------------------
// UDP Data From Remote SIO
//----------------------------------------------------------------------
        case SIO: {
            if (handle_workers_ipc_udp_data_sio(worker_ctx, worker_sessions, received_protocol) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
//----------------------------------------------------------------------
        default:
            LOG_ERROR("%sUnknown Source. UDP Remote Worker %d. Ignoring.", worker_ctx->label, remote_wot);
            CLOSE_IPC_PROTOCOL(&received_protocol);
    }
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_ack_cow(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol) {
    ipc_udp_data_ack_t *iudp_data_acki = received_protocol->payload.ipc_udp_data_ack;
    uint8_t index = received_protocol->index;
    uint8_t session_index = iudp_data_acki->session_index;
    cow_c_session_t *cow_c_session = (cow_c_session_t *)worker_sessions;
    cow_c_session_t *session = &cow_c_session[session_index];
    double retry_timer_interval = retry_interval_with_jitter(session->retry.value_prediction);
    switch ((orilink_protocol_type_t)iudp_data_acki->orilink_protocol) {
        case ORILINK_HELLO1: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                if (create_polling_1ms(worker_ctx, &session->hello1, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO2: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                if (create_polling_1ms(worker_ctx, &session->hello2, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO3: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                if (create_polling_1ms(worker_ctx, &session->hello3, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO4: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                if (create_polling_1ms(worker_ctx, &session->hello4, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HEARTBEAT: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                if (create_polling_1ms(worker_ctx, &session->heartbeat, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
                if (create_timer_oneshot(worker_ctx->label, &worker_ctx->async, &session->heartbeat_openner_timer_fd, session->heartbeat_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HEARTBEAT_ACK: {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        default:
            LOG_ERROR("%sUnknown ORILINK protocol type %d From Master To COW-%d[%d]. Ignoring.", worker_ctx->label, (orilink_protocol_type_t)iudp_data_acki->orilink_protocol, index, session_index);
            CLOSE_IPC_PROTOCOL(&received_protocol);
    }
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_ack_sio(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol) {
    ipc_udp_data_ack_t *iudp_data_acki = received_protocol->payload.ipc_udp_data_ack;
    uint8_t index = received_protocol->index;
    uint8_t session_index = iudp_data_acki->session_index;
    sio_c_session_t *sio_c_session = (sio_c_session_t *)worker_sessions;
    sio_c_session_t *session = &sio_c_session[session_index];
    double retry_timer_interval = retry_interval_with_jitter(session->retry.value_prediction);
    switch ((orilink_protocol_type_t)iudp_data_acki->orilink_protocol) {
        case ORILINK_HELLO1_ACK: {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO2_ACK: {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO3_ACK: {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO4_ACK: {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HEARTBEAT: {
            if (iudp_data_acki->trycount == (uint8_t)1) {
//======================================================================
                if (create_polling_1ms(worker_ctx, &session->heartbeat, retry_timer_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
                if (create_timer_oneshot(worker_ctx->label, &worker_ctx->async, &session->heartbeat_openner_timer_fd, session->heartbeat_interval) != SUCCESS) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
//======================================================================
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HEARTBEAT_ACK: {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        default:
            LOG_ERROR("%sUnknown ORILINK protocol type %d From Master To SIO-%d[%d]. Ignoring.", worker_ctx->label, (orilink_protocol_type_t)iudp_data_acki->orilink_protocol, index, session_index);
            CLOSE_IPC_PROTOCOL(&received_protocol);
    }
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_ack(worker_context_t *worker_ctx, void *worker_sessions, ipc_raw_protocol_t_status_t *ircvdi) {
    worker_type_t rcvd_wot = UNKNOWN;
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
        worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    } else {
        rcvd_wot = ircvdi->r_ipc_raw_protocol_t->wot;
        LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t *received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    switch (rcvd_wot) {
//----------------------------------------------------------------------
// UDP Data Ack For COW
//----------------------------------------------------------------------
        case COW: {
            if (handle_workers_ipc_udp_data_ack_cow(worker_ctx, worker_sessions, received_protocol) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
//----------------------------------------------------------------------
// UDP Data Ack For SIO
//----------------------------------------------------------------------
        case SIO: {
            if (handle_workers_ipc_udp_data_ack_sio(worker_ctx, worker_sessions, received_protocol) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
//----------------------------------------------------------------------
        default:
            LOG_ERROR("%sUnknown Source. UDP Remote Worker %d. Ignoring.", worker_ctx->label, rcvd_wot);
            CLOSE_IPC_PROTOCOL(&received_protocol);
    }
    return SUCCESS;
}

status_t handle_workers_ipc_event(worker_context_t *worker_ctx, void *worker_sessions, double *initial_delay_ms) {
    ipc_raw_protocol_t_status_t ircvdi = receive_ipc_raw_protocol_message(worker_ctx->label, worker_ctx->master_uds_fd);
    if (ircvdi.status != SUCCESS) {
        LOG_ERROR("%sError receiving or deserializing IPC message from Master: %d", worker_ctx->label, ircvdi.status);
        return ircvdi.status;
    }
    if (ipc_check_mac(
            worker_ctx->label,
            worker_ctx->mac_key, 
            ircvdi.r_ipc_raw_protocol_t
        ) != SUCCESS
    )
    {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
    if (ipc_read_header(
            worker_ctx->label, 
            worker_ctx->mac_key, 
            worker_ctx->remote_nonce, 
            ircvdi.r_ipc_raw_protocol_t
        ) != SUCCESS
    )
    {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
    if (ipc_check_ctr(
            worker_ctx->label,
            worker_ctx->aes_key, 
            &worker_ctx->remote_ctr, 
            ircvdi.r_ipc_raw_protocol_t
        ) != SUCCESS
    )
    {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
    switch (ircvdi.r_ipc_raw_protocol_t->type) {
        case IPC_MASTER_WORKER_INFO: {
            if (handle_workers_ipc_info(worker_ctx, initial_delay_ms, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case IPC_MASTER_WORKER_HELLO1_ACK: {
            if (handle_workers_ipc_hello1_ack(worker_ctx, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case IPC_MASTER_WORKER_HELLO2_ACK: {
            if (handle_workers_ipc_hello2_ack(worker_ctx, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case IPC_MASTER_COW_CONNECT: {
            if (handle_workers_ipc_cow_connect(worker_ctx, worker_sessions, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case IPC_UDP_DATA: {
            if (handle_workers_ipc_udp_data(worker_ctx, worker_sessions, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case IPC_UDP_DATA_ACK: {
            if (handle_workers_ipc_udp_data_ack(worker_ctx, worker_sessions, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        default:
            LOG_ERROR("%sUnknown IPC protocol type %d from Master. Ignoring.", worker_ctx->label, ircvdi.r_ipc_raw_protocol_t->type);
            CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
    }
    return SUCCESS;
}
