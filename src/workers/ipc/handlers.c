#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "ipc/protocol.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "ipc/cow_master_udp.h"
#include "pqc.h"
#include "poly1305-donna.h"
#include "aes.h"
#include "orilink/hello1.h"
#include "orilink/protocol.h"

void handle_workers_ipc_closed_event(worker_context_t *worker_ctx) {
    LOG_INFO("%sMaster disconnected. Initiating graceful shutdown...", worker_ctx->label);
    worker_ctx->shutdown_requested = 1;
}

status_t handle_workers_ipc_event(worker_context_t *worker_ctx, void *worker_sessions, double *initial_delay_ms) {
    ipc_raw_protocol_t_status_t ircvdi = receive_ipc_raw_protocol_message(worker_ctx->label, worker_ctx->master_uds_fd);
    if (ircvdi.status != SUCCESS) {
        LOG_ERROR("%sError receiving or deserializing IPC message from Master: %d", worker_ctx->label, ircvdi.status);
        return ircvdi.status;
    }
    if (ipc_check_mac_ctr(
            worker_ctx->label, 
            worker_ctx->aes_key, 
            worker_ctx->mac_key, 
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
            ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
                worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
                (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
            );
            if (deserialized_ircvdi.status != SUCCESS) {
                LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return FAILURE;
            } else {
                LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
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
                    if (async_delete_event(worker_ctx->label, &worker_ctx->async, &worker_ctx->heartbeat_timer_fd) != SUCCESS) {		
                        LOG_INFO("%sGagal async_delete_event hb timer, Untuk Rekeying", worker_ctx->label);
                        worker_ctx->shutdown_requested = 1;
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        return FAILURE;
                    }
                    CLOSE_FD(&worker_ctx->heartbeat_timer_fd);
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
            break;
        }
        case IPC_MASTER_WORKER_HELLO1_ACK: {
            if (!worker_ctx->hello1_sent) {
                LOG_ERROR("%sBelum pernah mengirim HELLO1", worker_ctx->label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return FAILURE;
            }
            if (worker_ctx->hello1_ack_rcvd) {
                LOG_ERROR("%sSudah ada HELLO1_ACK", worker_ctx->label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return FAILURE;
            }
            ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
                worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
                (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
            );
            if (deserialized_ircvdi.status != SUCCESS) {
                LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return FAILURE;
            } else {
                LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
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
            if (worker_master_hello2(worker_ctx) != SUCCESS) {
                LOG_ERROR("%sFailed to worker_master_hello2. Worker error. Initiating graceful shutdown...", worker_ctx->label);
                worker_ctx->shutdown_requested = 1;
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            memcpy(worker_ctx->remote_nonce, ihello1_acki->nonce, AES_NONCE_BYTES);
            worker_ctx->hello1_ack_rcvd = true;
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case IPC_MASTER_WORKER_HELLO2_ACK: {
            if (!worker_ctx->hello2_sent) {
                LOG_ERROR("%sBelum pernah mengirim HELLO2", worker_ctx->label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return FAILURE;
            }
            if (worker_ctx->hello2_ack_rcvd) {
                LOG_ERROR("%sSudah ada HELLO2_ACK", worker_ctx->label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return FAILURE;
            }
            ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
                worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
                (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
            );
            if (deserialized_ircvdi.status != SUCCESS) {
                LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return FAILURE;
            } else {
                LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
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
            uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
            memcpy(encrypted_wot_index, ihello2_acki->encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
            uint8_t data_mac[AES_TAG_BYTES];
            memcpy(data_mac, ihello2_acki->encrypted_wot_index + sizeof(uint8_t) + sizeof(uint8_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// Tmp aes_key
//----------------------------------------------------------------------
            uint8_t tmp_aes_key[HASHES_BYTES];
            kdf1(worker_ctx->kem_sharedsecret, tmp_aes_key);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
            uint8_t mac[AES_TAG_BYTES];
            poly1305_context mac_ctx;
            poly1305_init(&mac_ctx, worker_ctx->mac_key);
            poly1305_update(&mac_ctx, encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
            poly1305_finish(&mac_ctx, mac);
            if (!poly1305_verify(mac, data_mac)) {
                LOG_ERROR("%sFailed to Mac Tidak Sesuai. Worker error...", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }            
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
            uint8_t decrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
            aes256ctx aes_ctx;
            aes256_ctr_keyexp(&aes_ctx, tmp_aes_key);
//=========================================IV===========================    
            uint8_t keystream_buffer[sizeof(uint8_t) + sizeof(uint8_t)];
            uint8_t iv[AES_IV_BYTES];
            memcpy(iv, worker_ctx->remote_nonce, AES_NONCE_BYTES);
            uint32_t remote_ctr_be = htobe32(worker_ctx->remote_ctr);
            memcpy(iv + AES_NONCE_BYTES, &remote_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
            aes256_ctr(keystream_buffer, sizeof(uint8_t) + sizeof(uint8_t), iv, &aes_ctx);
            for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t); i++) {
                decrypted_wot_index[i] = encrypted_wot_index[i] ^ keystream_buffer[i];
            }
            aes256_ctx_release(&aes_ctx);
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
//----------------------------------------------------------------------
// Aktifkan Heartbeat Karna security/Enkripsi Sudah Ready
//---------------------------------------------------------------------- 
            if (async_create_timerfd(worker_ctx->label, &worker_ctx->heartbeat_timer_fd) != SUCCESS) {
                LOG_ERROR("%sWorker error async_create_timerfd...", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            if (async_set_timerfd_time(worker_ctx->label, &worker_ctx->heartbeat_timer_fd,
                WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0,
                WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT, 0) != SUCCESS)
            {
                LOG_ERROR("%sWorker error async_set_timerfd_time...", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &worker_ctx->heartbeat_timer_fd) != SUCCESS) {
                LOG_ERROR("%sWorker error async_create_incoming_event...", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
// Menganggap data valid dengan integritas
//---------------------------------------------------------------------- 
            memcpy(worker_ctx->aes_key, tmp_aes_key, HASHES_BYTES);
            memset (tmp_aes_key, 0, HASHES_BYTES);
            worker_ctx->remote_ctr = (uint32_t)0;
            worker_ctx->hello2_ack_rcvd = true;
//---------------------------------------------------------------------- 
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case IPC_MASTER_COW_CONNECT: {
            ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
                worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
                (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
            );
            if (deserialized_ircvdi.status != SUCCESS) {
                LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return FAILURE;
            } else {
                LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
            }           
            ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
            ipc_master_cow_connect_t *icow_connecti = received_protocol->payload.ipc_master_cow_connect;            
//----------------------------------------------------------------------            
            cow_c_session_t *cow_c_session = (cow_c_session_t *)worker_sessions;
            int slot_found = -1;
            for (uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
                if (!cow_c_session[i].in_use) {
                    cow_c_session[i].in_use = true;
                    memcpy(&cow_c_session[i].identity.remote_addr, &icow_connecti->server_addr, sizeof(struct sockaddr_in6));
                    slot_found = i;
                    break;
                }
            }
            if (slot_found == -1) {
                LOG_ERROR("%sNO SLOT.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            cow_c_session_t *session = &cow_c_session[slot_found];
            orilink_identity_t *identity = &cow_c_session[slot_found].identity;
            orilink_security_t *security = &cow_c_session[slot_found].security;
            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello1(
                worker_ctx->label,
                0x01,
                identity->remote_wot,
                identity->remote_index,
                identity->remote_session_index,
                identity->local_wot,
                identity->local_index,
                identity->local_session_index,
                identity->local_id,
                security->kem_publickey,
                session->hello1.sent_try_count
            );
            if (orilink_cmd_result.status != SUCCESS) {
                return FAILURE;
            }
            puint8_t_size_t_status_t data = create_orilink_raw_protocol_packet(
                worker_ctx->label,
                security->aes_key,
                security->mac_key,
                security->local_nonce,
                &security->local_ctr,
                orilink_cmd_result.r_orilink_protocol_t
            );
            if (data.status != SUCCESS) {
                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                return FAILURE;
            }
            session->hello1.len = data.r_size_t;
            session->hello1.data = (uint8_t *)calloc(1, data.r_size_t);
            memcpy(session->hello1.data, data.r_puint8_t, session->hello1.len);
//------------------------------------------------------------------------------------
// Here Below:
// create ipc_cow_master_udp_t and send it to the master via IPC without encryption
// encryption has already been done in orilink_prepare_cmd_hello1
//----------------------------------------------------------------------
            ipc_protocol_t_status_t ipc_cmd_result = ipc_prepare_cmd_cow_master_udp(
                worker_ctx->label,
                identity->local_wot,
                identity->local_index,
                &identity->remote_addr,
                session->hello1.len,
                session->hello1.data
            );
            if (ipc_cmd_result.status != SUCCESS) {
                return FAILURE;
            }
            ssize_t_status_t send_result = send_ipc_protocol_message(
                worker_ctx->label,
//------------------------------------------------------------------------------------
// Set AES KEY = NULL for IPC without encryption
//------------------------------------------------------------------------------------
                NULL,
//------------------------------------------------------------------------------------
                worker_ctx->mac_key,
                worker_ctx->local_nonce,
                &worker_ctx->local_ctr,
                worker_ctx->master_uds_fd, 
                ipc_cmd_result.r_ipc_protocol_t
            );
            if (send_result.status != SUCCESS) {
                LOG_ERROR("%sFailed to sent cow_master_udp to Master.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
                return send_result.status;
            } else {
                LOG_DEBUG("%sSent cow_master_udp to Master.", worker_ctx->label);
            }
            CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
//----------------------------------------------------------------------
            free(data.r_puint8_t);
            data.r_puint8_t = NULL;
            data.r_size_t = 0;
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        default:
            LOG_ERROR("%sUnknown protocol type %d from Master. Ignoring.", worker_ctx->label, ircvdi.r_ipc_raw_protocol_t->type);
            CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
    }
    return SUCCESS;
}
