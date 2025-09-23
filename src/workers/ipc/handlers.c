#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "log.h"
#include "ipc/protocol.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "ipc/udp_data.h"
#include "pqc.h"
#include "poly1305-donna.h"
#include "aes.h"
#include "orilink/hello1.h"
#include "orilink/hello2.h"
#include "orilink/hello3.h"
#include "orilink/hello4.h"
#include "orilink/hello1_ack.h"
#include "orilink/hello2_ack.h"
#include "orilink/hello3_ack.h"
#include "orilink/hello4_ack.h"
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
            memset(tmp_aes_key, 0, HASHES_BYTES);
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
            uint16_t slot_found = icow_connecti->session_index;
            cow_c_session_t *cow_c_session = (cow_c_session_t *)worker_sessions;
            cow_c_session_t *session = &cow_c_session[slot_found];
            orilink_identity_t *identity = &session->identity;
            orilink_security_t *security = &session->security;
            memcpy(&identity->remote_addr, &icow_connecti->remote_addr, sizeof(struct sockaddr_in6));
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
            if (udp_data.status != SUCCESS) {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                return FAILURE;
            }
//----------------------------------------------------------------------
// Here Below:
// create ipc_udp_data_t and send it to the master via IPC
//----------------------------------------------------------------------
            ipc_protocol_t_status_t ipc_cmd_result = ipc_prepare_cmd_udp_data(
                worker_ctx->label,
                identity->local_wot,
                identity->local_index,
//----------------------------------------------------------------------
// Master don't have session_index
//----------------------------------------------------------------------
                0xff,
//----------------------------------------------------------------------
                &identity->remote_addr,
                udp_data.r_size_t,
                udp_data.r_puint8_t
            );
            if (ipc_cmd_result.status != SUCCESS) {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            ssize_t_status_t send_result = send_ipc_protocol_message(
                worker_ctx->label,
                worker_ctx->aes_key,
                worker_ctx->mac_key,
                worker_ctx->local_nonce,
                &worker_ctx->local_ctr,
                worker_ctx->master_uds_fd, 
                ipc_cmd_result.r_ipc_protocol_t
            );
            if (send_result.status != SUCCESS) {
                LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
                return send_result.status;
            } else {
                LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
            }
            CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
//----------------------------------------------------------------------
            session->hello1.len = udp_data.r_size_t;
            session->hello1.data = (uint8_t *)calloc(1, udp_data.r_size_t);
            memcpy(session->hello1.data, udp_data.r_puint8_t, session->hello1.len);
            free(udp_data.r_puint8_t);
            udp_data.r_puint8_t = NULL;
            udp_data.r_size_t = 0;
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        case IPC_UDP_DATA: {
            worker_type_t remote_wot = UNKNOWN;
            ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
                worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
                (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
            );
            if (deserialized_ircvdi.status != SUCCESS) {
                LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return FAILURE;
            } else {
                remote_wot = ircvdi.r_ipc_raw_protocol_t->wot;
                LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
            }           
            ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
            ipc_udp_data_t *iudp_datai = received_protocol->payload.ipc_udp_data;
            switch (remote_wot) {
//----------------------------------------------------------------------
// UDP Data From Remote COW
//----------------------------------------------------------------------
                case COW: {
                    uint16_t slot_found = iudp_datai->session_index;
                    sio_c_session_t *sio_c_session = (sio_c_session_t *)worker_sessions;
                    sio_c_session_t *session = &sio_c_session[slot_found];
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
                    if (orilink_check_mac_ctr(
                            worker_ctx->label, 
                            security->aes_key, 
                            security->mac_key, 
                            &security->remote_ctr, 
                            oudp_datao
                        ) != SUCCESS
                    )
                    {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                        return FAILURE;
                    }
                    switch (oudp_datao->type) {
                        case ORILINK_HELLO1: {
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
                            orilink_hello1_t *ohello1 = received_orilink_protocol->payload.orilink_hello1;
                            uint64_t remote_id = ohello1->local_id;
                            uint8_t kem_publickey[KEM_PUBLICKEY_BYTES / 2];
                            memset(kem_publickey, 0, KEM_PUBLICKEY_BYTES / 2);
                            memcpy(kem_publickey, ohello1->publickey1, KEM_PUBLICKEY_BYTES / 2);
                            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello1_ack(
                                worker_ctx->label,
                                0x01,
                                remote_wot,
                                remote_index,
                                remote_session_index,
                                identity->local_wot,
                                identity->local_index,
                                identity->local_session_index,
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
                            if (udp_data.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
//----------------------------------------------------------------------
// Here Below:
// create ipc_udp_data_t and send it to the master via IPC
//----------------------------------------------------------------------
                            ipc_protocol_t_status_t ipc_cmd_result = ipc_prepare_cmd_udp_data(
                                worker_ctx->label,
                                identity->local_wot,
                                identity->local_index,
//----------------------------------------------------------------------
// Master don't have session_index
//----------------------------------------------------------------------
                                0xff,
//----------------------------------------------------------------------
                                &remote_addr,
                                udp_data.r_size_t,
                                udp_data.r_puint8_t
                            );
                            if (ipc_cmd_result.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
                            ssize_t_status_t send_result = send_ipc_protocol_message(
                                worker_ctx->label,
                                worker_ctx->aes_key,
                                worker_ctx->mac_key,
                                worker_ctx->local_nonce,
                                &worker_ctx->local_ctr,
                                worker_ctx->master_uds_fd, 
                                ipc_cmd_result.r_ipc_protocol_t
                            );
                            if (send_result.status != SUCCESS) {
                                LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
                                return send_result.status;
                            } else {
                                LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
                            }
                            CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
//----------------------------------------------------------------------
                            session->hello1_ack.len = udp_data.r_size_t;
                            session->hello1_ack.data = (uint8_t *)calloc(1, udp_data.r_size_t);
                            memcpy(session->hello1_ack.data, udp_data.r_puint8_t, session->hello1_ack.len);
                            free(udp_data.r_puint8_t);
                            udp_data.r_puint8_t = NULL;
                            udp_data.r_size_t = 0;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
                            memcpy(&identity->remote_addr, &remote_addr, sizeof(struct sockaddr_in6));
                            identity->remote_wot = remote_wot;
                            identity->remote_index = remote_index;
                            identity->remote_session_index = remote_session_index;
                            identity->remote_id = remote_id;
                            memcpy(security->kem_publickey, kem_publickey, KEM_PUBLICKEY_BYTES / 2);
                            memset(kem_publickey, 0, KEM_PUBLICKEY_BYTES / 2);
                            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                            break;
                        }
                        case ORILINK_HELLO2: {
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
                            orilink_hello2_t *ohello2 = received_orilink_protocol->payload.orilink_hello2;
                            uint64_t remote_id = ohello2->local_id;
                            uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
                            uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
                            uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
                            memset(kem_publickey, 0, KEM_PUBLICKEY_BYTES);
                            memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
                            memset(kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
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
                            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello2_ack(
                                worker_ctx->label,
                                0x01,
                                remote_wot,
                                remote_index,
                                remote_session_index,
                                identity->local_wot,
                                identity->local_index,
                                identity->local_session_index,
                                remote_id,
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
                            if (udp_data.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
//----------------------------------------------------------------------
// Here Below:
// create ipc_udp_data_t and send it to the master via IPC
//----------------------------------------------------------------------
                            ipc_protocol_t_status_t ipc_cmd_result = ipc_prepare_cmd_udp_data(
                                worker_ctx->label,
                                identity->local_wot,
                                identity->local_index,
//----------------------------------------------------------------------
// Master don't have session_index
//----------------------------------------------------------------------
                                0xff,
//----------------------------------------------------------------------
                                &remote_addr,
                                udp_data.r_size_t,
                                udp_data.r_puint8_t
                            );
                            if (ipc_cmd_result.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
                            ssize_t_status_t send_result = send_ipc_protocol_message(
                                worker_ctx->label,
                                worker_ctx->aes_key,
                                worker_ctx->mac_key,
                                worker_ctx->local_nonce,
                                &worker_ctx->local_ctr,
                                worker_ctx->master_uds_fd, 
                                ipc_cmd_result.r_ipc_protocol_t
                            );
                            if (send_result.status != SUCCESS) {
                                LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
                                return send_result.status;
                            } else {
                                LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
                            }
                            CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
//----------------------------------------------------------------------
                            session->hello2_ack.len = udp_data.r_size_t;
                            session->hello2_ack.data = (uint8_t *)calloc(1, udp_data.r_size_t);
                            memcpy(session->hello2_ack.data, udp_data.r_puint8_t, session->hello2_ack.len);
                            free(udp_data.r_puint8_t);
                            udp_data.r_puint8_t = NULL;
                            udp_data.r_size_t = 0;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
                            memcpy(&identity->remote_addr, &remote_addr, sizeof(struct sockaddr_in6));
                            identity->remote_wot = remote_wot;
                            identity->remote_index = remote_index;
                            identity->remote_session_index = remote_session_index;
                            identity->remote_id = remote_id;
                            memcpy(security->kem_publickey + (KEM_PUBLICKEY_BYTES / 2), kem_publickey + (KEM_PUBLICKEY_BYTES / 2), KEM_PUBLICKEY_BYTES / 2);
                            memcpy(security->kem_ciphertext, kem_ciphertext, KEM_CIPHERTEXT_BYTES);
                            memcpy(security->kem_sharedsecret, kem_sharedsecret, KEM_SHAREDSECRET_BYTES);
                            memset(kem_publickey, 0, KEM_PUBLICKEY_BYTES);
                            memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
                            memset(kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
                            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                            break;
                        }
                        case ORILINK_HELLO3: {
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
                            orilink_hello3_t *ohello3 = received_orilink_protocol->payload.orilink_hello3;
                            uint64_t remote_id = ohello3->local_id;
                            uint8_t local_nonce[AES_NONCE_BYTES];
                            memset(local_nonce, 0, AES_NONCE_BYTES);
                            if (generate_nonce(worker_ctx->label, local_nonce) != SUCCESS) {
                                LOG_ERROR("%sFailed to generate_nonce.", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                return FAILURE;
                            }
                            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello3_ack(
                                worker_ctx->label,
                                0x01,
                                remote_wot,
                                remote_index,
                                remote_session_index,
                                identity->local_wot,
                                identity->local_index,
                                identity->local_session_index,
                                remote_id,
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
                            if (udp_data.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
//----------------------------------------------------------------------
// Here Below:
// create ipc_udp_data_t and send it to the master via IPC
//----------------------------------------------------------------------
                            ipc_protocol_t_status_t ipc_cmd_result = ipc_prepare_cmd_udp_data(
                                worker_ctx->label,
                                identity->local_wot,
                                identity->local_index,
//----------------------------------------------------------------------
// Master don't have session_index
//----------------------------------------------------------------------
                                0xff,
//----------------------------------------------------------------------
                                &remote_addr,
                                udp_data.r_size_t,
                                udp_data.r_puint8_t
                            );
                            if (ipc_cmd_result.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
                            ssize_t_status_t send_result = send_ipc_protocol_message(
                                worker_ctx->label,
                                worker_ctx->aes_key,
                                worker_ctx->mac_key,
                                worker_ctx->local_nonce,
                                &worker_ctx->local_ctr,
                                worker_ctx->master_uds_fd, 
                                ipc_cmd_result.r_ipc_protocol_t
                            );
                            if (send_result.status != SUCCESS) {
                                LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
                                return send_result.status;
                            } else {
                                LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
                            }
                            CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
//----------------------------------------------------------------------
                            session->hello3_ack.len = udp_data.r_size_t;
                            session->hello3_ack.data = (uint8_t *)calloc(1, udp_data.r_size_t);
                            memcpy(session->hello3_ack.data, udp_data.r_puint8_t, session->hello3_ack.len);
                            free(udp_data.r_puint8_t);
                            udp_data.r_puint8_t = NULL;
                            udp_data.r_size_t = 0;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
                            memcpy(&identity->remote_addr, &remote_addr, sizeof(struct sockaddr_in6));
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
                            identity->remote_wot = remote_wot;
                            identity->remote_index = remote_index;
                            identity->remote_session_index = remote_session_index;
                            identity->remote_id = remote_id;
                            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                            break;
                        }
                        case ORILINK_HELLO4: {
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
                            orilink_hello4_t *ohello4 = received_orilink_protocol->payload.orilink_hello4;
//======================================================================
// Ambil remote_nonce
// Set remote_ctr = 0
// Ambil encrypter wot+index
// Ambil Mac
// Cocokkan MAc
// Decrypt wot dan index
//======================================================================
                            uint32_t remote_ctr = (uint32_t)0;
                            uint32_t local_ctr = (uint32_t)0;
                            uint8_t remote_nonce[AES_NONCE_BYTES];
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
                            uint8_t aes_key[HASHES_BYTES];
                            memset(aes_key, 0, HASHES_BYTES);
                            kdf1(security->kem_sharedsecret, aes_key);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
                            uint8_t encrypted_remote_identity_rcvd1[
                                AES_NONCE_BYTES +
                                sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
                            ];
                            memcpy(encrypted_remote_identity_rcvd1, ohello4->encrypted_local_identity, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
                            uint8_t mac0[AES_TAG_BYTES];
                            poly1305_context mac_ctx0;
                            poly1305_init(&mac_ctx0, security->mac_key);
                            poly1305_update(&mac_ctx0, encrypted_remote_identity_rcvd1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
                            poly1305_finish(&mac_ctx0, mac0);
                            if (!poly1305_verify(mac0, data_mac)) {
                                LOG_ERROR("%sFailed to Mac Tidak Sesuai.", worker_ctx->label);
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
                            aes256ctx aes_ctx0;
                            aes256_ctr_keyexp(&aes_ctx0, aes_key);
//=========================================IV===========================    
                            uint8_t keystream_buffer0[
                                sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
                            ];
                            uint8_t iv0[AES_IV_BYTES];
                            memcpy(iv0, remote_nonce, AES_NONCE_BYTES);
                            uint32_t remote_ctr_be = htobe32(remote_ctr);
                            memcpy(iv0 + AES_NONCE_BYTES, &remote_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
                            aes256_ctr(keystream_buffer0, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), iv0, &aes_ctx0);
                            for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t); i++) {
                                decrypted_remote_identity_rcvd[i] = encrypted_remote_identity_rcvd[i] ^ keystream_buffer0[i];
                            }
                            aes256_ctx_release(&aes_ctx0);
//----------------------------------------------------------------------
// Mencocokkan wot index
//----------------------------------------------------------------------
                            worker_type_t data_wot;
                            memcpy((uint8_t *)&data_wot, decrypted_remote_identity_rcvd, sizeof(uint8_t));
                            if (*(uint8_t *)&remote_wot != *(uint8_t *)&data_wot) {
                                LOG_ERROR("%sberbeda wot.", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                return FAILURE;
                            }
                            uint8_t data_index;
                            memcpy(&data_index, decrypted_remote_identity_rcvd + sizeof(uint8_t), sizeof(uint8_t));
                            if (remote_index != data_index) {
                                LOG_ERROR("%sberbeda index.", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                return FAILURE;
                            }
                            uint8_t data_session_index;
                            memcpy(&data_session_index, decrypted_remote_identity_rcvd + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint8_t));
                            if (remote_session_index != data_session_index) {
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
                                (uint8_t *)&remote_wot, 
                                sizeof(uint8_t)
                            );
                            memcpy(
                                remote_identity + sizeof(uint8_t), 
                                (uint8_t *)&remote_index, 
                                sizeof(uint8_t)
                            );
                            memcpy(
                                remote_identity + sizeof(uint8_t) + sizeof(uint8_t), 
                                (uint8_t *)&remote_session_index, 
                                sizeof(uint8_t)
                            );
                            uint64_t remote_id_be1 = htobe64(remote_id);
                            memcpy(
                                remote_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), 
                                &remote_id_be1, 
                                sizeof(uint64_t)
                            );
//======================================================================    
                            aes256ctx aes_ctx1;
                            aes256_ctr_keyexp(&aes_ctx1, aes_key);
//=========================================IV===========================    
                            uint8_t keystream_buffer1[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
                            uint8_t iv1[AES_IV_BYTES];
                            memcpy(iv1, security->local_nonce, AES_NONCE_BYTES);
                            uint32_t local_ctr_be1 = htobe32(local_ctr);
                            memcpy(iv1 + AES_NONCE_BYTES, &local_ctr_be1, sizeof(uint32_t));
//=========================================IV===========================    
                            aes256_ctr(keystream_buffer1, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), iv1, &aes_ctx1);
                            for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t); i++) {
                                encrypted_remote_identity[i] = remote_identity[i] ^ keystream_buffer1[i];
                            }
                            aes256_ctx_release(&aes_ctx1);
//======================================================================    
                            uint8_t mac1[AES_TAG_BYTES];
                            poly1305_context mac_ctx1;
                            poly1305_init(&mac_ctx1, security->mac_key);
                            poly1305_update(&mac_ctx1, encrypted_remote_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
                            poly1305_finish(&mac_ctx1, mac1);
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
                            aes256ctx aes_ctx2;
                            aes256_ctr_keyexp(&aes_ctx2, aes_key);
//=========================================IV===========================    
                            uint8_t keystream_buffer2[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
                            uint8_t iv2[AES_IV_BYTES];
                            memcpy(iv2, security->local_nonce, AES_NONCE_BYTES);
                            uint32_t local_ctr_be2 = htobe32(security->local_ctr);
                            memcpy(iv2 + AES_NONCE_BYTES, &local_ctr_be2, sizeof(uint32_t));
//=========================================IV===========================    
                            aes256_ctr(keystream_buffer2, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), iv2, &aes_ctx2);
                            for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t); i++) {
                                encrypted_local_identity[i] = local_identity[i] ^ keystream_buffer2[i];
                            }
                            aes256_ctx_release(&aes_ctx2);
//======================================================================    
                            uint8_t mac2[AES_TAG_BYTES];
                            poly1305_context mac_ctx2;
                            poly1305_init(&mac_ctx2, security->mac_key);
                            poly1305_update(&mac_ctx2, encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
                            poly1305_finish(&mac_ctx2, mac2);
//====================================================================== 
                            memcpy(encrypted_local_identity1, encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
                            memcpy(encrypted_local_identity1 + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), mac2, AES_TAG_BYTES);
//======================================================================
                            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello4_ack(
                                worker_ctx->label,
                                0x01,
                                remote_wot,
                                remote_index,
                                remote_session_index,
                                identity->local_wot,
                                identity->local_index,
                                identity->local_session_index,
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
                            if (udp_data.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
//----------------------------------------------------------------------
// Here Below:
// create ipc_udp_data_t and send it to the master via IPC
//----------------------------------------------------------------------
                            ipc_protocol_t_status_t ipc_cmd_result = ipc_prepare_cmd_udp_data(
                                worker_ctx->label,
                                identity->local_wot,
                                identity->local_index,
//----------------------------------------------------------------------
// Master don't have session_index
//----------------------------------------------------------------------
                                0xff,
//----------------------------------------------------------------------
                                &remote_addr,
                                udp_data.r_size_t,
                                udp_data.r_puint8_t
                            );
                            if (ipc_cmd_result.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
                            ssize_t_status_t send_result = send_ipc_protocol_message(
                                worker_ctx->label,
                                worker_ctx->aes_key,
                                worker_ctx->mac_key,
                                worker_ctx->local_nonce,
                                &worker_ctx->local_ctr,
                                worker_ctx->master_uds_fd, 
                                ipc_cmd_result.r_ipc_protocol_t
                            );
                            if (send_result.status != SUCCESS) {
                                LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
                                return send_result.status;
                            } else {
                                LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
                            }
                            CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
//----------------------------------------------------------------------
                            session->hello4_ack.len = udp_data.r_size_t;
                            session->hello4_ack.data = (uint8_t *)calloc(1, udp_data.r_size_t);
                            memcpy(session->hello4_ack.data, udp_data.r_puint8_t, session->hello4_ack.len);
                            free(udp_data.r_puint8_t);
                            udp_data.r_puint8_t = NULL;
                            udp_data.r_size_t = 0;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
                            memcpy(&identity->remote_addr, &remote_addr, sizeof(struct sockaddr_in6));
                            memcpy(security->aes_key, aes_key, HASHES_BYTES);
                            memcpy(security->remote_nonce, remote_nonce, AES_NONCE_BYTES);
                            security->remote_ctr = remote_ctr;
                            security->local_ctr = local_ctr;
                            memset(aes_key, 0, HASHES_BYTES);
                            memset(remote_nonce, 0, AES_NONCE_BYTES);
                            identity->remote_wot = remote_wot;
                            identity->remote_index = remote_index;
                            identity->remote_session_index = remote_session_index;
                            identity->remote_id = remote_id;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
                            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                            break;
                        }
                        default:
                            LOG_ERROR("%sUnknown ORILINK protocol type %d from Remote COW-%d[%d]. Ignoring.", worker_ctx->label, oudp_datao->type, oudp_datao->local_index, oudp_datao->local_session_index);
                            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    }
                    break;
                }
//----------------------------------------------------------------------
// UDP Data From Remote SIO
//----------------------------------------------------------------------
                case SIO: {
                    uint16_t slot_found = iudp_datai->session_index;
                    cow_c_session_t *cow_c_session = (cow_c_session_t *)worker_sessions;
                    cow_c_session_t *session = &cow_c_session[slot_found];
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
                    if (orilink_check_mac_ctr(
                            worker_ctx->label, 
                            security->aes_key, 
                            security->mac_key, 
                            &security->remote_ctr, 
                            oudp_datao
                        ) != SUCCESS
                    )
                    {
                        CLOSE_IPC_PROTOCOL(&received_protocol);
                        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                        return FAILURE;
                    }
                    switch (oudp_datao->type) {
                        case ORILINK_HELLO1_ACK: {
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
                            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello2(
                                worker_ctx->label,
                                0x01,
                                remote_wot,
                                remote_index,
                                remote_session_index,
                                identity->local_wot,
                                identity->local_index,
                                identity->local_session_index,
                                local_id,
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
                            if (udp_data.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
//----------------------------------------------------------------------
// Here Below:
// create ipc_udp_data_t and send it to the master via IPC
//----------------------------------------------------------------------
                            ipc_protocol_t_status_t ipc_cmd_result = ipc_prepare_cmd_udp_data(
                                worker_ctx->label,
                                identity->local_wot,
                                identity->local_index,
//----------------------------------------------------------------------
// Master don't have session_index
//----------------------------------------------------------------------
                                0xff,
//----------------------------------------------------------------------
                                &remote_addr,
                                udp_data.r_size_t,
                                udp_data.r_puint8_t
                            );
                            if (ipc_cmd_result.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
                            ssize_t_status_t send_result = send_ipc_protocol_message(
                                worker_ctx->label,
                                worker_ctx->aes_key,
                                worker_ctx->mac_key,
                                worker_ctx->local_nonce,
                                &worker_ctx->local_ctr,
                                worker_ctx->master_uds_fd, 
                                ipc_cmd_result.r_ipc_protocol_t
                            );
                            if (send_result.status != SUCCESS) {
                                LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
                                return send_result.status;
                            } else {
                                LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
                            }
                            CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
//----------------------------------------------------------------------
                            session->hello2.len = udp_data.r_size_t;
                            session->hello2.data = (uint8_t *)calloc(1, udp_data.r_size_t);
                            memcpy(session->hello2.data, udp_data.r_puint8_t, session->hello2.len);
                            free(udp_data.r_puint8_t);
                            udp_data.r_puint8_t = NULL;
                            udp_data.r_size_t = 0;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
                            memcpy(&identity->remote_addr, &remote_addr, sizeof(struct sockaddr_in6));
                            identity->remote_wot = remote_wot;
                            identity->remote_index = remote_index;
                            identity->remote_session_index = remote_session_index;
                            identity->local_id = local_id;
                            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                            break;
                        }
                        case ORILINK_HELLO2_ACK: {
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
                            orilink_hello2_ack_t *ohello2_ack = received_orilink_protocol->payload.orilink_hello2_ack;
                            uint64_t local_id = ohello2_ack->remote_id;
                            uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES / 2];
                            memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES / 2);
                            memcpy(kem_ciphertext, ohello2_ack->ciphertext1, KEM_CIPHERTEXT_BYTES / 2);
                            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello3(
                                worker_ctx->label,
                                0x01,
                                remote_wot,
                                remote_index,
                                remote_session_index,
                                identity->local_wot,
                                identity->local_index,
                                identity->local_session_index,
                                local_id,
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
                            if (udp_data.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
//----------------------------------------------------------------------
// Here Below:
// create ipc_udp_data_t and send it to the master via IPC
//----------------------------------------------------------------------
                            ipc_protocol_t_status_t ipc_cmd_result = ipc_prepare_cmd_udp_data(
                                worker_ctx->label,
                                identity->local_wot,
                                identity->local_index,
//----------------------------------------------------------------------
// Master don't have session_index
//----------------------------------------------------------------------
                                0xff,
//----------------------------------------------------------------------
                                &remote_addr,
                                udp_data.r_size_t,
                                udp_data.r_puint8_t
                            );
                            if (ipc_cmd_result.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
                            ssize_t_status_t send_result = send_ipc_protocol_message(
                                worker_ctx->label,
                                worker_ctx->aes_key,
                                worker_ctx->mac_key,
                                worker_ctx->local_nonce,
                                &worker_ctx->local_ctr,
                                worker_ctx->master_uds_fd, 
                                ipc_cmd_result.r_ipc_protocol_t
                            );
                            if (send_result.status != SUCCESS) {
                                LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
                                return send_result.status;
                            } else {
                                LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
                            }
                            CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
//----------------------------------------------------------------------
                            session->hello3.len = udp_data.r_size_t;
                            session->hello3.data = (uint8_t *)calloc(1, udp_data.r_size_t);
                            memcpy(session->hello3.data, udp_data.r_puint8_t, session->hello3.len);
                            free(udp_data.r_puint8_t);
                            udp_data.r_puint8_t = NULL;
                            udp_data.r_size_t = 0;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
                            memcpy(&identity->remote_addr, &remote_addr, sizeof(struct sockaddr_in6));
                            identity->remote_wot = remote_wot;
                            identity->remote_index = remote_index;
                            identity->remote_session_index = remote_session_index;
                            identity->local_id = local_id;
                            memcpy(security->kem_ciphertext, kem_ciphertext, KEM_CIPHERTEXT_BYTES / 2);
                            memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES / 2);
                            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                            break;
                        }
                        case ORILINK_HELLO3_ACK: {
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
                            orilink_hello3_ack_t *ohello3_ack = received_orilink_protocol->payload.orilink_hello3_ack;
                            uint64_t local_id = ohello3_ack->remote_id;
                            uint8_t remote_nonce[AES_NONCE_BYTES];
                            uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
                            uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
                            uint8_t aes_key[HASHES_BYTES];
                            uint8_t mac_key[HASHES_BYTES];
                            uint8_t local_nonce[AES_NONCE_BYTES];
                            uint32_t local_ctr = (uint32_t)0;
                            memset(remote_nonce, 0, AES_NONCE_BYTES);
                            memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
                            memset(kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
                            memset(aes_key, 0, HASHES_BYTES);
                            memset(mac_key, 0, HASHES_BYTES);
                            memset(local_nonce, 0, AES_NONCE_BYTES);
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
                            aes256ctx aes_ctx;
                            aes256_ctr_keyexp(&aes_ctx, aes_key);
//=========================================IV===========================    
                            uint8_t keystream_buffer[
                                sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
                            ];
                            uint8_t iv[AES_IV_BYTES];
                            memcpy(iv, local_nonce, AES_NONCE_BYTES);
                            uint32_t local_ctr_be = htobe32(local_ctr);
                            memcpy(iv + AES_NONCE_BYTES, &local_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
                            aes256_ctr(
                                keystream_buffer, 
                                sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), 
                                iv, 
                                &aes_ctx
                            );
                            for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t); i++) {
                                encrypted_local_identity[i] = local_identity[i] ^ keystream_buffer[i];
                            }
                            aes256_ctx_release(&aes_ctx);
//======================================================================    
                            memcpy(encrypted_local_identity1 + AES_NONCE_BYTES, encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
//======================================================================
                            uint8_t mac[AES_TAG_BYTES];
                            poly1305_context mac_ctx;
                            poly1305_init(&mac_ctx, mac_key);
                            poly1305_update(&mac_ctx, encrypted_local_identity1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
                            poly1305_finish(&mac_ctx, mac);
//====================================================================== 
                            memcpy(encrypted_local_identity2, encrypted_local_identity1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
                            memcpy(encrypted_local_identity2 + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), mac, AES_TAG_BYTES);
//======================================================================
                            orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello4(
                                worker_ctx->label,
                                0x01,
                                remote_wot,
                                remote_index,
                                remote_session_index,
                                identity->local_wot,
                                identity->local_index,
                                identity->local_session_index,
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
                            if (udp_data.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
//----------------------------------------------------------------------
// Here Below:
// create ipc_udp_data_t and send it to the master via IPC
//----------------------------------------------------------------------
                            ipc_protocol_t_status_t ipc_cmd_result = ipc_prepare_cmd_udp_data(
                                worker_ctx->label,
                                identity->local_wot,
                                identity->local_index,
//----------------------------------------------------------------------
// Master don't have session_index
//----------------------------------------------------------------------
                                0xff,
//----------------------------------------------------------------------
                                &remote_addr,
                                udp_data.r_size_t,
                                udp_data.r_puint8_t
                            );
                            if (ipc_cmd_result.status != SUCCESS) {
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                return FAILURE;
                            }
                            ssize_t_status_t send_result = send_ipc_protocol_message(
                                worker_ctx->label,
                                worker_ctx->aes_key,
                                worker_ctx->mac_key,
                                worker_ctx->local_nonce,
                                &worker_ctx->local_ctr,
                                worker_ctx->master_uds_fd, 
                                ipc_cmd_result.r_ipc_protocol_t
                            );
                            if (send_result.status != SUCCESS) {
                                LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
                                CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
                                return send_result.status;
                            } else {
                                LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
                            }
                            CLOSE_IPC_PROTOCOL(&ipc_cmd_result.r_ipc_protocol_t);
//----------------------------------------------------------------------
                            session->hello4.len = udp_data.r_size_t;
                            session->hello4.data = (uint8_t *)calloc(1, udp_data.r_size_t);
                            memcpy(session->hello4.data, udp_data.r_puint8_t, session->hello4.len);
                            free(udp_data.r_puint8_t);
                            udp_data.r_puint8_t = NULL;
                            udp_data.r_size_t = 0;
                            CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
                            memcpy(&identity->remote_addr, &remote_addr, sizeof(struct sockaddr_in6));
                            identity->remote_wot = remote_wot;
                            identity->remote_index = remote_index;
                            identity->remote_session_index = remote_session_index;
                            identity->local_id = local_id;
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
                            break;
                        }
                        case ORILINK_HELLO4_ACK: {
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
                            uint8_t mac0[AES_TAG_BYTES];
                            poly1305_context mac_ctx0;
                            poly1305_init(&mac_ctx0, security->mac_key);
                            poly1305_update(&mac_ctx0, encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
                            poly1305_finish(&mac_ctx0, mac0);
                            if (!poly1305_verify(mac0, data_mac0)) {
                                LOG_ERROR("%sFailed to Mac Tidak Sesuai. Worker error...", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                return FAILURE;
                            }            
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
                            uint8_t decrypted_local_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
                            aes256ctx aes_ctx0;
                            aes256_ctr_keyexp(&aes_ctx0, aes_key);
//=========================================IV===========================    
                            uint8_t keystream_buffer0[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
                            uint8_t iv0[AES_IV_BYTES];
                            memcpy(iv0, security->remote_nonce, AES_NONCE_BYTES);
                            uint32_t remote_ctr_be0 = htobe32(remote_ctr);
                            memcpy(iv0 + AES_NONCE_BYTES, &remote_ctr_be0, sizeof(uint32_t));
//=========================================IV===========================    
                            aes256_ctr(keystream_buffer0, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), iv0, &aes_ctx0);
                            for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t); i++) {
                                decrypted_local_identity[i] = encrypted_local_identity[i] ^ keystream_buffer0[i];
                            }
                            aes256_ctx_release(&aes_ctx0);
//----------------------------------------------------------------------
// Mencocokkan wot index
//----------------------------------------------------------------------
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
                            uint8_t mac1[AES_TAG_BYTES];
                            poly1305_context mac_ctx1;
                            poly1305_init(&mac_ctx1, security->mac_key);
                            poly1305_update(&mac_ctx1, encrypted_remote_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
                            poly1305_finish(&mac_ctx1, mac1);
                            if (!poly1305_verify(mac1, data_mac1)) {
                                LOG_ERROR("%sFailed to Mac Tidak Sesuai. Worker error...", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                return FAILURE;
                            }            
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
                            uint8_t decrypted_remote_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
                            aes256ctx aes_ctx1;
                            aes256_ctr_keyexp(&aes_ctx1, aes_key);
//=========================================IV===========================    
                            uint8_t keystream_buffer1[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
                            uint8_t iv1[AES_IV_BYTES];
                            memcpy(iv1, security->remote_nonce, AES_NONCE_BYTES);
                            uint32_t remote_ctr_be1 = htobe32(remote_ctr);
                            memcpy(iv1 + AES_NONCE_BYTES, &remote_ctr_be1, sizeof(uint32_t));
//=========================================IV===========================    
                            aes256_ctr(keystream_buffer1, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), iv1, &aes_ctx1);
                            for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t); i++) {
                                decrypted_remote_identity[i] = encrypted_remote_identity[i] ^ keystream_buffer1[i];
                            }
                            aes256_ctx_release(&aes_ctx1);
//----------------------------------------------------------------------
// Mencocokkan wot index
//----------------------------------------------------------------------
                            worker_type_t data_wot1;
                            memcpy((uint8_t *)&data_wot1, decrypted_remote_identity, sizeof(uint8_t));
                            if (*(uint8_t *)&remote_wot != *(uint8_t *)&data_wot1) {
                                LOG_ERROR("%sberbeda wot %d <=> %d. Worker error...", worker_ctx->label, data_wot1, identity->local_wot);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                return FAILURE;
                            }
                            uint8_t data_index1;
                            memcpy(&data_index1, decrypted_remote_identity + sizeof(uint8_t), sizeof(uint8_t));
                            if (remote_index != data_index1) {
                                LOG_ERROR("%sberbeda index. Worker error...", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                return FAILURE;
                            }
                            uint8_t data_session_index1;
                            memcpy(&data_session_index1, decrypted_remote_identity + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint8_t));
                            if (remote_session_index != data_session_index1) {
                                LOG_ERROR("%sberbeda session_index.", worker_ctx->label);
                                CLOSE_IPC_PROTOCOL(&received_protocol);
                                CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                                return FAILURE;
                            }
                            uint64_t remote_id_be;
                            memcpy(&remote_id_be, decrypted_local_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint64_t));
                            uint64_t remote_id = be64toh(remote_id_be);
//======================================================================
                            CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------
                            memcpy(&identity->remote_addr, &remote_addr, sizeof(struct sockaddr_in6));
                            identity->remote_wot = remote_wot;
                            identity->remote_index = remote_index;
                            identity->remote_session_index = remote_session_index;
                            identity->remote_id = remote_id;
                            identity->local_id = local_id;
                            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
                            break;
                        }
                        default:
                            LOG_ERROR("%sUnknown ORILINK protocol type %d from Remote SIO-%d[%d]. Ignoring.", worker_ctx->label, oudp_datao->type, oudp_datao->local_index, oudp_datao->local_session_index);
                            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    }
                    break;
                }
//----------------------------------------------------------------------
                default:
                    LOG_ERROR("%sUnknown Source. UDP Remote Worker %d. Ignoring.", worker_ctx->label, remote_wot);
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
        default:
            LOG_ERROR("%sUnknown IPC protocol type %d from Master. Ignoring.", worker_ctx->label, ircvdi.r_ipc_raw_protocol_t->type);
            CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
    }
    return SUCCESS;
}
