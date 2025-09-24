#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>

#include "log.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "types.h"
#include "utilities.h"
#include "master/master.h"
#include "master/ipc/handlers.h"
#include "master/ipc/worker_ipc_cmds.h"
#include "poly1305-donna.h"
#include "aes.h"

status_t handle_master_ipc_hello2(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, int rcvd_index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, ipc_raw_protocol_t_status_t *ircvdi) {
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(label,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return deserialized_ircvdi.status;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_worker_master_hello2_t *ihello2i = received_protocol->payload.ipc_worker_master_hello2;
    
    if (!security->hello1_ack_sent) {
        LOG_ERROR("%sBelum pernah mengirim HELLO1_ACK", label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    if (security->hello2_rcvd) {
        LOG_ERROR("%sSudah ada HELLO2", label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//======================================================================
// Ambil remote_nonce
// Set remote_ctr = 0
// Ambil encrypter wot+index
// Ambil Mac
// Cocokkan MAc
// Decrypt wot dan index
//======================================================================
    uint8_t remote_nonce[AES_NONCE_BYTES];
    memcpy(remote_nonce, ihello2i->encrypted_wot_index, AES_NONCE_BYTES);
    uint8_t encrypted_wot_index_rcvd[sizeof(uint8_t) + sizeof(uint8_t)];   
    memcpy(encrypted_wot_index_rcvd, ihello2i->encrypted_wot_index + AES_NONCE_BYTES, sizeof(uint8_t) + sizeof(uint8_t));
    uint8_t data_mac[AES_TAG_BYTES];
    memcpy(data_mac, ihello2i->encrypted_wot_index + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// Temporary Key
//----------------------------------------------------------------------
    uint8_t aes_key[HASHES_BYTES];
    kdf1(security->kem_sharedsecret, aes_key);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
    uint8_t encrypted_wot_index_rcvd1[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t)];
    memcpy(encrypted_wot_index_rcvd1, ihello2i->encrypted_wot_index, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
    uint8_t mac0[AES_TAG_BYTES];
    poly1305_context mac_ctx0;
    poly1305_init(&mac_ctx0, security->mac_key);
    poly1305_update(&mac_ctx0, encrypted_wot_index_rcvd1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
    poly1305_finish(&mac_ctx0, mac0);
    if (!poly1305_verify(mac0, data_mac)) {
        LOG_ERROR("%sFailed to Mac Tidak Sesuai.", label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
    uint8_t decrypted_wot_index_rcvd[sizeof(uint8_t) + sizeof(uint8_t)];
    aes256ctx aes_ctx0;
    aes256_ctr_keyexp(&aes_ctx0, aes_key);
//=========================================IV===========================    
    uint8_t keystream_buffer0[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t iv0[AES_IV_BYTES];
    memcpy(iv0, remote_nonce, AES_NONCE_BYTES);
    uint32_t remote_ctr_be = htobe32(security->remote_ctr);
    memcpy(iv0 + AES_NONCE_BYTES, &remote_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr(keystream_buffer0, sizeof(uint8_t) + sizeof(uint8_t), iv0, &aes_ctx0);
    for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t); i++) {
        decrypted_wot_index_rcvd[i] = encrypted_wot_index_rcvd[i] ^ keystream_buffer0[i];
    }
    aes256_ctx_release(&aes_ctx0);
//----------------------------------------------------------------------
// Mencocokkan wot index
//----------------------------------------------------------------------
    worker_type_t data_wot;
    memcpy((uint8_t *)&data_wot, decrypted_wot_index_rcvd, sizeof(uint8_t));
    if (*(uint8_t *)&rcvd_wot != *(uint8_t *)&data_wot) {
        LOG_ERROR("%sberbeda wot.", label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    uint8_t data_index;
    memcpy(&data_index, decrypted_wot_index_rcvd + sizeof(uint8_t), sizeof(uint8_t));
    if (rcvd_index != data_index) {
        LOG_ERROR("%sberbeda index.", label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
    uint8_t wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
    uint8_t encrypted_wot_index1[sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES];
    memcpy(wot_index, (uint8_t *)&rcvd_wot, sizeof(uint8_t));
    memcpy(wot_index + sizeof(uint8_t), &rcvd_index, sizeof(uint8_t));
//======================================================================    
    aes256ctx aes_ctx1;
    aes256_ctr_keyexp(&aes_ctx1, aes_key);
//=========================================IV===========================    
    uint8_t keystream_buffer1[sizeof(uint8_t) + sizeof(uint8_t)];
    uint8_t iv1[AES_IV_BYTES];
    memcpy(iv1, security->local_nonce, AES_NONCE_BYTES);
    uint32_t local_ctr_be = htobe32(security->local_ctr);
    memcpy(iv1 + AES_NONCE_BYTES, &local_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr(keystream_buffer1, sizeof(uint8_t) + sizeof(uint8_t), iv1, &aes_ctx1);
    for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t); i++) {
        encrypted_wot_index[i] = wot_index[i] ^ keystream_buffer1[i];
    }
    aes256_ctx_release(&aes_ctx1);
//======================================================================    
    uint8_t mac1[AES_TAG_BYTES];
    poly1305_context mac_ctx;
    poly1305_init(&mac_ctx, security->mac_key);
    poly1305_update(&mac_ctx, encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
    poly1305_finish(&mac_ctx, mac1);
//====================================================================== 
    memcpy(encrypted_wot_index1, encrypted_wot_index, sizeof(uint8_t) + sizeof(uint8_t));
    memcpy(encrypted_wot_index1 + sizeof(uint8_t) + sizeof(uint8_t), mac1, AES_TAG_BYTES);
//======================================================================
    if (master_worker_hello2_ack(label, master_ctx, rcvd_wot, rcvd_index, security, worker_name, worker_uds_fd, encrypted_wot_index1) != SUCCESS) {
        LOG_ERROR("%sFailed to master_worker_hello2_ack.", label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    memcpy(security->aes_key, aes_key, HASHES_BYTES);
    memset (aes_key, 0, HASHES_BYTES);
    security->local_ctr = (uint32_t)0;
    memcpy(security->remote_nonce, remote_nonce, AES_NONCE_BYTES);
    memset(remote_nonce, 0, AES_NONCE_BYTES);
    security->remote_ctr = (uint32_t)0;
//----------------------------------------------------------------------
// Menganggap data valid dengan integritas
//----------------------------------------------------------------------
    if (rcvd_wot == SIO) {
        master_ctx->sio_session[rcvd_index].isready = true;
    } else if (rcvd_wot == LOGIC) {
        master_ctx->logic_session[rcvd_index].isready = true;
    } else if (rcvd_wot == COW) {
        master_ctx->cow_session[rcvd_index].isready = true;
    } else if (rcvd_wot == DBR) {
        master_ctx->dbr_session[rcvd_index].isready = true;
    } else if (rcvd_wot == DBW) {
        master_ctx->dbw_session[rcvd_index].isready = true;
    }
    if (!master_ctx->all_workers_is_ready) {
        master_ctx->all_workers_is_ready = true;
        for (uint8_t indexrdy = 0; indexrdy < MAX_SIO_WORKERS; ++indexrdy) {
            if (!master_ctx->sio_session[indexrdy].isready) {
                master_ctx->all_workers_is_ready = false;
                break;
            }
        }
        if (master_ctx->all_workers_is_ready) {
            for (uint8_t indexrdy = 0; indexrdy < MAX_LOGIC_WORKERS; ++indexrdy) {
                if (!master_ctx->logic_session[indexrdy].isready) {
                    master_ctx->all_workers_is_ready = false;
                    break;
                }
            }
        }
        if (master_ctx->all_workers_is_ready) {
            for (uint8_t indexrdy = 0; indexrdy < MAX_COW_WORKERS; ++indexrdy) {
                if (!master_ctx->cow_session[indexrdy].isready) {
                    master_ctx->all_workers_is_ready = false;
                    break;
                }
            }
        }
        if (master_ctx->all_workers_is_ready) {
            for (uint8_t indexrdy = 0; indexrdy < MAX_DBR_WORKERS; ++indexrdy) {
                if (!master_ctx->dbr_session[indexrdy].isready) {
                    master_ctx->all_workers_is_ready = false;
                    break;
                }
            }
        }
        if (master_ctx->all_workers_is_ready) {
            for (uint8_t indexrdy = 0; indexrdy < MAX_DBW_WORKERS; ++indexrdy) {
                if (!master_ctx->dbw_session[indexrdy].isready) {
                    master_ctx->all_workers_is_ready = false;
                    break;
                }
            }
        }
        if (master_ctx->all_workers_is_ready) {
            LOG_INFO("%s====================================================", label);
            LOG_INFO("%sSEMUA WORKER SUDAH READY", label);
            LOG_INFO("%s====================================================", label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            return SUCCESS_WRKSRDY;
        }
    }
//---------------------------------------------------------------------- 
    CLOSE_IPC_PROTOCOL(&received_protocol);
    return SUCCESS;
}
