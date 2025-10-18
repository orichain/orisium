#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "log.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "types.h"
#include "utilities.h"
#include "master/master.h"
#include "master/ipc/handlers.h"
#include "master/ipc/worker_ipc_cmds.h"

status_t handle_master_ipc_hello2(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, worker_rekeying_t *rekeying, const char *worker_name, int *worker_uds_fd, ipc_raw_protocol_t_status_t *ircvdi) {
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
    uint32_t remote_ctr = (uint32_t)0;
    uint32_t local_ctr = (uint32_t)0;
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
    const size_t data_len_0 = AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t);
    if (compare_mac(
            security->mac_key,
            encrypted_wot_index_rcvd1,
            data_len_0,
            data_mac
        ) != SUCCESS
    )
    {
        LOG_ERROR("%sIPC Hello2 Mac mismatch!", label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE_MACMSMTCH;
    }
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
    uint8_t decrypted_wot_index_rcvd[sizeof(uint8_t) + sizeof(uint8_t)];
    const size_t data_len = sizeof(uint8_t) + sizeof(uint8_t);
    if (encrypt_decrypt_256(
            label,
            aes_key,
            remote_nonce,
            &remote_ctr,
            encrypted_wot_index_rcvd,
            decrypted_wot_index_rcvd,
            data_len
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
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
    if (encrypt_decrypt_256(
            label,
            aes_key,
            security->local_nonce,
            &local_ctr,
            wot_index,
            encrypted_wot_index,
            data_len
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//======================================================================    
    uint8_t mac1[AES_TAG_BYTES];
    const size_t data_4mac_len = sizeof(uint8_t) + sizeof(uint8_t);
    calculate_mac(security->mac_key, encrypted_wot_index, mac1, data_4mac_len);
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
    security->local_ctr = local_ctr;
    memcpy(security->remote_nonce, remote_nonce, AES_NONCE_BYTES);
    memset(remote_nonce, 0, AES_NONCE_BYTES);
    security->remote_ctr = remote_ctr;
//----------------------------------------------------------------------
    master_worker_session_t *session = get_master_worker_session(master_ctx, rcvd_wot, rcvd_index);
    if (session == NULL) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
// Menganggap data valid dengan integritas
//----------------------------------------------------------------------
    session->isready = true;
    if (!rekeying || !security) {
        LOG_ERROR("%sFailed to master_worker_hello2_ack.", label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
//----------------------------------------------------------------------
    rekeying->is_rekeying = false;
    ipc_protocol_queue_t *current = rekeying->rekeying_queue;
    ipc_protocol_queue_t *next;
    while (current != NULL) {
        next = current->next;
        ssize_t_status_t send_result = send_ipc_protocol_message(
            label, 
            security->aes_key,
            security->mac_key,
            security->local_nonce,
            &security->local_ctr,
            current->uds_fd,
            current->p
        );
        if (send_result.status != SUCCESS) {
            LOG_DEBUG("%sFailed to sent rekeying queue data to Worker.", label);
        } else {
            LOG_DEBUG("%sSent rekeying queue data to Worker.", label);
        }
        CLOSE_IPC_PROTOCOL(&current->p);
        free(current);
        current = next;
    }
    rekeying->rekeying_queue = NULL;
//----------------------------------------------------------------------
    if (!master_ctx->all_workers_is_ready) {
        master_ctx->all_workers_is_ready = true;
        for (uint8_t indexrdy = 0; indexrdy < MAX_SIO_WORKERS; ++indexrdy) {
            master_worker_session_t *indexrdy_session = get_master_worker_session(master_ctx, SIO, indexrdy);
            if (session == NULL) {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            if (!indexrdy_session->isready) {
                master_ctx->all_workers_is_ready = false;
                break;
            }
        }
        if (master_ctx->all_workers_is_ready) {
            for (uint8_t indexrdy = 0; indexrdy < MAX_LOGIC_WORKERS; ++indexrdy) {
                master_worker_session_t *indexrdy_session = get_master_worker_session(master_ctx, LOGIC, indexrdy);
                if (session == NULL) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
                if (!indexrdy_session->isready) {
                    master_ctx->all_workers_is_ready = false;
                    break;
                }
            }
        }
        if (master_ctx->all_workers_is_ready) {
            for (uint8_t indexrdy = 0; indexrdy < MAX_COW_WORKERS; ++indexrdy) {
                master_worker_session_t *indexrdy_session = get_master_worker_session(master_ctx, COW, indexrdy);
                if (session == NULL) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
                if (!indexrdy_session->isready) {
                    master_ctx->all_workers_is_ready = false;
                    break;
                }
            }
        }
        if (master_ctx->all_workers_is_ready) {
            for (uint8_t indexrdy = 0; indexrdy < MAX_DBR_WORKERS; ++indexrdy) {
                master_worker_session_t *indexrdy_session = get_master_worker_session(master_ctx, DBR, indexrdy);
                if (session == NULL) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
                if (!indexrdy_session->isready) {
                    master_ctx->all_workers_is_ready = false;
                    break;
                }
            }
        }
        if (master_ctx->all_workers_is_ready) {
            for (uint8_t indexrdy = 0; indexrdy < MAX_DBW_WORKERS; ++indexrdy) {
                master_worker_session_t *indexrdy_session = get_master_worker_session(master_ctx, DBW, indexrdy);
                if (session == NULL) {
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    return FAILURE;
                }
                if (!indexrdy_session->isready) {
                    master_ctx->all_workers_is_ready = false;
                    break;
                }
            }
        }
        if (master_ctx->all_workers_is_ready) {
            LOG_INFO("%s====================================================", label);
            LOG_INFO("%sAll Workers Is READY [Secure]", label);
            LOG_INFO("%s====================================================", label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            return SUCCESS_WRKSRDY;
        }
    }
//---------------------------------------------------------------------- 
    CLOSE_IPC_PROTOCOL(&received_protocol);
    return SUCCESS;
}
