#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <endian.h>

#include "log.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "types.h"
#include "utilities.h"
#include "master/ipc.h"
#include "master/process.h"
#include "master/workers.h"
#include "master/worker_ipc_cmds.h"
#include "pqc.h"
#include "poly1305-donna.h"
#include "aes.h"
#include "sessions/master_session.h"

worker_type_t_status_t handle_ipc_closed_event(const char *label, master_context_t *master_ctx, int *current_fd) {
	worker_type_t_status_t result;
	result.r_worker_type_t = UNKNOWN;
	result.status = FAILURE;
	result.index = (uint8_t)0xff;
    const char* worker_name = "Unknown";
    bool is_worker_uds = false;

    for (uint8_t i = 0; i < MAX_SIO_WORKERS; ++i) {
        if (*current_fd == master_ctx->sio_session[i].upp.uds[0]) {
            is_worker_uds = true;
            result.r_worker_type_t = SIO;
            worker_name = "SIO";
            result.index = i;
            break;
        }
    }
    if (!is_worker_uds) {
        for (uint8_t i = 0; i < MAX_LOGIC_WORKERS; ++i) {
            if (*current_fd == master_ctx->logic_session[i].upp.uds[0]) {
                is_worker_uds = true;
                result.r_worker_type_t = LOGIC;
                worker_name = "Logic";
                result.index = i;
                break;
            }
        }
    }
    if (!is_worker_uds) {
        for (uint8_t i = 0; i < MAX_COW_WORKERS; ++i) {
            if (*current_fd == master_ctx->cow_session[i].upp.uds[0]) {
                is_worker_uds = true;
                result.r_worker_type_t = COW;
                worker_name = "COW";
                result.index = i;
                break;
            }
        }
    }
    if (!is_worker_uds) {
        for (uint8_t i = 0; i < MAX_DBR_WORKERS; ++i) {
            if (*current_fd == master_ctx->dbr_session[i].upp.uds[0]) {
                is_worker_uds = true;
                result.r_worker_type_t = DBR;
                worker_name = "DBR";
                result.index = i;
                break;
            }
        }
    }
    if (!is_worker_uds) {
        for (uint8_t i = 0; i < MAX_DBW_WORKERS; ++i) {
            if (*current_fd == master_ctx->dbw_session[i].upp.uds[0]) {
                is_worker_uds = true;
                result.r_worker_type_t = DBW;
                worker_name = "DBW";
                result.index = i;
                break;
            }
        }
    }
    if (is_worker_uds) {
		LOG_DEBUG("%sWorker UDS FD %d (%s Worker %d) terputus.", label, *current_fd, worker_name, result.index);
        result.status = SUCCESS;			
		return result;
	}
	return result;
}

status_t handle_ipc_event(const char *label, master_context_t *master_ctx, int *current_fd) {
    ipc_raw_protocol_t_status_t ircvdi = receive_ipc_raw_protocol_message(label, current_fd);
	if (ircvdi.status != SUCCESS) {
		LOG_ERROR("%srecv_ipc_message from worker. %s", label, strerror(errno));
		return ircvdi.status;
	}
    worker_security_t *security = NULL;
    worker_type_t rcvd_wot = ircvdi.r_ipc_raw_protocol_t->wot;
    uint8_t rcvd_index = ircvdi.r_ipc_raw_protocol_t->index;
    if (rcvd_wot == SIO) {
        security = &master_ctx->sio_session[rcvd_index].security;
    } else if (rcvd_wot == LOGIC) {
        security = &master_ctx->logic_session[rcvd_index].security;
    } else if (rcvd_wot == COW) {
        security = &master_ctx->cow_session[rcvd_index].security;
    } else if (rcvd_wot == DBR) {
        security = &master_ctx->dbr_session[rcvd_index].security;
    } else if (rcvd_wot == DBW) {
        security = &master_ctx->dbw_session[rcvd_index].security;
    } else {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
    if (!security) {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
    if (check_mac_ctr(
            label, 
            security->aes_key, 
            security->mac_key, 
            &security->remote_ctr, 
            ircvdi.r_ipc_raw_protocol_t
        ) != SUCCESS
    )
    {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
	switch (ircvdi.r_ipc_raw_protocol_t->type) {
        case IPC_WORKER_MASTER_HELLO1: {
            ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(label,
                security->aes_key, security->remote_nonce, &security->remote_ctr,
                (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
            );
            if (deserialized_ircvdi.status != SUCCESS) {
                LOG_ERROR("%sipc_deserialize gagal dengan status %d.", label, deserialized_ircvdi.status);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return deserialized_ircvdi.status;
            } else {
                LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
            }           
            ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
            ipc_worker_master_hello1_t *ihello1i = received_protocol->payload.ipc_worker_master_hello1;
            uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
            if (security->hello1_rcvd) {
                LOG_ERROR("%sSudah ada HELLO1", label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            memcpy(security->kem_publickey, ihello1i->kem_publickey, KEM_PUBLICKEY_BYTES);
            if (KEM_ENCODE_SHAREDSECRET(
                security->kem_ciphertext, 
                kem_sharedsecret, 
                security->kem_publickey
            ) != 0)
            {
                LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
// hello1_ack masih memakai security->kem_sharedsecret kosong
// karena worker belum siap enkripsi
//----------------------------------------------------------------------
            if (master_worker_hello1_ack(master_ctx, rcvd_wot, rcvd_index) != SUCCESS) {
                LOG_ERROR("%sFailed to master_worker_hello1_ack.", label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
// setelah kirim hello1_ack
// pasang shared_secret di security->kem_sharedsecret
// untuk menerima pesan hello2 yang sudah terenkripsi
//----------------------------------------------------------------------
            memcpy(security->kem_sharedsecret, kem_sharedsecret, KEM_SHAREDSECRET_BYTES);
            kdf1(security->kem_sharedsecret, security->aes_key);
            kdf2(security->aes_key, security->mac_key);
            memset(kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
//----------------------------------------------------------------------
            security->hello1_rcvd = true;
            CLOSE_IPC_PROTOCOL(&received_protocol);
			break;
		}
        case IPC_WORKER_MASTER_HELLO2: {
            ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(label,
                security->aes_key, security->remote_nonce, &security->remote_ctr,
                (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
            );
            if (deserialized_ircvdi.status != SUCCESS) {
                LOG_ERROR("%sipc_deserialize gagal dengan status %d.", label, deserialized_ircvdi.status);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return deserialized_ircvdi.status;
            } else {
                LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
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
            memcpy(security->remote_nonce, ihello2i->encrypted_wot_index, AES_NONCE_BYTES);
            uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];   
            memcpy(encrypted_wot_index, ihello2i->encrypted_wot_index + AES_NONCE_BYTES, sizeof(uint8_t) + sizeof(uint8_t));
            uint8_t data_mac[AES_TAG_BYTES];
            memcpy(data_mac, ihello2i->encrypted_wot_index + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
            uint8_t encrypted_wot_index1[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t)];
            memcpy(encrypted_wot_index1, ihello2i->encrypted_wot_index, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
            uint8_t mac[AES_TAG_BYTES];
            poly1305_context mac_ctx;
            poly1305_init(&mac_ctx, security->kem_sharedsecret);
            poly1305_update(&mac_ctx, encrypted_wot_index1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t));
            poly1305_finish(&mac_ctx, mac);
            if (!poly1305_verify(mac, data_mac)) {
                LOG_ERROR("%sFailed to Mac Tidak Sesuai.", label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }            
            uint32_t temp_remote_ctr = (uint32_t)0;
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
            uint8_t decrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t)];
            aes256ctx aes_ctx;
            aes256_ctr_keyexp(&aes_ctx, security->kem_sharedsecret);
//=========================================IV===========================    
            uint8_t keystream_buffer[sizeof(uint8_t) + sizeof(uint8_t)];
            uint8_t iv[AES_IV_BYTES];
            memcpy(iv, security->remote_nonce, AES_NONCE_BYTES);
            uint32_t remote_ctr_be = htobe32(temp_remote_ctr);
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
            if (*(uint8_t *)&rcvd_wot != *(uint8_t *)&data_wot) {
                LOG_ERROR("%sberbeda wot.", label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            uint8_t data_index;
            memcpy(&data_index, decrypted_wot_index + sizeof(uint8_t), sizeof(uint8_t));
            if (rcvd_index != data_index) {
                LOG_ERROR("%sberbeda index.", label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            if (master_worker_hello2_ack(master_ctx, rcvd_wot, rcvd_index) != SUCCESS) {
                LOG_ERROR("%sFailed to master_worker_hello2_ack.", label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
// Menganggap data valid dengan integritas
//---------------------------------------------------------------------- 
            security->remote_ctr = (uint32_t)1;//sudah melakukan dekripsi data valid 1 kali
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
            bool is_all_workers_ready = true;
            for (uint8_t indexrdy = 0; indexrdy < MAX_SIO_WORKERS; ++indexrdy) {
                if (!master_ctx->sio_session[indexrdy].isready) {
                    is_all_workers_ready = false;
                    break;
                }
            }
            if (is_all_workers_ready) {
                for (uint8_t indexrdy = 0; indexrdy < MAX_LOGIC_WORKERS; ++indexrdy) {
                    if (!master_ctx->logic_session[indexrdy].isready) {
                        is_all_workers_ready = false;
                        break;
                    }
                }
            }
            if (is_all_workers_ready) {
                for (uint8_t indexrdy = 0; indexrdy < MAX_COW_WORKERS; ++indexrdy) {
                    if (!master_ctx->cow_session[indexrdy].isready) {
                        is_all_workers_ready = false;
                        break;
                    }
                }
            }
            if (is_all_workers_ready) {
                for (uint8_t indexrdy = 0; indexrdy < MAX_DBR_WORKERS; ++indexrdy) {
                    if (!master_ctx->dbr_session[indexrdy].isready) {
                        is_all_workers_ready = false;
                        break;
                    }
                }
            }
            if (is_all_workers_ready) {
                for (uint8_t indexrdy = 0; indexrdy < MAX_DBW_WORKERS; ++indexrdy) {
                    if (!master_ctx->dbw_session[indexrdy].isready) {
                        is_all_workers_ready = false;
                        break;
                    }
                }
            }
            if (is_all_workers_ready) {
                LOG_INFO("%s====================================================", label);
                LOG_INFO("%sSEMUA WORKER SUDAH READY", label);
                LOG_INFO("%s====================================================", label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return SUCCESS_WRKSRDY;
            }
//---------------------------------------------------------------------- 
            CLOSE_IPC_PROTOCOL(&received_protocol);
			break;
		}
		case IPC_WORKER_MASTER_HEARTBEAT: {
            ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(label,
                security->aes_key, security->remote_nonce, &security->remote_ctr,
                (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
            );
            if (deserialized_ircvdi.status != SUCCESS) {
                LOG_ERROR("%sipc_deserialize gagal dengan status %d.", label, deserialized_ircvdi.status);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return deserialized_ircvdi.status;
            } else {
                LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
            }           
            ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
            ipc_worker_master_heartbeat_t *iheartbeati = received_protocol->payload.ipc_worker_master_heartbeat;
            uint64_t_status_t rt = get_realtime_time_ns(label);
            if (rcvd_wot == SIO) {
                LOG_DEBUG("%sSIO %d set last_ack to %llu.", label, rcvd_index, rt.r_uint64_t);
                master_ctx->sio_session[rcvd_index].metrics.last_ack = rt.r_uint64_t;
                master_ctx->sio_session[rcvd_index].metrics.count_ack += (double)1;
                master_ctx->sio_session[rcvd_index].metrics.sum_hbtime += iheartbeati->hbtime;
                master_ctx->sio_session[rcvd_index].metrics.hbtime = iheartbeati->hbtime;
            } else if (rcvd_wot == LOGIC) {
                LOG_DEBUG("%sLogic %d set last_ack to %llu.", label, rcvd_index, rt.r_uint64_t);
                master_ctx->logic_session[rcvd_index].metrics.last_ack = rt.r_uint64_t;
                master_ctx->logic_session[rcvd_index].metrics.count_ack += (double)1;
                master_ctx->logic_session[rcvd_index].metrics.sum_hbtime += iheartbeati->hbtime;
                master_ctx->logic_session[rcvd_index].metrics.hbtime = iheartbeati->hbtime;
            } else if (rcvd_wot == COW) {
                LOG_DEBUG("%sCOW %d set last_ack to %llu.", label, rcvd_index, rt.r_uint64_t);
                master_ctx->cow_session[rcvd_index].metrics.last_ack = rt.r_uint64_t;
                master_ctx->cow_session[rcvd_index].metrics.count_ack += (double)1;
                master_ctx->cow_session[rcvd_index].metrics.sum_hbtime += iheartbeati->hbtime;
                master_ctx->cow_session[rcvd_index].metrics.hbtime = iheartbeati->hbtime;
            } else if (rcvd_wot == DBR) {
                LOG_DEBUG("%sDBR %d set last_ack to %llu.", label, rcvd_index, rt.r_uint64_t);
                master_ctx->dbr_session[rcvd_index].metrics.last_ack = rt.r_uint64_t;
                master_ctx->dbr_session[rcvd_index].metrics.count_ack += (double)1;
                master_ctx->dbr_session[rcvd_index].metrics.sum_hbtime += iheartbeati->hbtime;
                master_ctx->dbr_session[rcvd_index].metrics.hbtime = iheartbeati->hbtime;
            } else if (rcvd_wot == DBW) {
                LOG_DEBUG("%sDBW %d set last_ack to %llu.", label, rcvd_index, rt.r_uint64_t);
                master_ctx->dbw_session[rcvd_index].metrics.last_ack = rt.r_uint64_t;
                master_ctx->dbw_session[rcvd_index].metrics.count_ack += (double)1;
                master_ctx->dbw_session[rcvd_index].metrics.sum_hbtime += iheartbeati->hbtime;
                master_ctx->dbw_session[rcvd_index].metrics.hbtime = iheartbeati->hbtime;
            } else {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
			break;
		}
        case IPC_COW_MASTER_CONNECTION: {
            ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(label,
                security->aes_key, security->remote_nonce, &security->remote_ctr,
                (uint8_t*)ircvdi.r_ipc_raw_protocol_t->recv_buffer, ircvdi.r_ipc_raw_protocol_t->n
            );
            if (deserialized_ircvdi.status != SUCCESS) {
                LOG_ERROR("%sipc_deserialize gagal dengan status %d.", label, deserialized_ircvdi.status);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                return deserialized_ircvdi.status;
            } else {
                LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
                CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
            }           
            ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
            ipc_cow_master_connection_t *icowconni = received_protocol->payload.ipc_cow_master_connection;
            for (int i = 0; i < MAX_MASTER_COW_SESSIONS; ++i) {
                if (
                    master_ctx->cow_c_session[i].in_use &&
                    sockaddr_equal((const struct sockaddr *)&master_ctx->cow_c_session[i].server_addr, (const struct sockaddr *)&icowconni->server_addr)
                   )
                {
                    calculate_avgtt(label, master_ctx, rcvd_wot, rcvd_index);
                    master_ctx->cow_c_session[i].cow_index = -1;
                    master_ctx->cow_c_session[i].in_use = false;
                    memset(&master_ctx->cow_c_session[i].server_addr, 0, sizeof(struct sockaddr_in6));
                    break;
                }
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            break;
        }
		default:
			LOG_ERROR("%sUnknown protocol type %d from UDS FD %d. Ignoring.", label, ircvdi.r_ipc_raw_protocol_t->type, *current_fd);
			CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
	}
	return SUCCESS;
}
