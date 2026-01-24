#ifndef WORKERS_WORKER_IPC_INFO_H
#define WORKERS_WORKER_IPC_INFO_H

#include "ipc.h"
#include "node.h"
#include "types.h"
#include "workers/master_ipc_cmds.h"
#include "workers/workers.h"
#include "globals.h"

static inline status_t handle_master_workers_ipc_info(worker_context_t *worker_ctx, double *initial_delay_ms, ipc_raw_protocol_t_status_t *ircvdi) {
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label, &worker_ctx->oritlsf_pool,
            worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
            (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
            );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&worker_ctx->oritlsf_pool, &ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&worker_ctx->oritlsf_pool, &ircvdi->r_ipc_raw_protocol_t);
    }
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_master_worker_info_t *iinfoi = received_protocol->payload.ipc_master_worker_info;
    switch (iinfoi->flag) {
        case IT_SHUTDOWN: {
                              LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", worker_ctx->label);
                              CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                              worker_ctx->shutdown_requested = 1;
                              break;
                          }
        case IT_WAKEUP: {
                            LOG_INFO("%sIT_WAKEUP received...", worker_ctx->label);
                            CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
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
                               CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                               return FAILURE;
                           }
                           if (worker_master_hello1(worker_ctx) != SUCCESS) {
                               LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
                               worker_ctx->shutdown_requested = 1;
                               CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                               return FAILURE;
                           }
                           CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
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
                                  CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                                  return FAILURE;
                              }
                              worker_ctx->hello1_sent = false;
                              worker_ctx->hello1_ack_rcvd = false;
                              worker_ctx->hello2_sent = false;
                              worker_ctx->hello2_ack_rcvd = false;
                              if (worker_master_hello1(worker_ctx) != SUCCESS) {
                                  LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
                                  worker_ctx->shutdown_requested = 1;
                                  CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                                  return FAILURE;
                              }
                              CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                              break;
                          }
        case IT_AWKSRDY: {
                             if (worker_master_worker_info(worker_ctx, DBR, 0xff, IT_READNKEYS) != SUCCESS) {
                                 LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
                                 worker_ctx->shutdown_requested = 1;
                                 CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                                 return FAILURE;
                             }
                             CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                             break;
                         }
        default:
                         LOG_ERROR("%sUnknown Info Flag %d from Master. Ignoring.", worker_ctx->label, iinfoi->flag);
                         CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
    }
    return SUCCESS;
}

static inline status_t handle_worker_workers_ipc_info(worker_context_t *worker_ctx, ipc_raw_protocol_t_status_t *ircvdi) {
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label, &worker_ctx->oritlsf_pool,
            worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
            (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
            );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&worker_ctx->oritlsf_pool, &ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&worker_ctx->oritlsf_pool, &ircvdi->r_ipc_raw_protocol_t);
    }
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_worker_worker_info_t *iinfoi = received_protocol->payload.ipc_worker_worker_info;
    switch (iinfoi->flag) {
		case IT_READNKEYS: {
			                   nodekeys_t *out_nodekeys_keys = NULL;
                               int rc = nodekeys_keys_get_last(worker_ctx->label, &worker_ctx->oritlsf_pool, g_nodekeys_env, g_nodekeys_keys, &out_nodekeys_keys);
                               if (rc == MDB_SUCCESS) {
				                   LOG_ERROR("%sKeys Ada", worker_ctx->label);
				                   oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&out_nodekeys_keys);
			                   } else {
				                   if (worker_master_worker_info(worker_ctx, iinfoi->src_wot, iinfoi->src_index, IT_NKEYSEMPTY) != SUCCESS) {
					                   LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
					                   worker_ctx->shutdown_requested = 1;
					                   CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
					                   return FAILURE;
				                   }
			                   }
                               CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                               break;
                           }
        case IT_NKEYSEMPTY: {
			                    if (worker_master_worker_info(worker_ctx, DBW, 0x00, IT_APPNDNKEYS) != SUCCESS) {
				                    LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
				                    worker_ctx->shutdown_requested = 1;
				                    CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
				                    return FAILURE;
			                    }
                                CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                                break;
                            }
        case IT_APPNDNKEYS: {
			                    nodekeys_t *nodekeys = (nodekeys_t *)oritlsf_calloc(__FILE__, __LINE__, &worker_ctx->oritlsf_pool, 1, sizeof(nodekeys_t));
			                    nodekeys->no = 0;
			                    nodekeys->vermaj = NODEKEYS_VERSION_MAJOR;
			                    nodekeys->vermin = NODEKEYS_VERSION_MINOR;
			                    SIGN_GENERATE_KEYPAIR(nodekeys->sgn_publickey, nodekeys->sgn_privatekey);
			                    KEM_GENERATE_KEYPAIR(nodekeys->kem_publickey, nodekeys->kem_privatekey);
			                    int rc = nodekeys_keys_append(worker_ctx->label, g_nodekeys_env, g_nodekeys_keys, nodekeys);
			                    memset(nodekeys->sgn_privatekey, 0, SIGN_PRIVATEKEY_BYTES);
			                    memset(nodekeys->kem_privatekey, 0, KEM_PRIVATEKEY_BYTES);
			                    oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&nodekeys);
			                    if (rc == MDB_SUCCESS) {
				                    if (worker_master_worker_info(worker_ctx, iinfoi->src_wot, iinfoi->src_index, IT_APPNDNKEYS_SUCCESS) != SUCCESS) {
					                    LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
					                    worker_ctx->shutdown_requested = 1;
					                    CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
					                    return FAILURE;
				                    }
			                    } else {
				                    if (worker_master_worker_info(worker_ctx, iinfoi->src_wot, iinfoi->src_index, IT_APPNDNKEYS_FAILURE) != SUCCESS) {
					                    LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
					                    worker_ctx->shutdown_requested = 1;
					                    CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
					                    return FAILURE;
				                    }
			                    }
			                    CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
			                    break;
		                    }
		case IT_APPNDNKEYS_SUCCESS: {
			                            if (worker_master_worker_info(worker_ctx, DBR, 0xff, IT_READNKEYS) != SUCCESS) {
                                            LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
                                            worker_ctx->shutdown_requested = 1;
                                            CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                                            return FAILURE;
                                        }
                                        CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                                        break;
                                    }
        case IT_APPNDNKEYS_FAILURE: {
			                            LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
			                            worker_ctx->shutdown_requested = 1;
			                            CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
			                            return FAILURE;
                                        break;
                                    }
        case IT_READERA: {
			                 era_t *out_database_era = NULL;
                             int rc = database_era_get_last(worker_ctx->label, &worker_ctx->oritlsf_pool, g_database_env, g_database_era, &out_database_era);
                             if (rc == MDB_SUCCESS) {
				                 LOG_ERROR("%sEra Ada", worker_ctx->label);
				                 oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&out_database_era);
			                 } else {
				                 if (worker_master_worker_info(worker_ctx, iinfoi->src_wot, iinfoi->src_index, IT_ERAEMPTY) != SUCCESS) {
					                 LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
					                 worker_ctx->shutdown_requested = 1;
					                 CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
					                 return FAILURE;
				                 }
			                 }
                             CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                             break;
                         }
        case IT_ERAEMPTY: {
			                  if (worker_master_worker_info(worker_ctx, DBW, 0x00, IT_APPNDERA) != SUCCESS) {
				                  LOG_ERROR("%sWorker error. Initiating graceful shutdown...", worker_ctx->label);
				                  worker_ctx->shutdown_requested = 1;
				                  CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
				                  return FAILURE;
			                  }
                              CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
                              break;
                          }
        default:
                          LOG_ERROR("%sUnknown Info Flag %d from Master. Ignoring.", worker_ctx->label, iinfoi->flag);
                          CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &received_protocol);
    }
    return SUCCESS;
}

#endif
