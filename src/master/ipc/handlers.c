#include <stdint.h>
#include <stdio.h>

#include "log.h"
#include "ipc.h"
#include "types.h"
#include "master/master.h"
#include "master/ipc/handlers.h"
#include "ipc/protocol.h"
#include "stdbool.h"
#include "oritlsf.h"

status_t handle_master_ipc_closed_event(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, int *file_descriptor) {
	const char *worker_name = get_worker_name(wot);
    LOG_DEBUG("%sWorker UDS FD %d (%s Worker %d) terputus.", label, *file_descriptor, worker_name, index);
	return SUCCESS;
}

status_t handle_master_ipc_event(const char *label, master_context_t *master_ctx, int *file_descriptor, et_buffer_t *buffer) {
    et_result_t retr;
    retr.failure = false;
    retr.partial = true;
    retr.event_type = EIT_FD;
    retr.status = FAILURE;
    do {
        retr = receive_ipc_raw_protocol_message(&master_ctx->oritlsf_pool, file_descriptor, buffer);
        if (buffer->read_step == 1) {
            if (!retr.failure) {
                if (!retr.partial) {
                    ipc_raw_protocol_t_status_t ircvdi;
                    ircvdi.status = SUCCESS;
                    ircvdi.r_ipc_raw_protocol_t = (ipc_raw_protocol_t *)oritlsf_calloc(__FILE__, __LINE__, &master_ctx->oritlsf_pool, 1, sizeof(ipc_raw_protocol_t));
                    ircvdi.r_ipc_raw_protocol_t->n = (uint32_t)buffer->in_size_tb;
                    ircvdi.r_ipc_raw_protocol_t->recv_buffer = buffer->buffer_in;
                    buffer->buffer_in = NULL;
                    buffer->read_step = 0;
                    buffer->in_size_tb = 0;
                    buffer->in_size_c = 0;
                    if (ipc_read_cleartext_header(label, ircvdi.r_ipc_raw_protocol_t) != SUCCESS) {
                        CLOSE_IPC_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &ircvdi.r_ipc_raw_protocol_t);
                        return FAILURE;
                    }
                    worker_type_t rcvd_wot = ircvdi.r_ipc_raw_protocol_t->wot;
                    uint8_t rcvd_index = ircvdi.r_ipc_raw_protocol_t->index;
                    master_worker_session_t *session = get_master_worker_session(master_ctx, rcvd_wot, rcvd_index);
                    if (session == NULL) {
                        CLOSE_IPC_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &ircvdi.r_ipc_raw_protocol_t);
                        return FAILURE;
                    }
                    const char *worker_name = get_worker_name(rcvd_wot);
                    worker_security_t *security = session->security;
                    worker_rekeying_t *rekeying = session->rekeying;
                    int *worker_uds_fd = &session->upp->uds[0];
                    if (!security || !rekeying || *worker_uds_fd == -1) {
                        CLOSE_IPC_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &ircvdi.r_ipc_raw_protocol_t);
                        return FAILURE;
                    }
                    if (ipc_check_mac(
                            label, 
                            security->mac_key, 
                            ircvdi.r_ipc_raw_protocol_t
                        ) != SUCCESS
                    )
                    {
                        CLOSE_IPC_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &ircvdi.r_ipc_raw_protocol_t);
                        return FAILURE;
                    }
                    if (ipc_read_header(
                            label,  
                            security->mac_key, 
                            security->remote_nonce, 
                            ircvdi.r_ipc_raw_protocol_t
                        ) != SUCCESS
                    )
                    {
                        CLOSE_IPC_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &ircvdi.r_ipc_raw_protocol_t);
                        return FAILURE;
                    }
                    if (ipc_check_ctr(
                            label, 
                            security->aes_key, 
                            &security->remote_ctr, 
                            ircvdi.r_ipc_raw_protocol_t
                        ) != SUCCESS
                    )
                    {
                        CLOSE_IPC_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &ircvdi.r_ipc_raw_protocol_t);
                        return FAILURE;
                    }
                    switch (ircvdi.r_ipc_raw_protocol_t->type) {
                        case IPC_WORKER_MASTER_HELLO1: {
                            if (handle_master_ipc_hello1(label, master_ctx, rcvd_wot, rcvd_index, security, worker_name, worker_uds_fd, &ircvdi) != SUCCESS) {
                                return FAILURE;
                            }
                            break;
                        }
                        case IPC_WORKER_MASTER_HELLO2: {
                            status_t rhello2 = handle_master_ipc_hello2(label, master_ctx, rcvd_wot, rcvd_index, security, rekeying, worker_name, worker_uds_fd, &ircvdi);
                            if (rhello2 == SUCCESS_WRKSRDY) {
                                return SUCCESS_WRKSRDY;
                            }
                            if (rhello2 != SUCCESS) {
                                return FAILURE;
                            }
                            break;
                        }
                        case IPC_WORKER_MASTER_HEARTBEAT: {
                            if (handle_master_ipc_heartbeat(label, master_ctx, rcvd_wot, rcvd_index, security, &ircvdi) != SUCCESS) {
                                return FAILURE;
                            }
                            break;
                        }
                        case IPC_UDP_DATA: {
                            if (handle_master_ipc_udp_data(label, master_ctx, security, &ircvdi) != SUCCESS) {
                                return FAILURE;
                            }
                            break;
                        }
                        case IPC_WORKER_MASTER_INFO: {
                            if (handle_master_ipc_info(label, master_ctx, rcvd_wot, rcvd_index, security, &ircvdi) != SUCCESS) {
                                return FAILURE;
                            }
                            break;
                        }
                        case IPC_WORKER_WORKER_INFO: {
                            if (handle_worker_ipc_info(label, master_ctx, rcvd_wot, rcvd_index, security, &ircvdi) != SUCCESS) {
                                return FAILURE;
                            }
                            break;
                        }
                        default:
                            LOG_ERROR("%sUnknown IPC protocol type %d from UDS FD %d. Ignoring.", label, ircvdi.r_ipc_raw_protocol_t->type, *file_descriptor);
                            CLOSE_IPC_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &ircvdi.r_ipc_raw_protocol_t);
                    }
                }
            }
        }
//======================================================================
// !!!!!!Drain Sampe Kering!!!!!!
//======================================================================
    } while (retr.status == SUCCESS && retr.event_type == EIT_FD);
	return SUCCESS;
}
