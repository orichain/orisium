#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdbool.h>

#include "log.h"
#include "utilities.h"
#include "orilink/protocol.h"
#include "types.h"
#include "master/socket_listenner.h"
#include "master/process.h"
#include "master/worker_metrics.h"
#include "master/worker_selector.h"
#include "async.h"
#include "constants.h"
#include "pqc.h"
#include "sessions/master_session.h"
#include "master/server_orilink.h"

status_t setup_socket_listenner(const char *label, master_context *master_ctx, uint16_t *listen_port) {
    struct sockaddr_in6 addr;
    int opt = 1;
    int v6only = 0;
    
    master_ctx->listen_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (master_ctx->listen_sock == -1) {
		LOG_ERROR("%ssocket failed. %s", label, strerror(errno));
        return FAILURE;
    }
    status_t r_snbkg = set_nonblocking(label, master_ctx->listen_sock);
    if (r_snbkg != SUCCESS) {
        LOG_ERROR("%sset_nonblocking failed.", label);
        return r_snbkg;
    }
    if (setsockopt(master_ctx->listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        LOG_ERROR("%ssetsockopt failed. %s", label, strerror(errno));
        return FAILURE;
    }
    if (setsockopt(master_ctx->listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
		LOG_ERROR("%ssetsockopt failed. %s", label, strerror(errno));
        return FAILURE;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(*listen_port);
    addr.sin6_addr = in6addr_any;
    if (bind(master_ctx->listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("%sbind failed. %s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

status_t handle_listen_sock_event(const char *label, master_context *master_ctx, uint16_t *listen_port) {
    struct sockaddr_in6 client_addr;
	char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    
    orilink_raw_protocol_t_status_t orcvdo = receive_orilink_raw_protocol_packet(
        label,
        &master_ctx->listen_sock,
        (struct sockaddr *)&client_addr
    );
    if (orcvdo.status != SUCCESS) return orcvdo.status;
    int getname_res = getnameinfo((struct sockaddr *)&client_addr, sizeof(struct sockaddr_in6),
						host_str, NI_MAXHOST,
					  	port_str, NI_MAXSERV,
					  	NI_NUMERICHOST | NI_NUMERICSERV
					  );
	if (getname_res != 0) {
		LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
		return FAILURE;
	}
    size_t host_str_len = strlen(host_str);
    if (host_str_len >= INET6_ADDRSTRLEN) {
        LOG_ERROR("%sKoneksi ditolak dari IP %s. IP terlalu panjang.", label, host_str);
        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
        return FAILURE_IVLDIP;
    }
    char *endptr;
    long port_num = strtol(port_str, &endptr, 10);
    if (*endptr != '\0' || port_num <= 0 || port_num > 65535) {
		LOG_ERROR("%sKoneksi ditolak dari IP %s. PORT di luar rentang (1-65535).", label, host_str);
        CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
        return FAILURE_IVLDPORT;
    }
    switch (orcvdo.r_orilink_raw_protocol_t->type) {
        case ORILINK_HELLO1: {
            bool ip_already_connected = false;
            for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                if (
                        master_ctx->sio_c_session[i].in_use &&
                        sockaddr_equal((const struct sockaddr *)&master_ctx->sio_c_session[i].old_client_addr, (const struct sockaddr *)&client_addr) &&
                        master_ctx->sio_c_session[i].hello1_ack.rcvd
                   )
                {
                    ip_already_connected = true;
                    break;
                }
            }
            if (ip_already_connected) {
                LOG_WARN("%sHELLO1 ditolak dari IP %s. Sudah ada HELLO1 dari IP ini.", label, host_str);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE_ALRDYCONTD;
            }
            int sio_worker_idx = select_best_worker(label, master_ctx, SIO);
            if (sio_worker_idx == -1) {
                LOG_ERROR("%sFailed to select an SIO worker for new client IP %s. Rejecting.", label, host_str);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE_NOSLOT;
            }
            int slot_found = -1;
            for(int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                if(!master_ctx->sio_c_session[i].in_use) {
                    master_ctx->sio_c_session[i].sio_index = sio_worker_idx;
                    master_ctx->sio_c_session[i].in_use = true;
                    memcpy(&master_ctx->sio_c_session[i].old_client_addr, &client_addr, sizeof(struct sockaddr_in6));
                    slot_found = i;
                    break;
                }
            }
            if (slot_found == -1) {
                LOG_ERROR("%sWARNING: No free session slots in master_ctx->sio_c_session. Rejecting client IP %s.", label, host_str);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE_NOSLOT;
            }
            if (new_task_metrics(label, master_ctx, SIO, sio_worker_idx) != SUCCESS) {
                LOG_ERROR("%sFailed to input new task in SIO %d metrics.", label, sio_worker_idx);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE;
            }
            uint64_t_status_t rt = get_realtime_time_ns(label);
            if (rt.status != SUCCESS) {
                LOG_ERROR("%sFailed to get_realtime_time_ns.", label);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE;
            }
            LOG_DEVEL_DEBUG("%sNew client connected from IP %s.", label, host_str);
            master_sio_c_session_t *session = &master_ctx->sio_c_session[slot_found];
            orilink_protocol_t_status_t deserialized_orcvdo = orilink_deserialize(label,
                session->identity.kem_sharedsecret, session->remote_nonce, session->remote_ctr,
                (const uint8_t*)orcvdo.r_orilink_raw_protocol_t->recv_buffer, orcvdo.r_orilink_raw_protocol_t->n
            );
            if (deserialized_orcvdo.status != SUCCESS) {
                LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", label, deserialized_orcvdo.status);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return deserialized_orcvdo.status;
            } else {
                LOG_DEBUG("%sorilink_deserialize BERHASIL.", label);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
            }  
            orilink_protocol_t* received_protocol = deserialized_orcvdo.r_orilink_protocol_t;
            orilink_hello1_t *ohello1 = received_protocol->payload.orilink_hello1;
            session->hello1_ack.rcvd = true;
            session->hello1_ack.rcvd_time = rt.r_uint64_t;
            session->identity.client_id = ohello1->client_id;
            memcpy(session->client_kem_publickey, ohello1->publickey1, KEM_PUBLICKEY_BYTES / 2);
//====================================================================== 
// SEND HELLO1_ACK                   
//====================================================================== 
            if (async_create_timerfd(label, &session->hello1_ack.ack_timer_fd) != SUCCESS) {
                LOG_ERROR("%sFailed to async_create_timerfd.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
            if (send_hello1_ack(label, &master_ctx->listen_sock, session) != SUCCESS) {
                LOG_ERROR("%sFailed to send_hello1_ack.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
            if (async_create_incoming_event(label, &master_ctx->master_async, &session->hello1_ack.ack_timer_fd) != SUCCESS) {
                LOG_ERROR("%sFailed to async_create_incoming_event.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }        
//======================================================================
            CLOSE_ORILINK_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO2: {
            int session_index = -1;
            for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                if (
                        master_ctx->sio_c_session[i].in_use &&
                        sockaddr_equal((const struct sockaddr *)&master_ctx->sio_c_session[i].old_client_addr, (const struct sockaddr *)&client_addr) &&
                        master_ctx->sio_c_session[i].hello1_ack.ack_sent &&
                        (!master_ctx->sio_c_session[i].hello2_ack.rcvd)
                   )
                {
                    session_index = i;
                    break;
                }
            }
            if (session_index == -1) {
                LOG_WARN("%sHELLO2 ditolak dari IP %s. Tidak pernah mengirim HELLO1_ACK ke IP ini atau HELLO2 dari IP ini sudah ditangani.", label, host_str);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE_IVLDHDLD;
            }
            master_sio_c_session_t *session = &master_ctx->sio_c_session[session_index];
            orilink_protocol_t_status_t deserialized_orcvdo = orilink_deserialize(label,
                session->identity.kem_sharedsecret, session->remote_nonce, session->remote_ctr,
                (const uint8_t*)orcvdo.r_orilink_raw_protocol_t->recv_buffer, orcvdo.r_orilink_raw_protocol_t->n
            );
            if (deserialized_orcvdo.status != SUCCESS) {
                LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", label, deserialized_orcvdo.status);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return deserialized_orcvdo.status;
            } else {
                LOG_DEBUG("%sorilink_deserialize BERHASIL.", label);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
            }  
            orilink_protocol_t* received_protocol = deserialized_orcvdo.r_orilink_protocol_t;
            orilink_hello2_t *ohello2 = received_protocol->payload.orilink_hello2;
            if (master_ctx->sio_c_session[session_index].identity.client_id != ohello2->client_id) {
                LOG_WARN("%sHELLO2 ditolak dari IP %s. client_id berbeda.", label, host_str);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE_DIFCLID;
            }
            double try_count = (double)session->hello1_ack.ack_sent_try_count-(double)1;
            sio_c_calculate_retry(label, session, session_index, try_count);
            uint64_t_status_t rt = get_realtime_time_ns(label);
            if (rt.status != SUCCESS) {
                LOG_ERROR("%sFailed to get_realtime_time_ns.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            session->hello2_ack.rcvd = true;
            session->hello2_ack.rcvd_time = rt.r_uint64_t;
            memcpy(session->client_kem_publickey + (KEM_PUBLICKEY_BYTES / 2), ohello2->publickey2, KEM_PUBLICKEY_BYTES / 2);
            uint64_t interval_ull = session->hello2_ack.rcvd_time - session->hello1_ack.ack_sent_time;
            double rtt_value = (double)interval_ull;
            sio_c_calculate_rtt(label, session, session_index, rtt_value);
            cleanup_hello_ack(label, &master_ctx->master_async, &session->hello1_ack);            
//======================================================================
// Generate Identity                    
//======================================================================
            if (KEM_GENERATE_KEYPAIR(session->identity.kem_publickey, session->identity.kem_privatekey) != 0) {
                LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
// disimpan di temp_kem_sharedsecret terlebih dahulu karena clienr
// belum siap
//----------------------------------------------------------------------
            if (KEM_ENCODE_SHAREDSECRET(session->identity.kem_ciphertext, session->temp_kem_sharedsecret, session->client_kem_publickey) != 0) {
                LOG_ERROR("%sFailed to KEM_ENCODE_SHAREDSECRET.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//====================================================================== 
// SEND HELLO2_ACK                   
//====================================================================== 
            if (async_create_timerfd(label, &session->hello2_ack.ack_timer_fd) != SUCCESS) {
                LOG_ERROR("%sFailed to async_create_timerfd.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
            if (send_hello2_ack(label, &master_ctx->listen_sock, session) != SUCCESS) {
                LOG_ERROR("%sFailed to send_hello2_ack.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
            if (async_create_incoming_event(label, &master_ctx->master_async, &session->hello2_ack.ack_timer_fd) != SUCCESS) {
                LOG_ERROR("%sFailed to async_create_incoming_event.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }        
//======================================================================                       
            print_hex(label, session->identity.kem_ciphertext, KEM_CIPHERTEXT_BYTES, 1);
            CLOSE_ORILINK_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO3: {
            int session_index = -1;
            for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                if (
                        master_ctx->sio_c_session[i].in_use &&
                        sockaddr_equal((const struct sockaddr *)&master_ctx->sio_c_session[i].old_client_addr, (const struct sockaddr *)&client_addr) &&
                        master_ctx->sio_c_session[i].hello1_ack.ack_sent &&
                        master_ctx->sio_c_session[i].hello2_ack.ack_sent &&
                        (!master_ctx->sio_c_session[i].hello3_ack.rcvd)
                   )
                {
                    session_index = i;
                    break;
                }
            }
            if (session_index == -1) {
                LOG_WARN("%sHELLO3 ditolak dari IP %s. Tidak pernah mengirim HELLO1_ACK dan atau HELLO2_ACK ke IP ini atau HELLO3 dari IP ini sudah ditangani.", label, host_str);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE_IVLDHDLD;
            }
            master_sio_c_session_t *session = &master_ctx->sio_c_session[session_index];
            orilink_protocol_t_status_t deserialized_orcvdo = orilink_deserialize(label,
                session->identity.kem_sharedsecret, session->remote_nonce, session->remote_ctr,
                (const uint8_t*)orcvdo.r_orilink_raw_protocol_t->recv_buffer, orcvdo.r_orilink_raw_protocol_t->n
            );
            if (deserialized_orcvdo.status != SUCCESS) {
                LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", label, deserialized_orcvdo.status);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return deserialized_orcvdo.status;
            } else {
                LOG_DEBUG("%sorilink_deserialize BERHASIL.", label);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
            }  
            orilink_protocol_t* received_protocol = deserialized_orcvdo.r_orilink_protocol_t;
            orilink_hello3_t *ohello3 = received_protocol->payload.orilink_hello3;
            if (master_ctx->sio_c_session[session_index].identity.client_id != ohello3->client_id) {
                LOG_WARN("%sHELLO3 ditolak dari IP %s. client_id berbeda.", label, host_str);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE_DIFCLID;
            }
            double try_count = (double)session->hello2_ack.ack_sent_try_count-(double)1;
            sio_c_calculate_retry(label, session, session_index, try_count);
            uint64_t_status_t rt = get_realtime_time_ns(label);
            if (rt.status != SUCCESS) {
                LOG_ERROR("%sFailed to get_realtime_time_ns.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            session->hello3_ack.rcvd = true;
            session->hello3_ack.rcvd_time = rt.r_uint64_t;
            uint64_t interval_ull = session->hello3_ack.rcvd_time - session->hello2_ack.ack_sent_time;
            double rtt_value = (double)interval_ull;
            sio_c_calculate_rtt(label, session, session_index, rtt_value);
            cleanup_hello_ack(label, &master_ctx->master_async, &session->hello2_ack);            
//======================================================================
// Generate Nonce, Server ID, Port
//======================================================================
            if (generate_nonce(label, session->local_nonce) != SUCCESS) {
                LOG_ERROR("%sFailed to generate_nonce.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            if (generate_connection_id(label, &session->identity.server_id) != SUCCESS) {
                LOG_ERROR("%sFailed to generate_connection_id.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            session->identity.port = *listen_port + session_index;
//====================================================================== 
// SEND HELLO3_ACK                   
//====================================================================== 
            if (async_create_timerfd(label, &session->hello3_ack.ack_timer_fd) != SUCCESS) {
                LOG_ERROR("%sFailed to async_create_timerfd.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
            if (send_hello3_ack(label, &master_ctx->listen_sock, session) != SUCCESS) {
                LOG_ERROR("%sFailed to send_hello3_ack.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
            if (async_create_incoming_event(label, &master_ctx->master_async, &session->hello3_ack.ack_timer_fd) != SUCCESS) {
                LOG_ERROR("%sFailed to async_create_incoming_event.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }        
//======================================================================   
            CLOSE_ORILINK_PROTOCOL(&received_protocol);
            break;
        }
        default:
            CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
            return FAILURE;
    }
	return SUCCESS;
}
