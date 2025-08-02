#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdbool.h>
#include <endian.h>

#include "log.h"
#include "utilities.h"
#include "orilink/protocol.h"
#include "types.h"
#include "master/socket_listenner.h"
#include "master/master.h"
#include "master/worker_metrics.h"
#include "master/worker_selector.h"
#include "async.h"
#include "constants.h"
#include "pqc.h"
#include "master/server_orilink.h"
#include "poly1305-donna.h"
#include "aes.h"

status_t setup_socket_listenner(const char *label, master_context_t *master_ctx) {
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
    addr.sin6_port = htons(master_ctx->listen_port);
    addr.sin6_addr = in6addr_any;
    if (bind(master_ctx->listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("%sbind failed. %s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}

status_t handle_listen_sock_event(const char *label, master_context_t *master_ctx) {
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
                        sockaddr_equal((const struct sockaddr *)&master_ctx->sio_c_session[i].identity.remote_addr, (const struct sockaddr *)&client_addr) &&
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
                    memcpy(&master_ctx->sio_c_session[i].identity.remote_addr, &client_addr, sizeof(struct sockaddr_in6));
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
            LOG_DEBUG("%sNew client connected from IP %s.", label, host_str);
            master_sio_c_session_t *session = &master_ctx->sio_c_session[slot_found];
            orilink_protocol_t_status_t deserialized_orcvdo = orilink_deserialize(label,
                session->identity.kem_sharedsecret, session->identity.remote_nonce, session->identity.remote_ctr,
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
            bool client_id_found = false;
            for(int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                if(master_ctx->sio_c_session[i].in_use && (ohello1->client_id == master_ctx->sio_c_session[i].identity.client_id)) {
                    client_id_found = true;
                    break;
                }
            }
            if (client_id_found) {
                LOG_WARN("%sHELLO1 ditolak dari IP %s. Sudah ada client_id yang sama.", label, host_str);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE;
            }
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
//----------------------------------------------------------------------
// Semua sudah bersih
//----------------------------------------------------------------------
            session->hello1_ack.rcvd = true;
            session->hello1_ack.rcvd_time = rt.r_uint64_t;
//======================================================================
            CLOSE_ORILINK_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO2: {
            int session_index = -1;
            for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                if (
                        master_ctx->sio_c_session[i].in_use &&
                        sockaddr_equal((const struct sockaddr *)&master_ctx->sio_c_session[i].identity.remote_addr, (const struct sockaddr *)&client_addr) &&
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
                session->identity.kem_sharedsecret, session->identity.remote_nonce, session->identity.remote_ctr,
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
            memcpy(session->client_kem_publickey + (KEM_PUBLICKEY_BYTES / 2), ohello2->publickey2, KEM_PUBLICKEY_BYTES / 2);
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
// saat terima hello_end dari client segera pindah
// session->temp_kem_sharedsecret ke session->identity.kem_sharedsecret
// untuk membaca helo_end dari client
// data heloo_end belum terenkripsi karena berisi nonce
// namun sudah ada pengecekan mac menggunakan sharedsecret
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
// Hitung rtt retry sebelum kirim data
//----------------------------------------------------------------------
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
            uint64_t interval_ull = session->hello2_ack.rcvd_time - session->hello1_ack.ack_sent_time;
            double rtt_value = (double)interval_ull;
            sio_c_calculate_rtt(label, session, session_index, rtt_value);
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
//----------------------------------------------------------------------
// Semua sudah bersih
//----------------------------------------------------------------------
            cleanup_hello_ack(label, &master_ctx->master_async, &session->hello1_ack);  
//======================================================================                       
            CLOSE_ORILINK_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO3: {
            int session_index = -1;
            for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                if (
                        master_ctx->sio_c_session[i].in_use &&
                        sockaddr_equal((const struct sockaddr *)&master_ctx->sio_c_session[i].identity.remote_addr, (const struct sockaddr *)&client_addr) &&
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
                session->identity.kem_sharedsecret, session->identity.remote_nonce, session->identity.remote_ctr,
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
//======================================================================
// Generate Nonce, Server ID, Port
//======================================================================
            if (generate_nonce(label, session->identity.local_nonce) != SUCCESS) {
                LOG_ERROR("%sFailed to generate_nonce.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            if (generate_connection_id(label, &session->identity.server_id) != SUCCESS) {
                LOG_ERROR("%sFailed to generate_connection_id.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            session->identity.port = master_ctx->listen_port + session_index + 1;
//====================================================================== 
// SEND HELLO3_ACK                   
//====================================================================== 
            if (async_create_timerfd(label, &session->hello3_ack.ack_timer_fd) != SUCCESS) {
                LOG_ERROR("%sFailed to async_create_timerfd.", label);
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
// Hitung rtt retry sebelum kirim data
//----------------------------------------------------------------------
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
//----------------------------------------------------------------------
// Semua sudah bersih
//----------------------------------------------------------------------
            cleanup_hello_ack(label, &master_ctx->master_async, &session->hello2_ack);
//======================================================================   
            CLOSE_ORILINK_PROTOCOL(&received_protocol);
            break;
        }
        case ORILINK_HELLO_END: {
            int session_index = -1;
            for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                if (
                        master_ctx->sio_c_session[i].in_use &&
                        sockaddr_equal((const struct sockaddr *)&master_ctx->sio_c_session[i].identity.remote_addr, (const struct sockaddr *)&client_addr) &&
                        master_ctx->sio_c_session[i].hello1_ack.ack_sent &&
                        master_ctx->sio_c_session[i].hello2_ack.ack_sent &&
                        master_ctx->sio_c_session[i].hello3_ack.ack_sent &&
                        (!master_ctx->sio_c_session[i].sock_ready.rcvd)
                   )
                {
                    session_index = i;
                    break;
                }
            }
            if (session_index == -1) {
                LOG_WARN("%sHELLO_END ditolak dari IP %s. Tidak pernah mengirim HELLO1_ACK dan atau HELLO2_ACK dan atau HELLO3_ACK ke IP ini atau HELLO_END dari IP ini sudah ditangani.", label, host_str);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return FAILURE_IVLDHDLD;
            }
            master_sio_c_session_t *session = &master_ctx->sio_c_session[session_index];
//----------------------------------------------------------------------
// Pindahkan temp_kem_sharedsecret ke identity
// Di duga client sudah mengirim hello end
// Jika decrypt gagal berarti Mac tidak cocok
// Jika mac tidak cocok kembalikan lagi
// kosongkan kembali session->identity.kem_sharedsecret
// Artinya mungkin bukan client sebenarnya yang mengirim hello_end
// Tujuan pengosongan barangkali client sebenarnya masih retry hello3
//---------------------------------------------------------------------- 
            memcpy(session->identity.kem_sharedsecret, session->temp_kem_sharedsecret, KEM_SHAREDSECRET_BYTES);
//----------------------------------------------------------------------
            orilink_protocol_t_status_t deserialized_orcvdo = orilink_deserialize(label,
                session->identity.kem_sharedsecret, session->identity.remote_nonce, session->identity.remote_ctr,
                (const uint8_t*)orcvdo.r_orilink_raw_protocol_t->recv_buffer, orcvdo.r_orilink_raw_protocol_t->n
            );
            if (deserialized_orcvdo.status != SUCCESS) {
                LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", label, deserialized_orcvdo.status);
//----------------------------------------------------------------------
// Diduga Mac tidak cocok atau data tidak valid
// Diduga bukan client sebenarnya
// Artinya mungkin bukan client sebenarnya yang mengirim hello_end
// Tujuan pengosongan barangkali client sebenarnya masih retry hello3
//---------------------------------------------------------------------- 
                memset(session->identity.kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
//----------------------------------------------------------------------
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
                return deserialized_orcvdo.status;
            } else {
                LOG_DEBUG("%sorilink_deserialize BERHASIL.", label);
                CLOSE_ORILINK_RAW_PROTOCOL(&orcvdo.r_orilink_raw_protocol_t);
            }            
            orilink_protocol_t* received_protocol = deserialized_orcvdo.r_orilink_protocol_t;
            orilink_hello_end_t *ohello_end = received_protocol->payload.orilink_hello_end;
            if (master_ctx->sio_c_session[session_index].identity.client_id != ohello_end->client_id) {
                LOG_WARN("%sHELLO_END ditolak dari IP %s. client_id berbeda.", label, host_str);
//----------------------------------------------------------------------
// Diduga bukan client sebenarnya
// Artinya mungkin bukan client sebenarnya yang mengirim hello_end
// Tujuan pengosongan barangkali client sebenarnya masih retry hello3
//---------------------------------------------------------------------- 
                memset(session->identity.kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
//----------------------------------------------------------------------
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE_DIFCLID;
            }
//======================================================================
// Ambil remote_nonce
// Set remote_ctr = 0
// Ambil encrypter server_id+new_client_id
// Ambil Mac
// Cocokkan MAc
// Decrypt server_id dan new_client_id
//======================================================================
            memcpy(session->identity.remote_nonce, ohello_end->encrypted_server_id_new_client_id, AES_NONCE_BYTES);
            uint8_t encrypted_server_id_new_client_id[sizeof(uint64_t) + sizeof(uint64_t)];   
            memcpy(encrypted_server_id_new_client_id, ohello_end->encrypted_server_id_new_client_id + AES_NONCE_BYTES, sizeof(uint64_t) + sizeof(uint64_t));
            uint8_t data_mac[AES_TAG_BYTES];
            memcpy(data_mac, ohello_end->encrypted_server_id_new_client_id + AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint64_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
            uint8_t encrypted_server_id_new_client_id1[AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint64_t)];
            memcpy(encrypted_server_id_new_client_id1, ohello_end->encrypted_server_id_new_client_id, AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint64_t));
            uint8_t mac[AES_TAG_BYTES];
            poly1305_context mac_ctx;
            poly1305_init(&mac_ctx, session->identity.kem_sharedsecret);
            poly1305_update(&mac_ctx, encrypted_server_id_new_client_id1, AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint64_t));
            poly1305_finish(&mac_ctx, mac);
            if (!poly1305_verify(mac, data_mac)) {
                LOG_ERROR("%sFailed to Mac Tidak Sesuai.", label);
//----------------------------------------------------------------------
// Tujuan pengosongan memulai awal karna Mac nonce, server_id dan new_client_id mismatch
//---------------------------------------------------------------------- 
                memset(session->identity.kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
//----------------------------------------------------------------------
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            uint32_t temp_remote_ctr = (uint32_t)0;
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
            uint8_t decrypted_server_id_new_client_id[sizeof(uint64_t) + sizeof(uint64_t)];
            aes256ctx aes_ctx;
            aes256_ctr_keyexp(&aes_ctx, session->identity.kem_sharedsecret);
//=========================================IV===========================    
            uint8_t keystream_buffer[sizeof(uint64_t) + sizeof(uint64_t)];
            uint8_t iv[AES_IV_BYTES];
            memcpy(iv, session->identity.remote_nonce, AES_NONCE_BYTES);
            uint32_t remote_ctr_be = htobe32(temp_remote_ctr);
            memcpy(iv + AES_NONCE_BYTES, &remote_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
            aes256_ctr(keystream_buffer, sizeof(uint64_t) + sizeof(uint64_t), iv, &aes_ctx);
            for (size_t i = 0; i < sizeof(uint64_t) + sizeof(uint64_t); i++) {
                decrypted_server_id_new_client_id[i] = encrypted_server_id_new_client_id[i] ^ keystream_buffer[i];
            }
            aes256_ctx_release(&aes_ctx);
//---------------------------------------------------------------------- 
// Mengecek dan Mengisi identity
//---------------------------------------------------------------------- 
            uint64_t server_id_be;
            memcpy(&server_id_be, decrypted_server_id_new_client_id, sizeof(uint64_t));
            if (session->identity.server_id != be64toh(server_id_be)) {
                LOG_WARN("%sHELLO_END ditolak dari IP %s. server_id berbeda.", label, host_str);
//----------------------------------------------------------------------
// Tujuan pengosongan memulai awal karna server_id berbeda
//---------------------------------------------------------------------- 
                memset(session->identity.kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
//----------------------------------------------------------------------
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
//----------------------------------------------------------------------
// Kosongkan temp_kem_sharedsecret
// Menganggap data valid dengan integritas
//---------------------------------------------------------------------- 
            session->identity.remote_ctr = (uint32_t)1;//sudah melakukan dekripsi data valid 1 kali
            memset(session->temp_kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
//---------------------------------------------------------------------- 
            uint64_t new_client_id_be;
            memcpy(&new_client_id_be, decrypted_server_id_new_client_id + sizeof(uint64_t), sizeof(uint64_t));
            session->identity.client_id = be64toh(new_client_id_be);
//====================================================================== 
// Mengirim session ke SIO worker
//======================================================================
//----------------------------------------------------------------------
// Hitung rtt retry sebelum kirim data
//----------------------------------------------------------------------
            double try_count = (double)session->hello3_ack.ack_sent_try_count-(double)1;
            sio_c_calculate_retry(label, session, session_index, try_count);
            uint64_t_status_t rt = get_realtime_time_ns(label);
            if (rt.status != SUCCESS) {
                LOG_ERROR("%sFailed to get_realtime_time_ns.", label);
//----------------------------------------------------------------------
// Tujuan pengosongan memulai awal karna kegagalan server
// Harusnya tidak pernah terjadi server gagal mengambil real time clock
//---------------------------------------------------------------------- 
                memset(session->identity.kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
//----------------------------------------------------------------------
                CLOSE_ORILINK_PROTOCOL(&received_protocol);
                return FAILURE;
            }
            session->sock_ready.rcvd = true;
            session->sock_ready.rcvd_time = rt.r_uint64_t;
            uint64_t interval_ull = session->sock_ready.rcvd_time - session->hello3_ack.ack_sent_time;
            double rtt_value = (double)interval_ull;
            sio_c_calculate_rtt(label, session, session_index, rtt_value);
//----------------------------------------------------------------------
//----------------------------------------------------------------------
// Semua sudah bersih
//----------------------------------------------------------------------
            cleanup_hello_ack(label, &master_ctx->master_async, &session->hello3_ack);
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
