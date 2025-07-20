#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <endian.h>
#include <sys/types.h>

#include "constants.h"
#include "types.h"
#include "async.h"
#include "utilities.h"
#include "log.h"
#include "orilink/net.h"
#include "orilink/hash.h"

// Fungsi untuk mencari atau membuat sesi
udp_session_t_status_t orilink_find_or_create_session(udp_context_t *ctx, uint32_t conn_id, const struct sockaddr_in6 *addr, socklen_t len) {
    udp_session_t_status_t result;
    result.r_udp_session_t = NULL;
    result.status = FAILURE;
    // Cari sesi yang sudah ada
    for (int i = 0; i < ctx->session_count; i++) {
        if (ctx->sessions[i].connection_id == conn_id) {
            result.r_udp_session_t = &ctx->sessions[i];
            result.status = SUCCESS;
            return result;
        }
    }

    // Jika belum ada, buat sesi baru
    if (ctx->session_count < MAX_MASTER_CONCURRENT_SESSIONS) {
        udp_session_t* new_session = &ctx->sessions[ctx->session_count++];
        memset(new_session, 0, sizeof(udp_session_t));
        new_session->connection_id = conn_id;
        new_session->client_addr = *addr;
        new_session->client_addr_len = len;
        new_session->next_expected_seq = 1;
        new_session->max_recv_buffer_size = 64;
        new_session->available_receive_window = new_session->max_recv_buffer_size * ORILINK_MAX_PACKET_SIZE;
        new_session->last_active_time = time(NULL);
        new_session->is_handshake_complete = 0;
        new_session->is_fin_received = 0;
        
        LOG_INFO("[ORILINK]: Sesi baru dibuat untuk ID: %u", conn_id);
        result.r_udp_session_t = new_session;
        result.status = SUCCESS;
        return result;
    }
    return result;
}

// Fungsi untuk mengirim paket ACK/SACK
status_t orilink_send_sack(int sockfd, udp_session_t* session) {
    size_t payload_len = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + (session->buffer_count * sizeof(udp_sack_block_t));
    size_t total_size = sizeof(udp_packet_header_t) + payload_len;
    
    udp_sack_packet_t *pkt = (udp_sack_packet_t*)malloc(total_size);
    if (!pkt) return FAILURE;

    pkt->header.connection_id = htobe32(session->connection_id);
    pkt->header.sequence_number = 0;
    pkt->header.packet_type = PT_ACK;
    pkt->header.payload_length = htobe16(payload_len);
    pkt->header.stream_id = 0;
    pkt->header.stream_sequence_number = 0;
    
    pkt->last_acked_seq = htobe32(session->next_expected_seq - 1);
    pkt->sack_block_count = htobe16(session->buffer_count);
    pkt->available_receive_window = htobe32(session->available_receive_window);

    for (int i = 0; i < session->buffer_count; i++) {
        pkt->sack_blocks[i].start_seq = htobe32(session->recv_buffer[i]->global_sequence_number);
        pkt->sack_blocks[i].end_seq = htobe32(session->recv_buffer[i]->global_sequence_number);
    }
    
    pkt->header.checksum = 0;
    pkt->header.checksum = htobe32(orilink_hash32(pkt, total_size));
    
    ssize_t sent = sendto(sockfd, pkt, total_size, 0, (const struct sockaddr*)&session->client_addr, session->client_addr_len);
    if (sent != (ssize_t)total_size) {
        LOG_ERROR("[ORILINK]: sendto failed to send ACK/SACK properly. %s", strerror(errno));
        free(pkt);
        return FAILURE;
    }
    free(pkt);
    LOG_INFO("[ORILINK]: Sesi %u. Mengirim SACK. Last ACK: %u, SACK Blocks: %u. Jendela: %u",
           session->connection_id, session->next_expected_seq - 1, session->buffer_count, session->available_receive_window);
    return SUCCESS;
}

// Fungsi untuk memproses paket data yang baru diterima
status_t orilink_process_data_packet(int sockfd, udp_session_t* session, udp_packet_t* pkt) {
    uint32_t global_seq = be32toh(pkt->header.sequence_number);
    uint16_t stream_id = be16toh(pkt->header.stream_id);
    uint32_t stream_seq = be32toh(pkt->header.stream_sequence_number);
    uint16_t payload_len = be16toh(pkt->header.payload_length);
    
    if (payload_len > ORILINK_MAX_PACKET_SIZE) {
        LOG_WARN("[ORILINK]: Payload terlalu besar (%u), abaikan.", payload_len);
        return FAILURE_OOBUF;
    }
    LOG_INFO("[ORILINK]: Sesi %u. Menerima paket DATA #%u (Stream %u, Seq: %u).",
           session->connection_id, global_seq, stream_id, stream_seq);

    if (global_seq == session->next_expected_seq) {
        // Paket yang diharapkan tiba
        //if (session->file) {
        //    fwrite(pkt->payload, 1, payload_len, session->file);
            session->available_receive_window -= payload_len;
        //}
        
        session->next_expected_seq++;
        
        // Periksa buffer untuk paket yang sudah bisa diproses
        int packets_processed = 0;
        while (session->buffer_count > 0) {
            int found_next = -1;
            for (int i = 0; i < session->buffer_count; i++) {
                if (session->recv_buffer[i]->global_sequence_number == session->next_expected_seq) {
                    found_next = i;
                    break;
                }
            }

            if (found_next != -1) {
                //if (session->file) {
                //    fwrite(session->recv_buffer[found_next]->data, 1, session->recv_buffer[found_next]->data_len, session->file);
                    session->available_receive_window -= session->recv_buffer[found_next]->data_len;
                //}
                
                free(session->recv_buffer[found_next]);
                for (int i = found_next; i < session->buffer_count - 1; i++) {
                    session->recv_buffer[i] = session->recv_buffer[i+1];
                }
                session->buffer_count--;
                session->next_expected_seq++;
                packets_processed++;
            } else {
                break;
            }
        }
        
        // Setelah memproses paket in-order, kirim ACK/SACK
        return orilink_send_sack(sockfd, session);
    } else if (global_seq > session->next_expected_seq) {
        // Paket di luar urutan
        if (session->buffer_count < session->max_recv_buffer_size) {
            // Cek duplikat
            for(int i = 0; i < session->buffer_count; i++) {
                if(session->recv_buffer[i]->global_sequence_number == global_seq) {
                    return FAILURE_DPLCT; // Abaikan duplikat
                }
            }
            
            udp_received_packet_t* new_pkt = (udp_received_packet_t*)malloc(sizeof(udp_received_packet_t));
            new_pkt->global_sequence_number = global_seq;
            new_pkt->stream_id = stream_id;
            new_pkt->stream_sequence_number = stream_seq;
            memcpy(new_pkt->data, pkt->payload, payload_len);
            new_pkt->data_len = payload_len;
            
            // Simpan paket ke buffer
            session->recv_buffer[session->buffer_count++] = new_pkt;
            LOG_INFO("[ORILINK]: Sesi %u. Paket di luar urutan global #%u (Stream %u), disimpan di buffer.",
                   session->connection_id, global_seq, stream_id);

            // Kirim SACK
            return orilink_send_sack(sockfd, session);
        } else {
            // Buffer penuh, jatuhkan paket
            LOG_WARN("[ORILINK]: Buffer penuh untuk sesi %u. Menjatuhkan paket #%u.", session->connection_id, global_seq);
            return FAILURE_OOBUF;
        }
    } else {
        // Paket duplikat (sudah di-ACK), abaikan
        LOG_WARN("[ORILINK]: Sesi %u. Menerima paket duplikat #%u. Abaikan.", session->connection_id, global_seq);
        return FAILURE_DPLCT;
    }
}

// Fungsi untuk membuat dan mengirim paket
status_t orilink_send_packet(int sockfd, const struct sockaddr *dest_addr, socklen_t dest_addr_len,
                 uint32_t conn_id, uint32_t global_seq_num, udp_packet_type_t type,
                 uint16_t stream_id, uint32_t stream_seq_num, const uint8_t *data, size_t data_len) {
    size_t total_size = sizeof(udp_packet_header_t) + data_len;
    udp_packet_t *packet = (udp_packet_t *)malloc(total_size);
    if (!packet) {
        LOG_ERROR("[ORILINK]: malloc failed. %s", strerror(errno));
        return FAILURE;
    }

    packet->header.connection_id = htobe32(conn_id);
    packet->header.sequence_number = htobe32(global_seq_num);
    packet->header.packet_type = type;
    packet->header.payload_length = htobe16(data_len);
    packet->header.stream_id = htobe16(stream_id);
    packet->header.stream_sequence_number = htobe32(stream_seq_num);
    
    if (data) {
        memcpy(packet->payload, data, data_len);
    } else if (data_len > 0) {
        memset(packet->payload, 0, data_len);
    }
    
    packet->header.checksum = 0;
    uint32_t calculated_checksum = orilink_hash32(packet, total_size);
    packet->header.checksum = htobe32(calculated_checksum);
    
    ssize_t sent = sendto(sockfd, packet, total_size, 0, (const struct sockaddr *)dest_addr, dest_addr_len);
    if (sent != (ssize_t)total_size) {
        LOG_ERROR("[ORILINK]: sendto failed to send send_packet properly. %s", strerror(errno));
        free(packet);
        return FAILURE;
    }
    free(packet);
    return SUCCESS;
}

// Fungsi untuk mencari paket di buffer berdasarkan nomor urut global
udp_sent_packet_t_status_t orilink_find_packet_in_buffer(udp_context_t *ctx, uint32_t global_seq_num) {
    udp_sent_packet_t_status_t result;
    result.r_udp_session_t = NULL;
    result.status = FAILURE;
    for (int i = 0; i < ctx->buffer_count; i++) {
        if (ctx->send_buffer[i]->global_sequence_number == global_seq_num) {
            result.r_udp_session_t = ctx->send_buffer[i];
            result.status = SUCCESS;
            return result;
        }
    }
    return result;
}

// Fungsi Pembaruan Kontrol Kongesti CUBIC
status_t orilink_update_cubic_cwnd(udp_context_t *ctx) {
    if (ctx->congestion_window < ctx->slow_start_threshold) {
        ctx->congestion_window += 1.0;
    } else {
        uint64_t_status_t rt = get_realtime_time_ns("[ORILINK]: ");
        if (rt.status != SUCCESS) return rt.status;
        uint64_t now = rt.r_uint64_t;
        double t = (now - ctx->last_congestion_time) / 1e9; // konversi ke detik

        double K = cbrt(ctx->Wmax * (1.0 - CUBIC_BETA) / CUBIC_C);
        double W_cubic = CUBIC_C * pow(t - K, 3.0) + ctx->Wmax;

        if (W_cubic > ctx->congestion_window) {
            ctx->congestion_window = W_cubic;
        } else {
            ctx->congestion_window += 1.0 / ctx->congestion_window;
        }
    }
    return SUCCESS;
}
/*
void save_connection_id(uint32_t id) {
    FILE *fp = fopen("conn_id.txt", "w");
    if (fp) {
        fprintf(fp, "%u", id);
        fclose(fp);
    }
}

uint32_t load_connection_id() {
    FILE *fp = fopen("conn_id.txt", "r");
    uint32_t id = 0;
    if (fp) {
        fscanf(fp, "%u", &id);
        fclose(fp);
    }
    return id;
}
*/
status_t orilink_handle_syn(int sockfd, udp_session_t *session, udp_packet_t *received, const struct sockaddr *client_addr, socklen_t client_addr_len) {
    uint32_t conn_id = be32toh(received->header.connection_id);
    if (session->is_handshake_complete && !sockaddr_equal((const struct sockaddr *)&session->client_addr, client_addr)) {
        LOG_WARN("[ORILINK]: Connection ID %u reused from different source. Potential spoof?", conn_id);
        return FAILURE;
    }
    if (!session->is_handshake_complete) {
        udp_syn_packet_t* syn_pkt = (udp_syn_packet_t*)received;
        session->total_packets = be32toh(syn_pkt->total_packets);
        if (session->total_packets == 0 || session->total_packets > 1000000) {
            LOG_ERROR("[ORILINK]: suspicious total_packets value: %u", session->total_packets);
            return FAILURE;
        }
        session->max_recv_buffer_size = session->total_packets > 0 ? session->total_packets : 100;
        session->available_receive_window = session->max_recv_buffer_size * ORILINK_MAX_PACKET_SIZE;
        session->recv_buffer = (udp_received_packet_t**)malloc(session->max_recv_buffer_size * sizeof(udp_received_packet_t*));
        if (!session->recv_buffer) {
            LOG_ERROR("[ORILINK]: malloc failed for dynamic buffer. %s", strerror(errno));
            exit(1);
        }
        LOG_INFO("[ORILINK]: Menerima SYN dari ID %u. Total paket yang diharapkan: %u. Mengirim SYN-ACK.",
               conn_id, session->total_packets);
        udp_packet_header_t syn_ack_header;
        syn_ack_header.connection_id = htobe32(conn_id);
        syn_ack_header.packet_type = PT_SYN_ACK;
        syn_ack_header.checksum = 0;
        syn_ack_header.checksum = htobe32(orilink_hash32(&syn_ack_header, sizeof(syn_ack_header)));
        ssize_t sent = sendto(sockfd, &syn_ack_header, sizeof(syn_ack_header), 0, client_addr, client_addr_len);
        if (sent != sizeof(syn_ack_header)) {
            LOG_ERROR("[ORILINK]: sendto failed to send SYN-ACK properly. %s", strerror(errno));
            return FAILURE;
        }
    } else {
        LOG_INFO("[ORILINK]: Menerima SYN dari sesi yang sudah ada %u. Melanjutkan sesi.", conn_id);
        udp_packet_header_t syn_ack_header;
        syn_ack_header.connection_id = htobe32(conn_id);
        syn_ack_header.packet_type = PT_REUSED_SYN_ACK;
        syn_ack_header.checksum = 0;
        syn_ack_header.checksum = htobe32(orilink_hash32(&syn_ack_header, sizeof(syn_ack_header)));
        ssize_t sent = sendto(sockfd, &syn_ack_header, sizeof(syn_ack_header), 0, client_addr, client_addr_len);
        if (sent != sizeof(syn_ack_header)) {
            LOG_ERROR("[ORILINK]: sendto failed to send REUSED-SYN-ACK properly. %s", strerror(errno));
            return FAILURE;
        }
    }
    return SUCCESS;
}

status_t orilink_handle_ack(udp_session_t *session, udp_packet_t *received) {
    uint32_t conn_id = be32toh(received->header.connection_id);
    if (!session->is_handshake_complete) {
        LOG_INFO("[ORILINK]: Sesi %u. Menerima ACK terakhir, handshake selesai.", conn_id);
        session->is_handshake_complete = 1;
        //char filename[256];
        //sprintf(filename, "received_file_%u.dat", conn_id);
        //session->file = fopen(filename, "wb");
        //if (!session->file) {
        //    perror("fopen failed");
        //}
    }
    return SUCCESS;
}

status_t orilink_handle_data(int sockfd, udp_session_t *session, udp_packet_t *received) {
    if (session->is_handshake_complete) {
        return orilink_process_data_packet(sockfd, session, received);
    }
    return FAILURE;
}

status_t orilink_handle_fin(int sockfd, udp_session_t *session, udp_packet_t *received, const struct sockaddr *client_addr, socklen_t client_addr_len) {
    uint32_t conn_id = be32toh(received->header.connection_id);
    LOG_INFO("[ORILINK]: Menerima FIN dari sesi %u. Mengirim ACK dan FIN kembali.", conn_id);
    session->is_fin_received = 1;

    udp_packet_header_t ack_header;
    ack_header.connection_id = htobe32(conn_id);
    ack_header.packet_type = PT_ACK;
    ack_header.checksum = 0;
    ack_header.checksum = htobe32(orilink_hash32(&ack_header, sizeof(ack_header)));
    sendto(sockfd, &ack_header, sizeof(ack_header), 0, (const struct sockaddr *)&client_addr, client_addr_len);

    udp_packet_header_t fin_header;
    fin_header.connection_id = htobe32(conn_id);
    fin_header.packet_type = PT_FIN;
    fin_header.checksum = 0;
    fin_header.checksum = htobe32(orilink_hash32(&fin_header, sizeof(fin_header)));
    ssize_t sent = sendto(sockfd, &fin_header, sizeof(fin_header), 0, client_addr, client_addr_len);
    if (sent != sizeof(fin_header)) {
        LOG_ERROR("[ORILINK]: sendto failed to send FIN-ACK properly. %s", strerror(errno));
        return FAILURE;
    }    
    if ((session->next_expected_seq - 1) == session->total_packets && session->buffer_count == 0) {
        //if (session->file) {
        //    long pos = ftell(session->file);
        //    printf("Server: Ukuran file yang ditulis untuk sesi %u = %ld bytes\n", conn_id, pos);
        LOG_INFO("[ORILINK]: Semua data diterima. Menutup file sesi %u.", conn_id);
        //    fclose(session->file);
        //    session->file = NULL;
        //}
    } else {
        LOG_WARN("[ORILINK]: Masih ada data tertunda untuk sesi %u! next_expected_seq = %u, total = %u, buffer_count = %d",
               conn_id, session->next_expected_seq, session->total_packets, session->buffer_count);
    }
    return SUCCESS;
}

status_t orilink_handle_keepalive(udp_session_t *session, udp_packet_t *received) {
    uint32_t conn_id = be32toh(received->header.connection_id);
    uint64_t_status_t rt = get_realtime_time_ns("[ORILINK]: ");
    if (rt.status != SUCCESS) return rt.status;
    session->last_active_time = rt.r_uint64_t;
    LOG_INFO("[ORILINK]: Menerima KEEPALIVE dari sesi %u.", conn_id);
    return SUCCESS;
}

status_t orilink_cleanup_sessions(udp_context_t *ctx) {
    uint64_t_status_t rt = get_realtime_time_ns("[ORILINK]: ");
    if (rt.status != SUCCESS) return rt.status;
    uint64_t now = rt.r_uint64_t;
    for (int i = 0; i < ctx->session_count; i++) {
        if (((now - ctx->sessions[i].last_active_time)/1e9) > (double)WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT) {
            LOG_INFO("[ORILINK]: Membersihkan sesi tidak aktif %u.", ctx->sessions[i].connection_id);
            //if (ctx->sessions[i].file) {
            //    fclose(ctx->sessions[i].file);
            //    ctx->sessions[i].file = NULL;
            //}
            if (ctx->sessions[i].recv_buffer) {
                for (int j = 0; j < ctx->sessions[i].buffer_count; j++) {
                    free(ctx->sessions[i].recv_buffer[j]);
                }
                free(ctx->sessions[i].recv_buffer);
                ctx->sessions[i].recv_buffer = NULL;
            }
            ctx->sessions[i] = ctx->sessions[--ctx->session_count];
            i--;
        }
    }
    return SUCCESS;
}

void orilink_cleanup_handshake(async_type_t *async, udp_handshake_t *hs) {
    async_delete_event("[ORILINK]: ", async, &hs->sock_fd);
    CLOSE_FD(&hs->sock_fd);
    async_delete_event("[ORILINK]: ", async, &hs->timer_fd);
    CLOSE_FD(&hs->timer_fd);
}

udp_handshake_t_status_t orilink_handshake(async_type_t *cow_async, udp_context_t *ctx, int sockfd, const struct sockaddr *server_addr, socklen_t server_addr_len) {
    udp_handshake_t_status_t result;
    result.status = FAILURE;
    result.r_udp_handshake_t.sock_fd = -1;
    result.r_udp_handshake_t.timer_fd = -1;
    result.r_udp_handshake_t.hstime = 0ULL;
    result.r_udp_handshake_t.retry_count = 1;
    uint64_t_status_t rt = get_realtime_time_ns("[ORILINK]: ");
    if (rt.status != SUCCESS) return result;
    result.r_udp_handshake_t.hstime = rt.r_uint64_t;
    if (async_create_incoming_event("[ORILINK]: ", cow_async, &result.r_udp_handshake_t.sock_fd) != SUCCESS) return result;
    if (async_create_timerfd("[ORILINK]: ", &result.r_udp_handshake_t.timer_fd) != SUCCESS) return result;
	if (async_set_timerfd_time("[ORILINK]: ", &result.r_udp_handshake_t.timer_fd, 3, 0, 3, 0) != SUCCESS) return result;
	if (async_create_incoming_event("[ORILINK]: ", cow_async, &result.r_udp_handshake_t.timer_fd) != SUCCESS) return result;
    
    size_t total_size = sizeof(udp_syn_packet_t);
    udp_syn_packet_t* syn_pkt = (udp_syn_packet_t*)malloc(total_size);
    if (!syn_pkt) {
        LOG_ERROR("[ORILINK]: malloc failed.");
        orilink_cleanup_handshake(cow_async, &result.r_udp_handshake_t);
        return result;
    }
    LOG_WARN("[ORILINK]: Handshake attempt #%d", result.r_udp_handshake_t.retry_count);
    if (ctx->connection_id == 0) ctx->connection_id = rand();
    syn_pkt->header.connection_id = htonl(ctx->connection_id);
    syn_pkt->header.packet_type = PT_SYN;
    syn_pkt->header.payload_length = 0;
    syn_pkt->header.sequence_number = 0;
    syn_pkt->header.stream_id = 0;
    syn_pkt->header.stream_sequence_number = 0;
    syn_pkt->total_packets = htonl(ctx->total_packets_to_send);
    ctx->send_window_credit = ctx->total_packets_to_send * ORILINK_MAX_PACKET_SIZE;
    syn_pkt->header.checksum = 0;
    syn_pkt->header.checksum = htonl(orilink_hash32(syn_pkt, total_size));
    
    ssize_t sent = sendto(sockfd, syn_pkt, total_size, 0, server_addr, server_addr_len);
    if (sent != (ssize_t)total_size) {
        LOG_ERROR("[ORILINK]: sendto failed to send SYN properly. %s", strerror(errno));
        free(syn_pkt);
        orilink_cleanup_handshake(cow_async, &result.r_udp_handshake_t);
        return result;
    }
    free(syn_pkt);
    result.status = SUCCESS;
    ctx->is_syn_sent = 0x01;
    return result;
}

status_t orilink_retry_handshake(async_type_t *cow_async, udp_handshake_t *hs, udp_context_t *ctx, int sockfd, const struct sockaddr *server_addr, socklen_t server_addr_len) {
    if (!ctx->is_syn_acked) {
        size_t total_size = sizeof(udp_syn_packet_t);
        udp_syn_packet_t* syn_pkt = (udp_syn_packet_t*)malloc(total_size);
        if (!syn_pkt) {
            LOG_ERROR("[ORILINK]: malloc failed.");
            orilink_cleanup_handshake(cow_async, hs);
            return FAILURE;
        }
        hs->retry_count++;
        LOG_WARN("[ORILINK]: Retrying handshake attempt #%d", hs->retry_count);
        if (ctx->connection_id == 0) ctx->connection_id = rand();
        syn_pkt->header.connection_id = htonl(ctx->connection_id);
        syn_pkt->header.packet_type = PT_SYN;
        syn_pkt->header.payload_length = 0;
        syn_pkt->header.sequence_number = 0;
        syn_pkt->header.stream_id = 0;
        syn_pkt->header.stream_sequence_number = 0;
        syn_pkt->total_packets = htonl(ctx->total_packets_to_send);
        ctx->send_window_credit = ctx->total_packets_to_send * ORILINK_MAX_PACKET_SIZE;
        syn_pkt->header.checksum = 0;
        syn_pkt->header.checksum = htonl(orilink_hash32(syn_pkt, total_size));
        
        ssize_t sent = sendto(sockfd, syn_pkt, total_size, 0, server_addr, server_addr_len);
        if (sent != (ssize_t)total_size) {
            LOG_ERROR("[ORILINK]: sendto failed to send SYN properly. %s", strerror(errno));
            free(syn_pkt);
            orilink_cleanup_handshake(cow_async, hs);
            return FAILURE;
        }
        free(syn_pkt);
        ctx->is_syn_sent = 0x01;
    } else {
        orilink_cleanup_handshake(cow_async, hs);
    }
    return SUCCESS;
}

status_t orilink_handle_handshake(async_type_t *cow_async, udp_handshake_t *hs, udp_context_t *ctx, int sockfd, const struct sockaddr *server_addr, socklen_t server_addr_len) {
    if (!ctx->is_syn_acked) {
        uint8_t recv_buffer[ORILINK_MAX_PACKET_SIZE];
        struct sockaddr_in6 from_addr;
        socklen_t from_len = sizeof(from_addr);
        ssize_t n = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&from_addr, &from_len);
        if (!sockaddr_equal((struct sockaddr*)&from_addr, server_addr)) {
            LOG_WARN("[ORILINK]: Received packet from unexpected source.");
            return SUCCESS; // diabaikan
        }
        if (n < 0) {
            LOG_ERROR("[ORILINK]: recvfrom failed: %s", strerror(errno));
            return SUCCESS; // masih ditoleransi
        }
        if (n < (ssize_t)sizeof(udp_packet_header_t)) return SUCCESS;
        if (n >= (ssize_t)sizeof(udp_packet_header_t)) {
            udp_packet_t* received = (udp_packet_t*)recv_buffer;
            if (received->header.packet_type == PT_SYN_ACK || received->header.packet_type == PT_REUSED_SYN_ACK) {
                LOG_INFO("[ORILINK]: Menerima SYN-ACK/REUSED-SYN-ACK. Mengirim ACK...");
                if (orilink_send_packet(sockfd, server_addr, server_addr_len, ctx->connection_id, 0, PT_ACK, 0, 0, NULL, 0) != SUCCESS) return FAILURE;
                uint64_t_status_t rt = get_realtime_time_ns("[ORILINK]: ");
                if (rt.status != SUCCESS) return FAILURE;
                ctx->last_congestion_time = rt.r_uint64_t;
                ctx->is_syn_acked = 0x01;
                orilink_cleanup_handshake(cow_async, hs);
                return SUCCESS;
            }
        }
    } else {
        orilink_cleanup_handshake(cow_async, hs);
    }
    return SUCCESS;
}
