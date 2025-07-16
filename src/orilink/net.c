#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <sys/types.h>

#include "constants.h"
#include "types.h"
#include "orilink/net.h"
#include "orilink/hash.h"

// Fungsi untuk mencari atau membuat sesi
udp_session_t* find_or_create_session(udp_context_t *ctx, uint32_t conn_id, const struct sockaddr_in6 *addr, socklen_t len) {
    // Cari sesi yang sudah ada
    for (int i = 0; i < ctx->session_count; i++) {
        if (ctx->sessions[i].connection_id == conn_id) {
            return &ctx->sessions[i];
        }
    }

    // Jika belum ada, buat sesi baru
    if (ctx->session_count < MAX_SESSIONS) {
        udp_session_t* new_session = &ctx->sessions[ctx->session_count++];
        memset(new_session, 0, sizeof(udp_session_t));
        new_session->connection_id = conn_id;
        new_session->client_addr = *addr;
        new_session->client_addr_len = len;
        new_session->next_expected_seq = 1;
        new_session->available_receive_window = 150000; // Contoh window awal
        new_session->last_active_time = time(NULL);
        new_session->is_handshake_complete = 0;
        new_session->is_fin_received = 0;
        
        printf("Server: Sesi baru dibuat untuk ID: %u\n", conn_id);
        return new_session;
    }
    return NULL;
}

// Fungsi untuk mengirim paket ACK/SACK
void send_sack(int sockfd, udp_session_t* session) {
    size_t payload_len = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + (session->buffer_count * sizeof(udp_sack_block_t));
    size_t total_size = sizeof(udp_packet_header_t) + payload_len;
    
    udp_sack_packet_t *pkt = (udp_sack_packet_t*)malloc(total_size);
    if (!pkt) return;

    pkt->header.connection_id = htonl(session->connection_id);
    pkt->header.sequence_number = 0;
    pkt->header.packet_type = PT_ACK;
    pkt->header.payload_length = htons(payload_len);
    pkt->header.stream_id = 0;
    pkt->header.stream_sequence_number = 0;
    
    pkt->last_acked_seq = htonl(session->next_expected_seq - 1);
    pkt->sack_block_count = htons(session->buffer_count);
    pkt->available_receive_window = htonl(session->available_receive_window);

    for (int i = 0; i < session->buffer_count; i++) {
        pkt->sack_blocks[i].start_seq = htonl(session->recv_buffer[i]->global_sequence_number);
        pkt->sack_blocks[i].end_seq = htonl(session->recv_buffer[i]->global_sequence_number);
    }
    
    pkt->header.checksum = 0;
    pkt->header.checksum = htonl(orilink_hash32(pkt, total_size));
    
    sendto(sockfd, pkt, total_size, 0, (const struct sockaddr*)&session->client_addr, session->client_addr_len);
    free(pkt);

    printf("Server: Sesi %u. Mengirim SACK. Last ACK: %u, SACK Blocks: %u. Jendela: %u\n",
           session->connection_id, session->next_expected_seq - 1, session->buffer_count, session->available_receive_window);
}

// Fungsi untuk memproses paket data yang baru diterima
void process_data_packet(int sockfd, udp_session_t* session, udp_packet_t* pkt) {
    uint32_t global_seq = ntohl(pkt->header.sequence_number);
    uint16_t stream_id = ntohs(pkt->header.stream_id);
    uint32_t stream_seq = ntohl(pkt->header.stream_sequence_number);
    uint16_t payload_len = ntohs(pkt->header.payload_length);
    
    if (payload_len > MAX_BUFFER_SIZE) {
        printf("Server: Payload terlalu besar (%u), abaikan.\n", payload_len);
        return;
    }
    printf("Server: Sesi %u. Menerima paket DATA #%u (Stream %u, Seq: %u).\n",
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
        send_sack(sockfd, session);
    } else if (global_seq > session->next_expected_seq) {
        // Paket di luar urutan
        if (session->buffer_count < session->max_recv_buffer_size) {
            // Cek duplikat
            for(int i = 0; i < session->buffer_count; i++) {
                if(session->recv_buffer[i]->global_sequence_number == global_seq) {
                    return; // Abaikan duplikat
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
            printf("Server: Sesi %u. Paket di luar urutan global #%u (Stream %u), disimpan di buffer.\n",
                   session->connection_id, global_seq, stream_id);

            // Kirim SACK
            send_sack(sockfd, session);
        } else {
            // Buffer penuh, jatuhkan paket
            printf("Server: Buffer penuh untuk sesi %u. Menjatuhkan paket #%u.\n", session->connection_id, global_seq);
        }
    } else {
        // Paket duplikat (sudah di-ACK), abaikan
        printf("Server: Sesi %u. Menerima paket duplikat #%u. Abaikan.\n", session->connection_id, global_seq);
    }
}

// Fungsi untuk membuat dan mengirim paket
void send_packet(int sockfd, const struct sockaddr_in *dest_addr,
                 uint32_t conn_id, uint32_t global_seq_num, udp_packet_type_t type,
                 uint16_t stream_id, uint32_t stream_seq_num, const uint8_t *data, size_t data_len) {
    size_t total_size = sizeof(udp_packet_header_t) + data_len;
    udp_packet_t *packet = (udp_packet_t *)malloc(total_size);
    if (!packet) {
        perror("malloc failed");
        return;
    }

    packet->header.connection_id = htonl(conn_id);
    packet->header.sequence_number = htonl(global_seq_num);
    packet->header.packet_type = type;
    packet->header.payload_length = htons(data_len);
    packet->header.stream_id = htons(stream_id);
    packet->header.stream_sequence_number = htonl(stream_seq_num);
    
    if (data) {
        memcpy(packet->payload, data, data_len);
    } else if (data_len > 0) {
        memset(packet->payload, 0, data_len);
    }
    
    packet->header.checksum = 0;
    uint32_t calculated_checksum = orilink_hash32(packet, total_size);
    packet->header.checksum = htonl(calculated_checksum);
    
    if (sendto(sockfd, packet, total_size, 0, (const struct sockaddr *)dest_addr, sizeof(*dest_addr)) < 0) {
        perror("sendto failed");
    }
    free(packet);
}

// Fungsi untuk mencari paket di buffer berdasarkan nomor urut global
udp_sent_packet_t* find_packet_in_buffer(udp_context_t *ctx, uint32_t global_seq_num) {
    for (int i = 0; i < ctx->buffer_count; i++) {
        if (ctx->send_buffer[i]->global_sequence_number == global_seq_num) {
            return ctx->send_buffer[i];
        }
    }
    return NULL;
}

// Fungsi Pembaruan Kontrol Kongesti CUBIC
void update_cubic_cwnd(udp_context_t *ctx) {
    if (ctx->congestion_window < ctx->slow_start_threshold) {
        ctx->congestion_window += 1.0;
    } else {
        time_t now = time(NULL);
        double t = difftime(now, ctx->last_congestion_time);
        
        double K = cbrt(ctx->Wmax * (1.0 - CUBIC_BETA) / CUBIC_C);
        double W_cubic = CUBIC_C * pow(t - K, 3.0) + ctx->Wmax;
        
        if (W_cubic > ctx->congestion_window) {
            ctx->congestion_window = W_cubic;
        } else {
            ctx->congestion_window += 1.0 / ctx->congestion_window;
        }
    }
}

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

void orilink_handle_syn(int sockfd, udp_session_t *session, udp_packet_t *received, const struct sockaddr *client_addr, socklen_t client_addr_len) {
    uint32_t conn_id = ntohl(received->header.connection_id);
    if (!session->is_handshake_complete) {
        udp_syn_packet_t* syn_pkt = (udp_syn_packet_t*)received;
        session->total_packets = ntohl(syn_pkt->total_packets);

        session->max_recv_buffer_size = session->total_packets > 0 ? session->total_packets : 100;
        session->recv_buffer = (udp_received_packet_t**)malloc(session->max_recv_buffer_size * sizeof(udp_received_packet_t*));
        if (!session->recv_buffer) {
            perror("malloc failed for dynamic buffer");
            exit(1);
        }
        printf("Server: Menerima SYN dari ID %u. Total paket yang diharapkan: %u. Mengirim SYN-ACK.\n",
               conn_id, session->total_packets);
        udp_packet_header_t syn_ack_header;
        syn_ack_header.connection_id = htonl(conn_id);
        syn_ack_header.packet_type = PT_SYN_ACK;
        syn_ack_header.checksum = 0;
        syn_ack_header.checksum = htonl(orilink_hash32(&syn_ack_header, sizeof(syn_ack_header)));
        ssize_t sent = sendto(sockfd, &syn_ack_header, sizeof(syn_ack_header), 0, client_addr, client_addr_len);
        if (sent != sizeof(syn_ack_header)) {
            perror("sendto failed to send SYN-ACK properly");
        }
    } else {
        printf("Server: Menerima SYN dari sesi yang sudah ada %u. Melanjutkan sesi.\n", conn_id);
    }
}

void orilink_handle_ack(udp_session_t *session, udp_packet_t *received) {
    uint32_t conn_id = ntohl(received->header.connection_id);
    if (!session->is_handshake_complete) {
        printf("Server: Sesi %u. Menerima ACK terakhir, handshake selesai.\n", conn_id);
        session->is_handshake_complete = 1;
        //char filename[256];
        //sprintf(filename, "received_file_%u.dat", conn_id);
        //session->file = fopen(filename, "wb");
        //if (!session->file) {
        //    perror("fopen failed");
        //}
    }
}

void orilink_handle_data(int sockfd, udp_session_t *session, udp_packet_t *received) {
    if (session->is_handshake_complete) {
        process_data_packet(sockfd, session, received);
    }
}

void orilink_handle_fin(int sockfd, udp_session_t *session, udp_packet_t *received, const struct sockaddr *client_addr, socklen_t client_addr_len) {
    uint32_t conn_id = ntohl(received->header.connection_id);
    printf("Server: Menerima FIN dari sesi %u. Mengirim ACK dan FIN kembali.\n", conn_id);
    session->is_fin_received = 1;

    udp_packet_header_t ack_header;
    ack_header.connection_id = htonl(conn_id);
    ack_header.packet_type = PT_ACK;
    ack_header.checksum = 0;
    ack_header.checksum = htonl(orilink_hash32(&ack_header, sizeof(ack_header)));
    sendto(sockfd, &ack_header, sizeof(ack_header), 0, (const struct sockaddr *)&client_addr, client_addr_len);

    udp_packet_header_t fin_header;
    fin_header.connection_id = htonl(conn_id);
    fin_header.packet_type = PT_FIN;
    fin_header.checksum = 0;
    fin_header.checksum = htonl(orilink_hash32(&fin_header, sizeof(fin_header)));
    ssize_t sent = sendto(sockfd, &fin_header, sizeof(fin_header), 0, client_addr, client_addr_len);
    if (sent != sizeof(fin_header)) {
        perror("sendto failed to send FIN-ACK properly");
    }    
    if ((session->next_expected_seq - 1) == session->total_packets && session->buffer_count == 0) {
        //if (session->file) {
        //    long pos = ftell(session->file);
        //    printf("Server: Ukuran file yang ditulis untuk sesi %u = %ld bytes\n", conn_id, pos);
            printf("Server: Semua data diterima. Menutup file sesi %u.\n", conn_id);
        //    fclose(session->file);
        //    session->file = NULL;
        //}
    } else {
        printf("Server: Masih ada data tertunda untuk sesi %u! next_expected_seq = %u, total = %u, buffer_count = %d\n",
               conn_id, session->next_expected_seq, session->total_packets, session->buffer_count);
    }
}

void orilink_handle_keepalive(udp_session_t *session, udp_packet_t *received) {
    uint32_t conn_id = ntohl(received->header.connection_id);
    session->last_active_time = time(NULL);
    printf("Server: Menerima KEEPALIVE dari sesi %u.\n", conn_id);
}

void orilink_cleanup_sessions(udp_context_t *ctx) {
    time_t now = time(NULL);
    for (int i = 0; i < ctx->session_count; i++) {
        if (now - ctx->sessions[i].last_active_time > 300) {
            printf("Server: Membersihkan sesi tidak aktif %u.\n", ctx->sessions[i].connection_id);
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
}
