#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#include "sessions/closed_correlation_id.h"
#include "log.h"
#include "types.h"
#include "utilities.h"
#include "constants.h"

status_t add_closed_correlation_id(const char *label, closed_correlation_id_t **head, uint64_t id, uint8_t host_ip[]) {
    closed_correlation_id_t *new_node = (closed_correlation_id_t *)malloc(sizeof(closed_correlation_id_t));
    if (new_node == NULL) {
        LOG_ERROR("%sGagal mengalokasikan memori untuk node baru", label);
        return FAILURE;
    }
    uint64_t_status_t grtns_result = get_realtime_time_ns(label);    
    if (grtns_result.status == SUCCESS) {
		new_node->correlation_id = id;
		memcpy(new_node->ip, host_ip, INET6_ADDRSTRLEN);
		new_node->closed_time = grtns_result.r_uint64_t;
		new_node->next = *head; // Node baru menunjuk ke head lama
		*head = new_node;       // Head sekarang adalah node baru
		LOG_INFO("%sClosed correlation ID %llu berhasil ditambahkan.", label, (unsigned long long)id);
		return grtns_result.status;
	}
	return FAILURE;
}

status_t delete_closed_correlation_id(const char *label, closed_correlation_id_t **head, uint64_t id) {
    closed_correlation_id_t *current = *head;
    closed_correlation_id_t *prev = NULL;

    // Jika node yang akan dihapus adalah head
    if (current != NULL && current->correlation_id == id) {
        *head = current->next; // Pindahkan head ke node berikutnya
        free(current);         // Bebaskan memori node lama
        LOG_INFO("%sCorrelation ID %llu berhasil dihapus (head).", label, (unsigned long long)id);
        return SUCCESS;
    }

    // Cari node yang akan dihapus
    while (current != NULL && current->correlation_id != id) {
        prev = current;
        current = current->next;
    }

    // Jika ID tidak ditemukan
    if (current == NULL) {
        LOG_WARN("%sCorrelation ID %llu tidak ditemukan.", label, (unsigned long long)id);
        return FAILURE;
    }

    // Hapus node dari tengah atau akhir
    prev->next = current->next;
    free(current);
    LOG_INFO("%sCorrelation ID %llu berhasil dihapus.", label, (unsigned long long)id);
    return SUCCESS;
}

closed_correlation_id_t_status_t find_closed_correlation_id(const char *label, closed_correlation_id_t *head, uint64_t id) {
    closed_correlation_id_t *current = head;
    closed_correlation_id_t_status_t result;
    result.r_closed_correlation_id_t = current;
    result.status = FAILURE;
    while (current != NULL) {
        if (current->correlation_id == id) {
            LOG_INFO("%sCorrelation ID %llu ditemukan.", label, (unsigned long long)id);
            result.status = SUCCESS;
            return result;
        }
        current = current->next;
    }
    LOG_WARN("%sCorrelation ID %llu tidak ditemukan.", label, (unsigned long long)id);
    return result;
}

closed_correlation_id_t_status_t find_first_ratelimited_closed_correlation_id(const char *label, closed_correlation_id_t *head, uint8_t host_ip[]) {
	closed_correlation_id_t *current = head;
    closed_correlation_id_t_status_t result;
    result.r_closed_correlation_id_t = current;
    result.status = FAILURE;
    //==========FILTER RATELIMIT========================================
    while (current != NULL) {
        if (memcmp(current->ip, host_ip, INET6_ADDRSTRLEN) == 0) {
			uint64_t_status_t grtns_result = get_realtime_time_ns(label);    
			if (grtns_result.status == SUCCESS) {
				uint64_t ratelimit_ns = (uint64_t)RATELIMITSEC * 1000000000ULL;
				if ((grtns_result.r_uint64_t - current->closed_time) <= ratelimit_ns) {
					result.status = FAILURE_RATELIMIT;
					LOG_ERROR("%sIP %s mencoba melakukan koneksi diatas ratelimit.", label, host_ip);					
					current->closed_time = grtns_result.r_uint64_t;	// <==== tambahan				
					return result;
				}
			} else {
				result.status = FAILURE_RATELIMIT;
				LOG_ERROR("%sGagal menghitung ratelimit untuk IP %s -> mencoba melakukan koneksi diatas ratelimit.", label, host_ip);
				return result;
			}
        }
        current = current->next;
    }
    LOG_INFO("%sIP %s tidak ditemukan di tabel ratelimit.", label, host_ip);
    //==================================================================
    current = head;
    while (current != NULL) {
		uint64_t_status_t grtns_result = get_realtime_time_ns(label);
		if (grtns_result.status == SUCCESS) {
			uint64_t ratelimit_ns = (uint64_t)RATELIMITSEC * 1000000000ULL;
			if ((grtns_result.r_uint64_t - current->closed_time) > ratelimit_ns) {
				result.status = grtns_result.status;
				LOG_INFO("%sIP %s berhasil mendapatkan reusable correlation id %llu.", label, host_ip, (unsigned long long)current->correlation_id);
				return result;
			}
		} else {
			result.status = grtns_result.status;
			LOG_WARN("%sIP %s gagal mencari reusable correlation id yang bebas ratelimit -> dianggap gagal mencari reusable correlation id.", label, host_ip);
			return result;
		}
        current = current->next;
    }
    LOG_WARN("%sIP %s tidak menemukan reusable correlation ID.", label, host_ip);
    return result;
}

int_status_t count_closed_correlation_ids(const char *label, closed_correlation_id_t *head) {
	int_status_t result;
	result.r_int = 0;
	result.status = FAILURE;
    closed_correlation_id_t *current = head;
    while (current != NULL) {
        result.r_int++;
        current = current->next;
    }
    LOG_INFO("%sJumlah Correlation ID dalam list: %d", label, result.r_int);
    result.status = SUCCESS;
    return result;
}

void display_closed_correlation_ids(const char *label, closed_correlation_id_t *head) {
    closed_correlation_id_t *current = head;
    if (current == NULL) {
        LOG_WARN("%sList kosong.", label);
        return;
    }
    LOG_INFO("%sIsi list: ", label);
    while (current != NULL) {
        LOG_INFO("%s%llu -> ", label, (unsigned long long)current->correlation_id);
        current = current->next;
    }
    LOG_INFO("%sNULL", label);
}

void free_closed_correlation_ids(const char *label, closed_correlation_id_t **head) {
    closed_correlation_id_t *current = *head;
    closed_correlation_id_t *next;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    *head = NULL; // Pastikan head menjadi NULL setelah semua node dibebaskan
    LOG_INFO("%sSemua node dalam list telah dibebaskan.", label);
}
