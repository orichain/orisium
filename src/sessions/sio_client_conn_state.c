#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "sessions/sio_client_conn_state.h"
#include "log.h"
#include "types.h"

void add_sio_client_conn_state(const char *label, sio_client_conn_state_t **head, uint64_t id) {
    sio_client_conn_state_t *new_node = (sio_client_conn_state_t *)malloc(sizeof(sio_client_conn_state_t));
    if (new_node == NULL) {
        LOG_ERROR("%sGagal mengalokasikan memori untuk node baru", label);
        return;
    }
    new_node->correlation_id = id;
    new_node->next = *head; // Node baru menunjuk ke head lama
    *head = new_node;       // Head sekarang adalah node baru
    LOG_ERROR("%sCorrelation ID %llu berhasil ditambahkan.", label, (unsigned long long)id);
}

status_t delete_sio_client_conn_state(const char *label, sio_client_conn_state_t **head, uint64_t id) {
    sio_client_conn_state_t *current = *head;
    sio_client_conn_state_t *prev = NULL;

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

sio_client_conn_state_t_status_t find_sio_client_conn_state(const char *label, sio_client_conn_state_t *head, uint64_t id) {
    sio_client_conn_state_t *current = head;
    sio_client_conn_state_t_status_t result;
    result.r_sio_client_conn_state_t = current;
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

sio_client_conn_state_t_status_t find_first_sio_client_conn_state(const char *label, sio_client_conn_state_t *head) {
    sio_client_conn_state_t *current = head;
    sio_client_conn_state_t_status_t result;
    result.r_sio_client_conn_state_t = current;
    result.status = FAILURE;
    while (current != NULL) {
		LOG_INFO("%sCorrelation ID %llu ditemukan.", label, (unsigned long long)current->correlation_id);
        result.status = SUCCESS;
        return result;
    }
    LOG_WARN("%sCorrelation ID tidak ditemukan.", label);
    return result;
}

int_status_t count_sio_client_conn_states(const char *label, sio_client_conn_state_t *head) {
	int_status_t result;
	result.r_int = 0;
	result.status = FAILURE;
    sio_client_conn_state_t *current = head;
    while (current != NULL) {
        result.r_int++;
        current = current->next;
    }
    LOG_INFO("%sJumlah Correlation ID dalam list: %d", label, result.r_int);
    result.status = SUCCESS;
    return result;
}

void display_sio_client_conn_states(const char *label, sio_client_conn_state_t *head) {
    sio_client_conn_state_t *current = head;
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

void free_sio_client_conn_states(const char *label, sio_client_conn_state_t **head) {
    sio_client_conn_state_t *current = *head;
    sio_client_conn_state_t *next;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    *head = NULL; // Pastikan head menjadi NULL setelah semua node dibebaskan
    LOG_INFO("%sSemua node dalam list telah dibebaskan.", label);
}
