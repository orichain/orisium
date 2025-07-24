#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "sessions/master_session.h"
#include "log.h"
#include "types.h"
#include "utilities.h"
#include "constants.h"

status_t add_master_sio_dc_session(const char *label, master_sio_dc_session_t **head, struct sockaddr_in6 *client_addr) {
    master_sio_dc_session_t *new_node = (master_sio_dc_session_t *)malloc(sizeof(master_sio_dc_session_t));
    if (new_node == NULL) {
        LOG_ERROR("%sGagal mengalokasikan memori untuk node baru", label);
        return FAILURE;
    }
    char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    int getname_res = getnameinfo((struct sockaddr *)client_addr, sizeof(*client_addr),
						host_str, NI_MAXHOST,
					  	port_str, NI_MAXSERV,
					  	NI_NUMERICHOST | NI_NUMERICSERV
					  );
	if (getname_res != 0) {
		LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
		return FAILURE;
	}
    uint64_t_status_t grtns_result = get_realtime_time_ns(label);    
    if (grtns_result.status == SUCCESS) {
		memcpy(&new_node->client_addr, client_addr, sizeof(*client_addr));
		new_node->dc_time = grtns_result.r_uint64_t;
		new_node->next = *head;
		*head = new_node;
		LOG_DEBUG("%sIP %s berhasil ditambahkan.", label, host_str);
		return grtns_result.status;
	}
	return FAILURE;
}

status_t delete_master_sio_dc_session(const char *label, master_sio_dc_session_t **head, struct sockaddr_in6 *client_addr) {
    master_sio_dc_session_t *current = *head;
    master_sio_dc_session_t *prev = NULL;
    char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    int getname_res = getnameinfo((struct sockaddr *)client_addr, sizeof(*client_addr),
						host_str, NI_MAXHOST,
					  	port_str, NI_MAXSERV,
					  	NI_NUMERICHOST | NI_NUMERICSERV
					  );
	if (getname_res != 0) {
		LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
		return FAILURE;
	}
    if (current != NULL && sockaddr_equal((const struct sockaddr *)&current->client_addr, (const struct sockaddr *)client_addr)) {
        *head = current->next;
        free(current);        
        LOG_DEBUG("%sIP %s berhasil dihapus (head).", label, host_str);
        return SUCCESS;
    }
    while (current != NULL && sockaddr_equal((const struct sockaddr *)&current->client_addr, (const struct sockaddr *)client_addr)) {
        prev = current;
        current = current->next;
    }
    if (current == NULL) {
        LOG_DEBUG("%sIP %s tidak ditemukan.", label, host_str);
        return FAILURE;
    }
    prev->next = current->next;
    free(current);
    LOG_DEBUG("%sIP %s berhasil dihapus.", label, host_str);
    return SUCCESS;
}

master_sio_dc_session_t_status_t find_master_sio_dc_session(const char *label, master_sio_dc_session_t *head, struct sockaddr_in6 *client_addr) {
    master_sio_dc_session_t_status_t result;
    result.r_master_sio_dc_session_t = head;
    result.status = FAILURE;
    char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    int getname_res = getnameinfo((struct sockaddr *)client_addr, sizeof(*client_addr),
						host_str, NI_MAXHOST,
					  	port_str, NI_MAXSERV,
					  	NI_NUMERICHOST | NI_NUMERICSERV
					  );
	if (getname_res != 0) {
		LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
		return result;
	}
    while (result.r_master_sio_dc_session_t != NULL) {
        if (sockaddr_equal((const struct sockaddr *)&result.r_master_sio_dc_session_t->client_addr, (const struct sockaddr *)client_addr)) {
            LOG_DEBUG("%sIP %s ditemukan.", label, host_str);
            result.status = SUCCESS;
            return result;
        }
        result.r_master_sio_dc_session_t = result.r_master_sio_dc_session_t->next;
    }
    LOG_DEBUG("%sIP %s tidak ditemukan.", label, host_str);
    return result;
}

master_sio_dc_session_t_status_t find_first_ratelimited_master_sio_dc_session(const char *label, master_sio_dc_session_t *head, struct sockaddr_in6 *client_addr) {
    master_sio_dc_session_t_status_t result;
    result.r_master_sio_dc_session_t = head;
    result.status = FAILURE;
    char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    int getname_res = getnameinfo((struct sockaddr *)client_addr, sizeof(*client_addr),
						host_str, NI_MAXHOST,
					  	port_str, NI_MAXSERV,
					  	NI_NUMERICHOST | NI_NUMERICSERV
					  );
	if (getname_res != 0) {
		LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
		return result;
	}
    //==========FILTER RATELIMIT========================================
    while (result.r_master_sio_dc_session_t != NULL) {
        if (sockaddr_equal((const struct sockaddr *)&result.r_master_sio_dc_session_t->client_addr, (const struct sockaddr *)client_addr)) {
			uint64_t_status_t grtns_result = get_realtime_time_ns(label);    
			if (grtns_result.status == SUCCESS) {
				uint64_t ratelimit_ns = (uint64_t)RATELIMITSEC * 1000000000ULL;
				if ((grtns_result.r_uint64_t - result.r_master_sio_dc_session_t->dc_time) <= ratelimit_ns) {
					result.status = FAILURE_RATELIMIT;
					LOG_ERROR("%sIP %s mencoba melakukan koneksi diatas ratelimit.", label, host_str);					
					result.r_master_sio_dc_session_t->dc_time = grtns_result.r_uint64_t;	// <==== tambahan				
					return result;
				}
			} else {
				result.status = FAILURE_RATELIMIT;
				LOG_ERROR("%sGagal menghitung ratelimit untuk IP %s -> mencoba melakukan koneksi diatas ratelimit.", label, host_str);
				return result;
			}
        }
        result.r_master_sio_dc_session_t = result.r_master_sio_dc_session_t->next;
    }
    LOG_DEBUG("%sIP %s tidak ditemukan di tabel ratelimit.", label, host_str);
    //==================================================================
    result.r_master_sio_dc_session_t = head;
    while (result.r_master_sio_dc_session_t != NULL) {
		uint64_t_status_t grtns_result = get_realtime_time_ns(label);
		if (grtns_result.status == SUCCESS) {
			uint64_t ratelimit_ns = (uint64_t)RATELIMITSEC * 1000000000ULL;
			if ((grtns_result.r_uint64_t - result.r_master_sio_dc_session_t->dc_time) > ratelimit_ns) {
				result.status = grtns_result.status;
				LOG_DEBUG("%sIP %s menemukan reusable slot.", label, host_str);
				return result;
			}
		} else {
			result.status = grtns_result.status;
			LOG_DEBUG("%sIP %s gagal menemukan reusable slot yang bebas ratelimit -> dianggap gagal menemukan reusable slot.", label, host_str);
			return result;
		}
        result.r_master_sio_dc_session_t = result.r_master_sio_dc_session_t->next;
    }
    LOG_DEBUG("%sIP %s tidak menemukan reusable slot.", label, host_str);
    return result;
}

int_status_t count_master_sio_dc_sessions(const char *label, master_sio_dc_session_t *head) {
	int_status_t result;
	result.r_int = 0;
	result.status = FAILURE;
    master_sio_dc_session_t *current = head;
    while (current != NULL) {
        result.r_int++;
        current = current->next;
    }
    LOG_DEBUG("%sJumlah Correlation ID dalam list: %d", label, result.r_int);
    result.status = SUCCESS;
    return result;
}

void display_master_sio_dc_sessions(const char *label, master_sio_dc_session_t *head) {
    master_sio_dc_session_t *current = head;
    if (current == NULL) {
        LOG_DEBUG("%sList kosong.", label);
        return;
    }
    LOG_DEBUG("%sIsi list: ", label);
    while (current != NULL) {
        char host_str[NI_MAXHOST];
        char port_str[NI_MAXSERV];
        int getname_res = getnameinfo((struct sockaddr *)&current->client_addr, sizeof(current->client_addr),
                            host_str, NI_MAXHOST,
                            port_str, NI_MAXSERV,
                            NI_NUMERICHOST | NI_NUMERICSERV
                          );
        if (getname_res != 0) {
            LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
            continue;
        }
    }
    LOG_DEBUG("%sNULL", label);
}

void free_master_sio_dc_sessions(const char *label, master_sio_dc_session_t **head) {
    master_sio_dc_session_t *current = *head;
    master_sio_dc_session_t *next;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    *head = NULL; // Pastikan head menjadi NULL setelah semua node dibebaskan
    LOG_DEBUG("%smaster_sio_dc_sessions dibebaskan.", label);
}
