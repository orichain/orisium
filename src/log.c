#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "log.h"

#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
#include <dirent.h>

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
#if defined(__clang__)
#if __clang_major__ < 21
#include <sys/dirent.h>
#endif
#endif
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "globals.h"
#include "utilities.h"
#include "types.h"

static FILE *log_fp = NULL;
static char current_filename[64] = "";

static void get_log_filename(char *buf, size_t len) {
    time_t t = time(NULL);
    struct tm tm_info;
    localtime_r(&t, &tm_info);
    snprintf(buf, len, "logs/%04d-%02d-%02d.log",
             tm_info.tm_year + 1900,
             tm_info.tm_mon + 1,
             tm_info.tm_mday);
}

void log_init() {
    struct stat st = {0};
    if (stat("logs", &st) == -1) {
        mkdir("logs", 0755);
    }

    get_log_filename(current_filename, sizeof(current_filename));
    log_fp = fopen(current_filename, "w+");
    if (!log_fp) {
        fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void log_close() {
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}

void cleanup_old_logs(int max_age_days) {
    DIR *dir = opendir("logs");
    if (!dir) {
        fprintf(stderr, "Failed to open logs directory: %s\n", strerror(errno));
        return;
    }

    struct dirent *entry;
    time_t now = time(NULL);

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue;

        if (strlen(entry->d_name) != 14) continue;
        if (strstr(entry->d_name, ".log") == NULL) continue;
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        int year, month, day;
        if (sscanf(entry->d_name, "%4d-%2d-%2d.log", &year, &month, &day) != 3)
            continue;

        struct tm file_tm = {0};
        file_tm.tm_year = year - 1900;
        file_tm.tm_mon  = month - 1;
        file_tm.tm_mday = day;
        file_tm.tm_hour = 0;
        file_tm.tm_min  = 0;
        file_tm.tm_sec  = 0;

        time_t file_time = mktime(&file_tm);
        if (file_time == -1) {
            fprintf(stderr, "Invalid mktime() for: %s\n", entry->d_name);
            continue;
        }

        double diff_days = difftime(now, file_time) / (60 * 60 * 24);
        if (diff_days >= max_age_days) {
            char filepath[128];
            snprintf(filepath, sizeof(filepath), "logs/%s", entry->d_name);
            if (remove(filepath) == 0) {
                fprintf(stderr, "Deleted old log: %s\n", filepath);
            } else {
                fprintf(stderr, "Failed to delete old log: %s - %s\n", filepath, strerror(errno));
            }
        }
    }

    closedir(dir);
}

void *log_cleaner_thread(void *arg) {
	uint64_t_status_t grtns_result = get_monotonic_time_ns("[LOG]: ");
	if (grtns_result.status == SUCCESS) {
		uint64_t current_time = grtns_result.r_uint64_t;
		uint64_t start_time = current_time;
		uint64_t clean_every = (uint64_t)86400 * 1000000000ULL; // 24 hours

		cleanup_old_logs(7);
		while (!shutdown_requested) {
			grtns_result = get_monotonic_time_ns("[LOG]: ");
			if (grtns_result.status == SUCCESS) {
				current_time = grtns_result.r_uint64_t;
				if ((current_time - start_time) > clean_every) {
					if (!shutdown_requested) cleanup_old_logs(7);
					start_time = current_time;
				}
				if (sleep_s(1) != SUCCESS) {
					continue;
				}
			} else {
				fprintf(stderr, "[LOG]: Log cleaner failed to get current_time.\n");
			}
		}
	} else {
		fprintf(stderr, "[LOG]: Log cleaner failed to start %s\n", strerror(errno));
	}
    return NULL;
}
#endif

#ifdef PRODUCTION
void log_no_write(const char *level, const char *fmt, ...) {}
void log_write(const char *level, const char *fmt, ...) {
    char filename[64];
    get_log_filename(filename, sizeof(filename));

    if (strcmp(filename, current_filename) != 0) {
        log_close();
        strncpy(current_filename, filename, sizeof(current_filename));
        log_fp = fopen(current_filename, "a");
        if (!log_fp) {
            fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
            return;
        }
    }

    char timebuf[32];
    get_time_str(timebuf, sizeof(timebuf));

    // Format: [TIMESTAMP] [LEVEL] MESSAGE\n
    fprintf(log_fp, "[%s] [%s] ", timebuf, level);

    va_list args;
    va_start(args, fmt);
    vfprintf(log_fp, fmt, args);
    va_end(args);

    fprintf(log_fp, "\n"); // Pastikan ada newline setelah pesan log
    fflush(log_fp);
}
#elif defined(DEVELOPMENT)
void log_no_write(const char *level, const char *file, const char *func, int line, const char *fmt, ...) {}
#ifdef TOSCREEN
void log_write(const char *level, const char *file, const char *func, int line, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    time_t t = time(NULL);
    struct tm tm_info;
    localtime_r(&t, &tm_info);
    size_t time_buf_len = 32;
    char time_buf[time_buf_len];
    strftime(time_buf, time_buf_len, "%Y-%m-%d %H:%M:%S", &tm_info);

    FILE *out = (level[0] == 'E' || level[0] == 'W') ? stderr : stdout;
    fprintf(out, "[%s] [%s] (%s:%s:%d)\n", time_buf, level, file, func, line);
    vfprintf(out, fmt, args);
    fprintf(out, "\n");
    va_end(args);
}
#elif defined(TOFILE)
void log_write(const char *level, const char *file, const char *func, int line, const char *fmt, ...) {
    char filename[64];
    get_log_filename(filename, sizeof(filename));

    if (strcmp(filename, current_filename) != 0) {
        log_close();
        strncpy(current_filename, filename, sizeof(current_filename));
        log_fp = fopen(current_filename, "a");
        if (!log_fp) {
            fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
            return;
        }
    }

    char timebuf[32];
    get_time_str(timebuf, sizeof(timebuf));

    // Format: [TIMESTAMP] [LEVEL] (FILE:FUNCTION:LINE)\nMESSAGE\n
    fprintf(log_fp, "[%s] [%s] (%s:%s:%d)\n", timebuf, level, file, func, line);

    va_list args;
    va_start(args, fmt);
    vfprintf(log_fp, fmt, args);
    va_end(args);

    fprintf(log_fp, "\n"); // Tambahkan newline setelah pesan log
    fflush(log_fp);
}
#endif
#endif
