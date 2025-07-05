#include <stdarg.h> // for va_end, va_list, va_start
#include <stdio.h>  // for fprintf, vfprintf, FILE, NULL, stderr, stdout
#include <time.h>   // for localtime, strftime, time, time_t

#include "log.h"    // for log_write

#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
    #include <dirent.h>     // for dirent, closedir, opendir, readdir, DIR, DT_REG
    #include <errno.h>      // for errno
    #include <stdint.h>     // for uint64_t
    #include <stdlib.h>     // for exit, EXIT_FAILURE
    #include <string.h>     // for strerror, strlen, strncmp
    #include <sys/stat.h>   // for stat, mkdir

    #include "globals.h"    // for shutdown_requested
    #include "utilities.h"  // for get_realtime_time_ns, sleep_s

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

    static void get_time_str(char *buf, size_t len) {
        time_t t = time(NULL);
        struct tm tm_info;
        localtime_r(&t, &tm_info);
        strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm_info);
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
            if (entry->d_type != DT_REG) continue; // skip non-regular files
            if (strncmp(entry->d_name, "20", 2) != 0) continue; // must start with year
            if (strlen(entry->d_name) != 14) continue; // "YYYY-MM-DD.log"

            // Parse date from filename
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
		uint64_t_status_t grtns_result = get_realtime_time_ns("[LOG]: ");
		if (grtns_result.status == SUCCESS) {
			uint64_t current_time = grtns_result.r_uint64_t;
			uint64_t start_time = current_time;
			uint64_t clean_every = (uint64_t)86400 * 1000000000ULL; // 24 hours

			cleanup_old_logs(7);
			while (!shutdown_requested) {
				grtns_result = get_realtime_time_ns("[LOG]: ");
				if (grtns_result.status == SUCCESS) {
					current_time = grtns_result.r_uint64_t;
					if ((current_time - start_time) > clean_every) {
						cleanup_old_logs(7);
						start_time = current_time;
					}
					sleep_s(1);
				} else {
					fprintf(stderr, "[LOG]: Log cleaner failed to get current_time.\n");
				}
			}	
		}
		fprintf(stderr, "[LOG]: Log cleaner failed to start %s\n", strerror(errno));
        return NULL;
    }
#endif

#ifdef PRODUCTION
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
    #ifdef TOSCREEN
        void log_write(const char *level, const char *file, const char *func, int line, const char *fmt, ...) {
            va_list args;
            va_start(args, fmt);

            time_t now = time(NULL);
            struct tm *t = localtime(&now);
            char time_buf[32];
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

            FILE *out = (level[0] == 'E' || level[0] == 'W') ? stderr : stdout;

            // Format: [TIMESTAMP] [LEVEL] (FILE:FUNCTION:LINE)\nMESSAGE\n
            fprintf(out, "[%s] [%s] (%s:%s:%d)\n", time_buf, level, file, func, line);
            vfprintf(out, fmt, args);
            fprintf(out, "\n"); // Tambahkan newline setelah pesan log
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
