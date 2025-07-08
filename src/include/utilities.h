#ifndef UTILITIES_H
#define UTILITIES_H

#include "types.h"

status_t set_nonblocking(const char* label, int fd);
status_t sleep_ns(long nanoseconds);
status_t sleep_us(long microseconds);
status_t sleep_ms(long milliseconds);
status_t sleep_s(double seconds);
uint64_t_status_t get_realtime_time_ns(const char *label);
status_t ensure_directory_exists(const char *label, const char *path);

void print_hex(const char* label, const uint8_t* data, size_t len, int uppercase);

#endif
