#ifndef UTILITIES_H
#define UTILITIES_H

status_t set_nonblocking(const char* label, int fd);
void sleep_ns(long nanoseconds);
void sleep_us(long microseconds);
void sleep_ms(long milliseconds);
void sleep_s(double seconds);
uint64_t_status_t get_realtime_time_ns(const char *label);

#endif
