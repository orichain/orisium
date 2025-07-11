#ifndef LOG_H
#define LOG_H

#include <stdio.h>

#ifdef PRODUCTION
	void log_write(const char *level, const char *fmt, ...);
    #ifdef NDEBUG
        void log_no_write(const char *level, const char *fmt, ...);
        #define LOG_DEBUG(fmt, ...) log_no_write("DEBUG", __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
    #else
        #define LOG_DEBUG(fmt, ...) log_write("DEBUG", __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
    #endif
	#define LOG_INFO(fmt, ...)  log_write("INFO",  fmt, ##__VA_ARGS__)
	#define LOG_WARN(fmt, ...)  log_write("WARN",  fmt, ##__VA_ARGS__)
	#define LOG_ERROR(fmt, ...) log_write("ERROR", fmt, ##__VA_ARGS__)  
    #define LOG_DEVEL_DEBUG(fmt, ...) log_write("DEVEL-DEBUG", __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
#elif defined(DEVELOPMENT)
	void log_write(const char *level, const char *file, const char *func, int line, const char *fmt, ...);
    #ifdef NDEBUG
        void log_no_write(const char *level, const char *file, const char *func, int line, const char *fmt, ...);
        #define LOG_DEBUG(fmt, ...) log_no_write("DEBUG", __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
    #else
        #define LOG_DEBUG(fmt, ...) log_write("DEBUG", __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
    #endif
	#define LOG_INFO(fmt, ...)  log_write("INFO",  __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
	#define LOG_WARN(fmt, ...)  log_write("WARN",  __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
	#define LOG_ERROR(fmt, ...) log_write("ERROR", __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
    #define LOG_DEVEL_DEBUG(fmt, ...) log_write("DEVEL-DEBUG", __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
#endif

#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
	void log_init();
	void log_close();
	void *log_cleaner_thread(void *arg);
#endif

#endif
