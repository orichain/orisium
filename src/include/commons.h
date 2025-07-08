#ifndef COMMONS_H
#define COMMONS_H

#include <unistd.h>
#include <sys/wait.h>

#define IPC_LENGTH_PREFIX_BYTES sizeof(uint32_t)

#define CHECK_BUFFER_BOUNDS(current_offset, bytes_to_write, total_buffer_size) \
    do { \
        if ((current_offset) + (bytes_to_write) > (total_buffer_size)) { \
            fprintf(stderr, "[SER Error]: Buffer overflow check failed. Offset: %zu, Bytes to write: %zu, Total buffer size: %zu\n", \
                    (size_t)(current_offset), (size_t)(bytes_to_write), (size_t)(total_buffer_size)); /* Explicit cast to size_t */ \
            return FAILURE_OOBUF; /* Mengembalikan status_t */ \
        } \
    } while(0)
    
#define CHECK_BUFFER_BOUNDS_NO_RETURN(current_offset, bytes_to_write, total_buffer_size) \
    ((current_offset) + (bytes_to_write) > (total_buffer_size)) ? \
    (fprintf(stderr, "[SER Error]: Buffer overflow check failed. Offset: %zu, Bytes to write: %zu, Total buffer size: %zu\n", \
             (size_t)(current_offset), (size_t)(bytes_to_write), (size_t)(total_buffer_size)), 1) : 0
             
#define SER_CHECK_SPACE(x) \
	do { \
		if (x > buffer_size) { \
			return FAILURE_OOBUF; \
		} \
    } while(0)
    
#define DESER_CHECK_SPACE(x) \
	do { \
		if (len < x) { \
			return FAILURE_OOBUF; \
		} \
    } while(0)

#define CLOSE_FD(x) \
    do { \
        if (x != -1) { \
            close(x); \
            x = -1; \
        } \
    } while(0)
    
#define CLOSE_UDS(x) \
    do { \
        if (x != 0) { \
			close(x); \
			x = 0; \
		} \
    } while(0)

#define CLOSE_PID(x) do { \
    if (x > 0) { \
        kill(x, SIGTERM); \
        waitpid(x, NULL, 0); \
        x = 0; \
    } \
} while (0)
             
#endif
