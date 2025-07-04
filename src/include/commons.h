#ifndef COMMONS_H
#define COMMONS_H

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
             
#define SER_CHECK_SPACE(x) if (x > buffer_size) return FAILURE_OOBUF

#define DESER_CHECK_SPACE(x) if (len < x) return FAILURE_OOBUF

#define CLOSE_FD(x) if (x != -1) { close(x); x = -1; }
#define CLOSE_PAYLOAD(x) if (x) { free(x); x = NULL; }
#define CLOSE_PROTOCOL(x) if (x) { free(x); x = NULL; }
             
#endif
