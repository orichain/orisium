#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <string.h>      // for memset, strncpy
#include <fcntl.h>       // for fcntl, F_GETFL, F_SETFL, O_NONBLOCK

#include "log.h"
#include "types.h"

status_t set_nonblocking(const char* label, int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        LOG_ERROR("%sfcntl F_GETFL: %s", label, strerror(errno));
        return FAILURE;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_ERROR("%sfcntl F_SETFL O_NONBLOCK: %s", label, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}
