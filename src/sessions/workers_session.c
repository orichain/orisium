#include "async.h"
#include "sessions/workers_session.h"
#include "utilities.h"

void cleanup_hello(const char *label, async_type_t *async, hello_t *h) {
    h->interval_timer_fd = (double)1;
    h->sent_try_count = 0x00;
    async_delete_event(label, async, &h->timer_fd);
    CLOSE_FD(&h->timer_fd);
}

void setup_hello(hello_t *h) {
    h->interval_timer_fd = (double)1;
    h->sent_try_count = 0x00;
    CLOSE_FD(&h->timer_fd);
}
