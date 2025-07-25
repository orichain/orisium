#include "sessions/master_session.h"
#include "utilities.h"

void cleanup_hello_ack(const char *label, async_type_t *async, hello_ack_t *h) {
    h->interval_ack_timer_fd = (double)1;
    h->ack_sent_try_count = 0x00;
    async_delete_event(label, async, &h->ack_timer_fd);
    CLOSE_FD(&h->ack_timer_fd);
}

void setup_hello_ack(hello_ack_t *h) {
    h->interval_ack_timer_fd = (double)1;
    h->ack_sent_try_count = 0x00;
    CLOSE_FD(&h->ack_timer_fd);
}
