#ifndef ORITW_TIMER_EVENT_H
#define ORITW_TIMER_EVENT_H

#include <stdint.h>
#include <stdio.h>

#include "constants.h"
#include "oritlsf.h"

typedef enum {
    TE_UNKNOWN = (uint8_t)0x00,
    //----------------------------------------------------------------------
    TE_CHECKHEALTHY = (uint8_t)0x01,
    TE_HEARTBEAT = (uint8_t)0x02,
    //----------------------------------------------------------------------
    TE_GENERAL = (uint8_t)0x03
        //----------------------------------------------------------------------
} timer_event_type_t;

typedef struct timer_event_t {
    struct timer_event_t *next;
    struct timer_event_t *prev;
    struct timer_event_t *sorting_next;
    struct timer_event_t *sorting_prev;
    uint64_t expiration_tick;
    uint64_t timer_id;
    timer_event_type_t event_type;
    uint32_t shard_index;
    uint16_t bucket_index;
} timer_event_t;

static inline void timer_event_add_tail(timer_event_t **head, timer_event_t **tail, timer_event_t *event) {
    event->next = NULL;
    event->prev = *tail;
    if (*tail) {
        (*tail)->next = event;
    } else {
        *head = event;
    }
    *tail = event;
}

static inline void timer_event_add_head(timer_event_t **head, timer_event_t **tail, timer_event_t *event) {
    event->prev = NULL;
    event->next = *head;
    if (*head) {
        (*head)->prev = event;
    } else {
        *tail = event;
    }
    *head = event;
}

static inline void timer_event_insert_before(timer_event_t **head, timer_event_t **tail, timer_event_t *pos, timer_event_t *new_event) {
    if (!pos) {
        timer_event_add_tail(head, tail, new_event);
        return;
    }
    new_event->next = pos;
    new_event->prev = pos->prev;
    if (pos->prev) {
        pos->prev->next = new_event;
    } else {
        *head = new_event;
    }
    pos->prev = new_event;
}

static inline void timer_event_insert_after(timer_event_t **head, timer_event_t **tail, timer_event_t *pos, timer_event_t *new_event) {
    if (!pos) {
        timer_event_add_head(head, tail, new_event);
        return;
    }
    new_event->prev = pos;
    new_event->next = pos->next;
    if (pos->next) {
        pos->next->prev = new_event;
    } else {
        *tail = new_event;
    }
    pos->next = new_event;
}

static inline void timer_event_sorting_remove(timer_event_t **head, timer_event_t **tail, timer_event_t *event) {
    if (event->sorting_prev)
        event->sorting_prev->sorting_next = event->sorting_next;
    else
        *head = event->sorting_next;

    if (event->sorting_next)
        event->sorting_next->sorting_prev = event->sorting_prev;
    else
        *tail = event->sorting_prev;
    event->sorting_next = NULL;
    event->sorting_prev = NULL;
}

static inline void timer_event_remove(timer_event_t **head, timer_event_t **tail, timer_event_t *event) {
    if (!event) return;
    if (event->prev)
        event->prev->next = event->next;
    else
        *head = event->next;

    if (event->next)
        event->next->prev = event->prev;
    else
        *tail = event->prev;
    event->next = NULL;
    event->prev = NULL;
}

static inline timer_event_t *timer_event_pop_head(timer_event_t **head, timer_event_t **tail) {
    if (!(*head)) return NULL;
    timer_event_t *ev = *head;
    *head = ev->next;
    if (*head)
        (*head)->prev = NULL;
    else
        *tail = NULL;
    ev->next = ev->prev = NULL;
    return ev;
}

static inline timer_event_t *timer_event_pop_tail(timer_event_t **head, timer_event_t **tail) {
    if (!(*tail)) return NULL;
    timer_event_t *ev = *tail;
    *tail = ev->prev;
    if (*tail)
        (*tail)->next = NULL;
    else
        *head = NULL;
    ev->next = ev->prev = NULL;
    return ev;
}

static inline void timer_event_sorting_add_tail(timer_event_t **head, timer_event_t **tail, timer_event_t *event) {
    event->sorting_next = NULL;
    event->sorting_prev = *tail;
    if (*tail) {
        (*tail)->sorting_next = event;
    } else {
        *head = event;
    }
    *tail = event;
}

static inline void timer_event_sorting_add_head(timer_event_t **head, timer_event_t **tail, timer_event_t *event) {
    event->sorting_prev = NULL;
    event->sorting_next = *head;
    if (*head) {
        (*head)->sorting_prev = event;
    } else {
        *tail = event;
    }
    *head = event;
}

static inline void timer_event_sorting_insert_before(timer_event_t **head, timer_event_t **tail, timer_event_t *pos, timer_event_t *new_event) {
    if (!pos) {
        timer_event_sorting_add_tail(head, tail, new_event);
        return;
    }
    new_event->sorting_next = pos;
    new_event->sorting_prev = pos->sorting_prev;
    if (pos->sorting_prev) {
        pos->sorting_prev->sorting_next = new_event;
    } else {
        *head = new_event;
    }
    pos->sorting_prev = new_event;
}

static inline void timer_event_sorting_insert_after(timer_event_t **head, timer_event_t **tail, timer_event_t *pos, timer_event_t *new_event) {
    if (!pos) {
        timer_event_sorting_add_head(head, tail, new_event);
        return;
    }
    new_event->sorting_prev = pos;
    new_event->sorting_next = pos->sorting_next;
    if (pos->sorting_next) {
        pos->sorting_next->sorting_prev = new_event;
    } else {
        *tail = new_event;
    }
    pos->sorting_next = new_event;
}

static inline void timer_event_sorting_remove_all(timer_event_t **head, timer_event_t **tail) {
    timer_event_t *cur = *head;
    while (cur) {
        timer_event_t *next = cur->next;
        timer_event_sorting_remove(head, tail, cur);
        cur = next;
    }
    *head = *tail = NULL;
}

static inline void timer_event_cleanup(oritlsf_pool_t *pool, timer_event_t **head, timer_event_t **tail) {
    timer_event_t *cur = *head;
    while (cur) {
        timer_event_t *next = cur->next;
        cur->expiration_tick = 0;
        cur->timer_id = 0;
        cur->bucket_index = WHEEL_SIZE;
        cur->shard_index = MAX_TIMER_SHARD;
        oritlsf_free(pool, (void **)&cur);
        cur = next;
    }
    *head = *tail = NULL;
}

#endif
