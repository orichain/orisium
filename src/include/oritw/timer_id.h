#ifndef ORITW_TIMER_ID_H
#define ORITW_TIMER_ID_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "oritw/timer_event.h"

typedef struct timer_id_t {
    timer_event_t *event;
    uint64_t id;
    double delay_us;
    timer_event_type_t event_type;
    struct timer_id_t *next;
    struct timer_id_t *prev;
} timer_id_t;

static inline void timer_id_add_tail(timer_id_t **head, timer_id_t **tail, timer_id_t *id) {
    id->next = NULL;
    id->prev = *tail;
    if (*tail) {
        (*tail)->next = id;
    } else {
        *head = id;
    }
    *tail = id;
}

static inline void timer_id_add_head(timer_id_t **head, timer_id_t **tail, timer_id_t *id) {
    id->prev = NULL;
    id->next = *head;
    if (*head) {
        (*head)->prev = id;
    } else {
        *tail = id;
    }
    *head = id;
}

static inline void timer_id_insert_before(timer_id_t **head, timer_id_t **tail, timer_id_t *pos, timer_id_t *new_id) {
    if (!pos) {
        timer_id_add_tail(head, tail, new_id);
        return;
    }
    new_id->next = pos;
    new_id->prev = pos->prev;
    if (pos->prev) {
        pos->prev->next = new_id;
    } else {
        *head = new_id;
    }
    pos->prev = new_id;
}

static inline void timer_id_insert_after(timer_id_t **head, timer_id_t **tail, timer_id_t *pos, timer_id_t *new_id) {
    if (!pos) {
        timer_id_add_head(head, tail, new_id);
        return;
    }
    new_id->prev = pos;
    new_id->next = pos->next;
    if (pos->next) {
        pos->next->prev = new_id;
    } else {
        *tail = new_id;
    }
    pos->next = new_id;
}

static inline void timer_id_remove(timer_id_t **head, timer_id_t **tail, timer_id_t *id) {
    if (!id) return;
    if (id->prev)
        id->prev->next = id->next;
    else
        *head = id->next;

    if (id->next)
        id->next->prev = id->prev;
    else
        *tail = id->prev;
    id->next = NULL;
    id->prev = NULL;
}

static inline timer_id_t *timer_id_pop_head(timer_id_t **head, timer_id_t **tail) {
    if (!(*head)) return NULL;
    timer_id_t *ev = *head;
    *head = ev->next;
    if (*head)
        (*head)->prev = NULL;
    else
        *tail = NULL;
    ev->next = ev->prev = NULL;
    return ev;
}

static inline timer_id_t *timer_id_pop_tail(timer_id_t **head, timer_id_t **tail) {
    if (!(*tail)) return NULL;
    timer_id_t *ev = *tail;
    *tail = ev->prev;
    if (*tail)
        (*tail)->next = NULL;
    else
        *head = NULL;
    ev->next = ev->prev = NULL;
    return ev;
}

static inline void timer_id_cleanup(timer_id_t **head, timer_id_t **tail) {
    timer_id_t *cur = *head;
    while (cur) {
        timer_id_t *next = cur->next;
        cur->id = 0;
        cur->delay_us = 0;
        cur->event = NULL;
        free(cur);
        cur = next;
    }
    *head = *tail = NULL;
}

#endif
