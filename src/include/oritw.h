#ifndef ORITW_H
#define ORITW_H

#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "async.h"
#include "constants.h"
#include "log.h"
#include "types.h"
#include "utilities.h"

#if (WHEEL_SIZE & (WHEEL_SIZE - 1)) != 0
#error "WHEEL_SIZE must be a power of 2 for optimal performance."
#endif
#define WHEEL_MASK (WHEEL_SIZE - 1)

typedef struct {
    uint64_t expiration_tick;
    uint16_t bucket_index;
} min_heap_node_t;

typedef struct {
    min_heap_node_t nodes[WHEEL_SIZE];
    uint32_t size;
    uint16_t bucket_to_heap_index[WHEEL_SIZE];
} min_heap_t;

typedef struct timer_event_t {
    struct timer_event_t *next;
    uint64_t expiration_tick;
    uint64_t timer_id;
    struct timer_event_t **prev_next_ptr;
    uint32_t level_index;
    uint16_t slot_index;
    bool removed;
    bool collected_for_cleanup;
} timer_event_t;

typedef struct {
    timer_event_t *event;
    uint64_t id;
} timer_id_t;

typedef struct {
    timer_event_t *head;
    timer_event_t *tail;
    uint64_t min_expiration;
} timer_bucket_t;

typedef struct {
    timer_bucket_t buckets[WHEEL_SIZE];
    uint16_t current_index;
    uint64_t tick_factor;
    uint64_t current_tick_count;
    min_heap_t min_heap;
} timer_wheel_t;

typedef struct {
    timer_wheel_t timer_wheel;
    int tick_event_fd;
    int timeout_event_fd;
    timer_event_t *ready_queue_head;
    timer_event_t *ready_queue_tail;
    uint64_t global_current_tick;
    double last_delay_us;
    uint64_t next_expiration_tick;
    timer_event_t *event_pool_head;
} ori_timer_wheel_t;

typedef ori_timer_wheel_t *ori_timer_wheels_t[MAX_TIMER_LEVELS];

static inline void min_heap_swap(min_heap_node_t *a, min_heap_node_t *b, min_heap_t *heap) {
    heap->bucket_to_heap_index[a->bucket_index] = (uint16_t)(b - heap->nodes);
    heap->bucket_to_heap_index[b->bucket_index] = (uint16_t)(a - heap->nodes);
    min_heap_node_t temp = *a;
    *a = *b;
    *b = temp;
}

static inline void min_heapify_down(min_heap_t *heap, uint32_t i) {
    uint32_t smallest = i;
    uint32_t left = 2 * i + 1;
    uint32_t right = 2 * i + 2;
    if (left < heap->size && heap->nodes[left].expiration_tick < heap->nodes[smallest].expiration_tick) {
        smallest = left;
    }
    if (right < heap->size && heap->nodes[right].expiration_tick < heap->nodes[smallest].expiration_tick) {
        smallest = right;
    }
    if (smallest != i) {
        min_heap_swap(&heap->nodes[i], &heap->nodes[smallest], heap);
        min_heapify_down(heap, smallest);
    }
}

static inline void min_heapify_up(min_heap_t *heap, uint32_t i) {
    while (i != 0 && heap->nodes[(i - 1) / 2].expiration_tick > heap->nodes[i].expiration_tick) {
        min_heap_swap(&heap->nodes[i], &heap->nodes[(i - 1) / 2], heap);
        i = (i - 1) / 2;
    }
}

static inline void min_heap_init(min_heap_t *heap) {
    heap->size = WHEEL_SIZE;
    for (uint32_t i = 0; i < WHEEL_SIZE; ++i) {
        heap->nodes[i].expiration_tick = ULLONG_MAX;
        heap->nodes[i].bucket_index = (uint16_t)i;
        heap->bucket_to_heap_index[i] = (uint16_t)i;
    }
}

static inline void min_heap_update(min_heap_t *heap, uint16_t bucket_index, uint64_t new_expiration) {
    uint32_t i = heap->bucket_to_heap_index[bucket_index];
    if (i >= heap->size) return;
    uint64_t old_expiration = heap->nodes[i].expiration_tick;
    heap->nodes[i].expiration_tick = new_expiration;
    if (new_expiration < old_expiration) {
        min_heapify_up(heap, i);
    } else if (new_expiration > old_expiration) {
        min_heapify_down(heap, i);
    }
}

static inline uint64_t min_heap_get_min(min_heap_t *heap) {
    return heap->nodes[0].expiration_tick;
}

static inline timer_event_t *oritw_pool_alloc(ori_timer_wheel_t *timer) {
    timer_event_t *event;

    if (timer->event_pool_head != NULL) {
        event = timer->event_pool_head;
        timer->event_pool_head = event->next;
    } else {
        event = malloc(sizeof(timer_event_t));
        if (event == NULL) {
            return NULL;
        }
    }
    event->next = NULL;
    event->prev_next_ptr = NULL;
    event->slot_index = WHEEL_SIZE;
    event->level_index = MAX_TIMER_LEVELS;
    event->expiration_tick = 0;
    event->timer_id = 0;
    event->removed = false;
    event->collected_for_cleanup = false;
    return event;
}

static inline void oritw_pool_free_internal(ori_timer_wheel_t *timer, timer_event_t *event) {
    if (!event) return;
    event->expiration_tick = 0;
    event->prev_next_ptr = NULL;
    event->timer_id = 0;
    event->removed = false;
    event->collected_for_cleanup = false;
    event->next = timer->event_pool_head;
    timer->event_pool_head = event;
}

static inline void oritw_pool_free(ori_timer_wheels_t timers, timer_event_t *event) {
    ori_timer_wheel_t *timer = timers[event->level_index];
    oritw_pool_free_internal(timer, event);
}

static inline void oritw_collect_list_for_cleanup(timer_event_t **list_head_ptr, timer_event_t **collector_head) {
    timer_event_t *cur = *list_head_ptr;
    while (cur != NULL) {
        timer_event_t *next = cur->next;
        if (!cur->collected_for_cleanup) {
            cur->collected_for_cleanup = true;
            cur->next = *collector_head;
            *collector_head = cur;
        }
        cur = next;
    }
    *list_head_ptr = NULL;
}

static inline void oritw_free_collector(timer_event_t *collector_head) {
    timer_event_t *cur = collector_head;
    while (cur != NULL) {
        timer_event_t *next = cur->next;
        cur->next = NULL;
        cur->prev_next_ptr = NULL;
        cur->collected_for_cleanup = false;
        free(cur);
        cur = next;
    }
}

static inline bool oritw_find_earliest_event(ori_timer_wheel_t *timer, uint64_t *out_expiration) {
    uint64_t min_abs_expiration = min_heap_get_min(&timer->timer_wheel.min_heap);
    if (min_abs_expiration == ULLONG_MAX || min_abs_expiration <= timer->global_current_tick) {
        timer->next_expiration_tick = ULLONG_MAX;
        if (out_expiration) *out_expiration = ULLONG_MAX;
        return false;
    }
    timer->next_expiration_tick = min_abs_expiration;
    if (out_expiration) *out_expiration = min_abs_expiration;
    return true;
}

static inline status_t oritw_reschedule_main_timer(
    const char *label, 
    async_type_t *async, 
    ori_timer_wheels_t timers,
    uint32_t level
)
{
    ori_timer_wheel_t *timer = timers[level];
    uint64_t next_expiration_tick;
    bool earliest_event_found = oritw_find_earliest_event(timer, &next_expiration_tick);
    if (earliest_event_found && next_expiration_tick > timer->global_current_tick) {
        uint64_t delay_tick = next_expiration_tick - timer->global_current_tick;
        double delay_us = (double)delay_tick;
        double delay_s = delay_us / 1e6;
        timer->last_delay_us = delay_us;
        timer->next_expiration_tick = next_expiration_tick;
        if (create_timer_oneshot(label, async, &timer->tick_event_fd, delay_s) != SUCCESS) {
            LOG_ERROR("%sFailed to re-arm main tick timer (delay_us=%.2f).", label, delay_us);
            return FAILURE;
        }
        //LOG_DEVEL_DEBUG("%sRescheduled main timer: delay_us=%.2f next_tick=%" PRIu64, label, delay_us, next_expiration_tick);
    } else {
        timer->last_delay_us = 0.0;
        timer->next_expiration_tick = ULLONG_MAX;
        if (timer->tick_event_fd != -1) {
            if (update_timer_oneshot(label, &timer->tick_event_fd, 0.0) != SUCCESS) {
                LOG_ERROR("%sFailed to disarm main tick timer.", label);
                return FAILURE;
            }
        }
        //LOG_DEVEL_DEBUG("%sMain timer disarmed (no future event).", label);
    }
    return SUCCESS;
}

static inline status_t oritw_remove_event_internal(ori_timer_wheel_t *timer, timer_event_t *event_to_remove) {
    if (!event_to_remove) return SUCCESS;
    if (event_to_remove->timer_id == 0 || event_to_remove->removed) {
        if (event_to_remove->timer_id == 0) {
             LOG_WARN("oritw_remove_event_internal: Detected stale pointer (event id=0). Freeing event to pool without wheel removal.");
        }
        event_to_remove->removed = true;
        event_to_remove->next = NULL;
        event_to_remove->prev_next_ptr = NULL;
        oritw_pool_free_internal(timer, event_to_remove);
        return SUCCESS;
    }
    if (event_to_remove->slot_index >= WHEEL_SIZE) {
        event_to_remove->removed = true;
        event_to_remove->next = NULL;
        event_to_remove->prev_next_ptr = NULL;
        oritw_pool_free_internal(timer, event_to_remove);
        return SUCCESS;
    }
    timer_wheel_t *timer_wheel = &timer->timer_wheel;
    timer_bucket_t *bucket = &timer_wheel->buckets[event_to_remove->slot_index];
    bool was_tail = (bucket->tail == event_to_remove);
    uint64_t removed_exp = event_to_remove->expiration_tick;
    *(event_to_remove->prev_next_ptr) = event_to_remove->next;
    if (event_to_remove->next) {
        event_to_remove->next->prev_next_ptr = event_to_remove->prev_next_ptr;
    }
    if (bucket->head == NULL) {
        bucket->tail = NULL;
        bucket->min_expiration = ULLONG_MAX;
    } else if (was_tail) {
        timer_event_t *it = bucket->head;
        timer_event_t *last = NULL;
        while (it) {
            last = it;
            it = it->next;
        }
        bucket->tail = last;
    }
    if (bucket->head != NULL && removed_exp == bucket->min_expiration) {
        uint64_t new_min = ULLONG_MAX;
        for (timer_event_t *it = bucket->head; it; it = it->next) {
            if (it->expiration_tick < new_min) new_min = it->expiration_tick;
        }
        bucket->min_expiration = new_min;
    }
    min_heap_update(&timer_wheel->min_heap, event_to_remove->slot_index, bucket->min_expiration);
    oritw_find_earliest_event(timer, NULL);
    event_to_remove->prev_next_ptr = NULL;
    event_to_remove->next = NULL;
    event_to_remove->removed = true;
    event_to_remove->slot_index = WHEEL_SIZE;
    oritw_pool_free_internal(timer, event_to_remove);
    return SUCCESS;
}

static inline status_t oritw_remove_event(
    const char *label, 
    async_type_t *async, 
    ori_timer_wheels_t timers, 
    timer_event_t *event_to_remove
)
{
    if (!event_to_remove) return SUCCESS;
    if (event_to_remove->removed) {
        //LOG_DEVEL_DEBUG("oritw_queue_remove_event: event id=%" PRIu64 " already removed, skipping", event_to_remove->timer_id);
        return SUCCESS;
    }
    uint32_t level_index = event_to_remove->level_index;
    ori_timer_wheel_t *timer = timers[level_index];
    if (!timer) return FAILURE;
    event_to_remove->next = NULL;
    uint64_t expire = event_to_remove->expiration_tick;
    uint64_t current_min_exp = min_heap_get_min(&timer->timer_wheel.min_heap);
    bool should_reschedule = false;
    if (expire <= current_min_exp) {
        should_reschedule = true;
    }
    if (oritw_remove_event_internal(timer, event_to_remove) != SUCCESS) return FAILURE;
    if (should_reschedule) {
        if (oritw_reschedule_main_timer(label, async, timers, level_index) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

static inline void oritw_calculate_level(
    ori_timer_wheels_t timers,
    uint64_t delay_us,
    uint32_t *level_index
)
{
    if (delay_us < 30000ULL) {
        *level_index = 0;
        return;
    }
    if (delay_us < 50000ULL) {
        *level_index = 1;
        return;
    }
    if (delay_us < 100000ULL) {
        *level_index = 2;
        return;
    }
    if (delay_us < 500000ULL) {
        *level_index = 3;
        return;
    }
    if (delay_us < 1000000ULL) {
        *level_index = 4;
        return;
    }
    if (delay_us < 3000000ULL) {
        *level_index = 5;
        return;
    }
    if (delay_us < 5000000ULL) {
        *level_index = 6;
        return;
    }
    if (delay_us < 7000000ULL) {
        *level_index = 7;
        return;
    }
    if (delay_us < 9000000ULL) {
        *level_index = 8;
        return;
    }
    *level_index = MAX_TIMER_LEVELS - 1;
}

static inline void oritw_calculate_slot(
    ori_timer_wheel_t *timer,
    uint64_t expiration_tick,
    uint32_t *slot_index
)
{
    timer_wheel_t *l0 = &timer->timer_wheel;
    uint64_t abs_slot_index = expiration_tick / l0->tick_factor;
    *slot_index = (uint32_t)(abs_slot_index & WHEEL_MASK);
    if (expiration_tick <= timer->global_current_tick) {
        *slot_index = l0->current_index;
    }
}

static inline status_t oritw_add_event(
    const char *label, 
    async_type_t *async, 
    ori_timer_wheels_t timers,
    timer_id_t *timer_id,
    double double_delay_us
)
{
    if (!timer_id) return FAILURE;
    timer_id->event = NULL;
    uint64_t delay_us = (uint64_t)ceil(double_delay_us);
    if (delay_us == 0 && double_delay_us > 0.0) {
        delay_us = 1;
    }
    uint32_t level_index;
    oritw_calculate_level(timers, delay_us, &level_index);
    ori_timer_wheel_t *timer = timers[level_index];
    timer_event_t *new_event = oritw_pool_alloc(timer);
    if (!new_event) {
        return FAILURE_NOMEM;
    }
    uint64_t expire;
    if (UINT64_MAX - timer->global_current_tick < delay_us) {
        expire = UINT64_MAX;
    } else {
        expire = timer->global_current_tick + delay_us;
    }
    new_event->expiration_tick = expire;
    new_event->timer_id = timer_id->id;
    new_event->level_index = level_index;
    new_event->next = NULL;
    bool should_reschedule = false;
    uint64_t current_min_exp = min_heap_get_min(&timer->timer_wheel.min_heap);
    if (expire < current_min_exp) {
        should_reschedule = true;
    }
    timer_id->event = new_event;
    uint32_t slot_index;
    oritw_calculate_slot(timer, new_event->expiration_tick, &slot_index);
    timer_wheel_t *wheel = &timer->timer_wheel;
    timer_bucket_t *bucket = &wheel->buckets[slot_index];
    new_event->slot_index = (uint16_t)slot_index;
    new_event->next = NULL;
    if (bucket->tail) {
        bucket->tail->next = new_event;
        new_event->prev_next_ptr = &bucket->tail->next;
        bucket->tail = new_event;
    } else {
        bucket->head = new_event;
        bucket->tail = new_event;
        new_event->prev_next_ptr = &bucket->head;
    }
    if (new_event->expiration_tick < bucket->min_expiration) {
        bucket->min_expiration = new_event->expiration_tick;
        min_heap_update(&wheel->min_heap, (uint16_t)slot_index, bucket->min_expiration);
    }
    timer->next_expiration_tick = min_heap_get_min(&timer->timer_wheel.min_heap);
    if (should_reschedule) {
        if (oritw_reschedule_main_timer(label, async, timers, level_index) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

static inline status_t oritw_process_expired_l0(ori_timer_wheel_t *timer, uint32_t start_index, uint32_t end_index) {
    uint32_t current_slot_index = start_index;
    timer_wheel_t *l0 = &timer->timer_wheel;
    while (true) {
        timer_bucket_t *bucket = &l0->buckets[current_slot_index];
        timer_event_t *cur = bucket->head;
        timer_event_t *next_event = NULL;
        bucket->head = NULL;
        bucket->tail = NULL;
        uint64_t new_min_exp = ULLONG_MAX;
        while (cur) {
            next_event = cur->next;
            if (cur->removed || cur->collected_for_cleanup) {
                cur = next_event;
                continue;
            }
            if (cur->expiration_tick <= timer->global_current_tick) {
                cur->next = NULL;
                if (timer->ready_queue_tail) {
                    cur->prev_next_ptr = &timer->ready_queue_tail->next;
                    timer->ready_queue_tail->next = cur;
                    timer->ready_queue_tail = cur;
                } else {
                    timer->ready_queue_head = cur;
                    timer->ready_queue_tail = cur;
                    cur->prev_next_ptr = &timer->ready_queue_head;
                }
            } else {
                if (bucket->head == NULL) {
                    bucket->head = cur;
                    bucket->tail = cur;
                    cur->next = NULL;
                    cur->prev_next_ptr = &bucket->head;
                } else {
                    cur->prev_next_ptr = &bucket->tail->next;
                    bucket->tail->next = cur;
                    bucket->tail = cur;
                    cur->next = NULL;
                }
                cur->slot_index = (uint16_t)current_slot_index;
                if (cur->expiration_tick < new_min_exp) {
                    new_min_exp = cur->expiration_tick;
                }
            }
            cur = next_event;
        }
        bucket->min_expiration = new_min_exp;
        min_heap_update(&l0->min_heap, (uint16_t)current_slot_index, new_min_exp);
        if (current_slot_index == end_index) break;
        current_slot_index = (current_slot_index + 1) & WHEEL_MASK;
    }
    oritw_find_earliest_event(timer, NULL);
    return SUCCESS;
}

static inline status_t oritw_advance_time_and_process_expired(
    const char *label, 
    async_type_t *async, 
    ori_timer_wheels_t timers, 
    uint32_t level,
    uint64_t ticks_to_advance
)
{
    if (ticks_to_advance == 0) return SUCCESS;
    ori_timer_wheel_t *timer = timers[level];
    uint64_t remaining_ticks = ticks_to_advance;
    while (remaining_ticks > 0) {
        uint32_t l0_start_index = timer->timer_wheel.current_index;
        uint64_t slots_until_wrap = WHEEL_SIZE - l0_start_index;
        uint64_t chunk_advance = remaining_ticks < slots_until_wrap ? remaining_ticks : slots_until_wrap;
        if (chunk_advance == 0) break;
        uint32_t l0_end_index = (l0_start_index + (uint32_t)chunk_advance) & WHEEL_MASK;
        timer->timer_wheel.current_index = (uint16_t)l0_end_index;
        timer->global_current_tick += chunk_advance;
        if (oritw_process_expired_l0(timer, l0_start_index, l0_end_index) != SUCCESS) {
            return FAILURE;
        }
        remaining_ticks -= chunk_advance;
    }
    return oritw_reschedule_main_timer(label, async, timers, level);
}

static inline status_t oritw_setup(const char *label, async_type_t *async, ori_timer_wheels_t timers) {
    for (uint32_t llv = 0; llv < MAX_TIMER_LEVELS; ++llv) {
        timers[llv] = (ori_timer_wheel_t *)malloc(sizeof(ori_timer_wheel_t));
        if (!timers[llv]) return FAILURE;
        ori_timer_wheel_t *tw = timers[llv];
        tw->tick_event_fd = -1;
        tw->timeout_event_fd = -1;
        tw->ready_queue_head = NULL;
        tw->ready_queue_tail = NULL;
        tw->event_pool_head = NULL;
        tw->global_current_tick = 0;
        tw->last_delay_us = 0.0;
        tw->next_expiration_tick = ULLONG_MAX;
        timer_wheel_t *wheel = &tw->timer_wheel;
        wheel->current_index = 0;
        wheel->tick_factor = 1;
        wheel->current_tick_count = 0;
        min_heap_init(&wheel->min_heap);
        for (uint32_t s = 0; s < WHEEL_SIZE; ++s) {
            wheel->buckets[s].head = NULL;
            wheel->buckets[s].tail = NULL;
            wheel->buckets[s].min_expiration = ULLONG_MAX;
        }
        if (async_create_event(label, &tw->timeout_event_fd) != SUCCESS) return FAILURE;
        if (async_create_incoming_event(label, async, &tw->timeout_event_fd) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

static inline void oritw_cleanup(const char *label, async_type_t *async, ori_timer_wheels_t timers) {
    for (uint32_t llv = 0; llv < MAX_TIMER_LEVELS; ++llv) {
        ori_timer_wheel_t *tw = timers[llv];
        if (!tw) continue;
        timer_event_t *collector_head = NULL;
        timer_wheel_t *wheel = &tw->timer_wheel;
        for (uint32_t s = 0; s < WHEEL_SIZE; ++s) {
            timer_bucket_t *bucket = &wheel->buckets[s];
            oritw_collect_list_for_cleanup(&bucket->head, &collector_head);
            bucket->tail = NULL;
            bucket->min_expiration = ULLONG_MAX;
        }
        for (uint32_t i = 0; i < wheel->min_heap.size; ++i) {
            wheel->min_heap.nodes[i].expiration_tick = ULLONG_MAX;
        }
        oritw_collect_list_for_cleanup(&tw->ready_queue_head, &collector_head);
        tw->ready_queue_tail = NULL;
        oritw_collect_list_for_cleanup(&tw->event_pool_head, &collector_head);
        tw->event_pool_head = NULL;
        oritw_free_collector(collector_head);
        tw->global_current_tick = 0;
        tw->next_expiration_tick = ULLONG_MAX;
        tw->last_delay_us = 0.0;
        async_delete_event(label, async, &tw->tick_event_fd);
        CLOSE_FD(&tw->tick_event_fd);
        async_delete_event(label, async, &tw->timeout_event_fd);
        CLOSE_FD(&tw->timeout_event_fd);
        free(tw);
        timers[llv] = NULL;
    }
}

#endif
