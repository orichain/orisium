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
#define ORITW_MAX_CANDIDATES 16

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
    struct timer_event_t *prev;
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
    bool cleanup;
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
    uint32_t current = i; 
    uint32_t smallest;
    
    while (true) {
        smallest = current;
        uint32_t left = 2 * current + 1;
        uint32_t right = 2 * current + 2;

        if (left < heap->size && heap->nodes[left].expiration_tick < heap->nodes[smallest].expiration_tick) {
            smallest = left;
        }
        if (right < heap->size && heap->nodes[right].expiration_tick < heap->nodes[smallest].expiration_tick) {
            smallest = right;
        }
        
        if (smallest != current) {
            min_heap_swap(&heap->nodes[current], &heap->nodes[smallest], heap);
            current = smallest; 
        } else {
            break; 
        }
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
    return (heap->size > 0) ? heap->nodes[0].expiration_tick : ULLONG_MAX;
}

static inline uint64_t min_heap_get_kth_candidate(min_heap_t *heap, uint32_t k) {
    uint64_t candidates[ORITW_MAX_CANDIDATES];
    uint32_t n = heap->size < ORITW_MAX_CANDIDATES ? heap->size : ORITW_MAX_CANDIDATES;
    uint32_t count = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t t = heap->nodes[i].expiration_tick;
        if (t != ULLONG_MAX) candidates[count++] = t;
    }
    if (count < k) return ULLONG_MAX;
    for (uint32_t i = 0; i < k; ++i) {
        uint32_t min_i = i;
        for (uint32_t j = i + 1; j < count; ++j)
            if (candidates[j] < candidates[min_i]) min_i = j;
        uint64_t tmp = candidates[i];
        candidates[i] = candidates[min_i];
        candidates[min_i] = tmp;
    }
    return candidates[k - 1];
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
    event->prev = NULL;
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
    event->prev = NULL;
    event->prev_next_ptr = NULL;
    event->timer_id = 0;
    event->removed = false;
    event->collected_for_cleanup = false;
    event->slot_index = WHEEL_SIZE;
    event->level_index = MAX_TIMER_LEVELS;
    event->next = timer->event_pool_head;
    timer->event_pool_head = event;
}

static inline void oritw_pool_free(ori_timer_wheels_t timers, timer_event_t *event) {
    if (event->timer_id == 0 || event->removed || event->slot_index >= WHEEL_SIZE || event->level_index >= MAX_TIMER_LEVELS) return;
    ori_timer_wheel_t *timer = timers[event->level_index];
    if (!timer || timer->cleanup) return;
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
        cur->prev = NULL;
        cur->prev_next_ptr = NULL;
        cur->collected_for_cleanup = false;
        free(cur);
        cur = next;
    }
}

static inline bool oritw_find_earliest_event(ori_timer_wheel_t *timer, uint64_t *out_expiration) {
    uint64_t min_abs_expiration = min_heap_get_min(&timer->timer_wheel.min_heap);
    if (min_abs_expiration == ULLONG_MAX) {
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
    if (!timer || timer->cleanup) return FAILURE;
    uint64_t next_expiration_tick;
    bool earliest_event_found = oritw_find_earliest_event(timer, &next_expiration_tick);

    if (earliest_event_found) {
        uint64_t delay_tick = 0;
        if (next_expiration_tick > timer->global_current_tick) {
            delay_tick = next_expiration_tick - timer->global_current_tick;
        } 
        double delay_us = (double)delay_tick;
        double delay_s = delay_us / 1e6;
        timer->last_delay_us = delay_us;
        timer->next_expiration_tick = next_expiration_tick;
        if (timer->timeout_event_fd == -1) {
            if (async_create_event(label, &timer->timeout_event_fd) != SUCCESS) return FAILURE;
            if (async_create_incoming_event(label, async, &timer->timeout_event_fd) != SUCCESS) return FAILURE;
        }
        if (create_timer_oneshot(label, async, &timer->tick_event_fd, delay_s) != SUCCESS) {
            LOG_ERROR("%sFailed to re-arm main tick timer (delay_us=%.2f).", label, delay_us);
            return FAILURE;
        }
    } else {
        timer->last_delay_us = 0.0;
        timer->next_expiration_tick = ULLONG_MAX;
        if (timer->tick_event_fd != -1) {
            if (update_timer_oneshot(label, &timer->tick_event_fd, 0.0) != SUCCESS) {
                LOG_ERROR("%sFailed to disarm main tick timer.", label);
                return FAILURE;
            }
        }
    }
    return SUCCESS;
}

static inline status_t oritw_remove_event_internal(ori_timer_wheel_t *timer, timer_event_t *event_to_remove, bool *should_reschedule) {
    if (!event_to_remove) return SUCCESS;
    if (event_to_remove->timer_id == 0 || event_to_remove->removed || event_to_remove->slot_index >= WHEEL_SIZE || event_to_remove->level_index >= MAX_TIMER_LEVELS) {
        event_to_remove->removed = true;
        event_to_remove->next = NULL;
        event_to_remove->prev = NULL;
        event_to_remove->prev_next_ptr = NULL;
        oritw_pool_free_internal(timer, event_to_remove);
        *should_reschedule = false;
        return SUCCESS;
    }
    uint64_t expire = event_to_remove->expiration_tick;
    uint64_t current_min_exp = min_heap_get_min(&timer->timer_wheel.min_heap);
    *should_reschedule = (expire <= current_min_exp);
    timer_wheel_t *timer_wheel = &timer->timer_wheel;
    timer_bucket_t *bucket = &timer_wheel->buckets[event_to_remove->slot_index];
    if (event_to_remove->prev_next_ptr)
        *(event_to_remove->prev_next_ptr) = event_to_remove->next;
    if (event_to_remove->next) {
        event_to_remove->next->prev_next_ptr = event_to_remove->prev_next_ptr;
        event_to_remove->next->prev = event_to_remove->prev;
    }
    if (bucket->tail == event_to_remove) {
        bucket->tail = event_to_remove->prev;
    }
    if (bucket->head == event_to_remove) {
        bucket->head = event_to_remove->next;
    }
    if (bucket->head == NULL) {
        bucket->min_expiration = ULLONG_MAX; 
    }
    min_heap_update(&timer_wheel->min_heap, event_to_remove->slot_index, bucket->min_expiration);
    event_to_remove->prev_next_ptr = NULL;
    event_to_remove->prev = NULL;
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
        return SUCCESS;
    }
    uint32_t level_index = event_to_remove->level_index;
    if (level_index >= MAX_TIMER_LEVELS) return FAILURE;
    ori_timer_wheel_t *timer = timers[level_index];
    if (!timer || timer->cleanup) return FAILURE;
    bool should_reschedule = false;
    if (oritw_remove_event_internal(timer, event_to_remove, &should_reschedule) != SUCCESS) return FAILURE;
    if (should_reschedule) {
        if (oritw_reschedule_main_timer(label, async, timers, level_index) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

static inline uint32_t min_heap_collect_candidates(min_heap_t *heap, uint64_t out[ORITW_MAX_CANDIDATES]) {
    uint32_t limit = heap->size < ORITW_MAX_CANDIDATES ? heap->size : ORITW_MAX_CANDIDATES;
    uint32_t count = 0;
    for (uint32_t i = 0; i < limit; i++) {
        uint64_t t = heap->nodes[i].expiration_tick;
        if (t != ULLONG_MAX)
            out[count++] = t;
    }
    for (uint32_t i = 0; i + 1 < count; i++) {
        uint32_t min_i = i;
        for (uint32_t j = i + 1; j < count; j++)
            if (out[j] < out[min_i])
                min_i = j;
        uint64_t tmp = out[i];
        out[i] = out[min_i];
        out[min_i] = tmp;
    }
    return count;
}

static inline bool oritw_validate_min_gap_and_long_jump(
    ori_timer_wheels_t timers,
    uint64_t delay_us,
    uint32_t level,
    bool *reschedule
) {
    ori_timer_wheel_t *timer = timers[level];
    if (!timer || timer->cleanup) return false;
    uint64_t min_gap_us = (uint64_t)MIN_GAP_US;
    uint64_t expire;
    if (UINT64_MAX - timer->global_current_tick < delay_us)
        expire = UINT64_MAX;
    else
        expire = timer->global_current_tick + delay_us;
    uint64_t heap_candidates[ORITW_MAX_CANDIDATES];
    uint32_t count = min_heap_collect_candidates(&timer->timer_wheel.min_heap, heap_candidates);
    if (count == 0) {
        *reschedule = true;
        return true;
    }
    *reschedule = false;
    uint64_t first_exp = heap_candidates[0];
    if (first_exp >= expire)
        return false;
    for (uint32_t i = 0; i < count && i < ORITW_MAX_CANDIDATES; i++) {
        uint64_t exp_i = heap_candidates[i];
        if (exp_i == ULLONG_MAX) break;
        if (exp_i >= expire) break;
        uint64_t diff = expire - exp_i;
        if (diff < min_gap_us) {
            return false;
        }
    }
    return true;
}

static inline void oritw_calculate_level(
    ori_timer_wheels_t timers,
    uint64_t delay_us,
    uint32_t *level_index,
    bool *reschedule
)
{
    for (uint16_t llvl=0;llvl<(MAX_TIMER_LEVELS - 1);++llvl) {
        if (oritw_validate_min_gap_and_long_jump(timers, delay_us, llvl, reschedule)) {
            *level_index = llvl;
            return;
        }
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
    bool should_reschedule = false;
    oritw_calculate_level(timers, delay_us, &level_index, &should_reschedule);
    ori_timer_wheel_t *timer = timers[level_index];
    if (!timer || timer->cleanup) return FAILURE;
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
    new_event->prev = NULL; 
    timer_id->event = new_event;
    uint32_t slot_index;
    oritw_calculate_slot(timer, new_event->expiration_tick, &slot_index);
    timer_wheel_t *wheel = &timer->timer_wheel;
    timer_bucket_t *bucket = &wheel->buckets[slot_index];
    new_event->slot_index = (uint16_t)slot_index;
    if (bucket->tail) {
        bucket->tail->next = new_event;
        new_event->prev_next_ptr = &bucket->tail->next;
        new_event->prev = bucket->tail;     
        bucket->tail = new_event;
    } else {
        bucket->head = new_event;
        bucket->tail = new_event;
        new_event->prev_next_ptr = &bucket->head;
        new_event->prev = NULL;             
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
                cur->prev = NULL;             
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
                    cur->prev = NULL;           
                    cur->prev_next_ptr = &bucket->head;
                } else {
                    cur->prev_next_ptr = &bucket->tail->next;
                    cur->prev = bucket->tail;   
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
    if (!timer || timer->cleanup) return FAILURE;
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
        tw->cleanup = false;
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
    }
    return SUCCESS;
}

static inline void oritw_cleanup(const char *label, async_type_t *async, ori_timer_wheels_t timers) {
    for (uint32_t llv = 0; llv < MAX_TIMER_LEVELS; ++llv) {
        ori_timer_wheel_t *tw = timers[llv];
        if (!tw) continue;
        tw->cleanup = true;
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
