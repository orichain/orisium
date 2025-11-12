#ifndef ORITW_H
#define ORITW_H

#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "async.h"
#include "constants.h"
#include "log.h"
#include "types.h"
#include "utilities.h"
#include "oritw/timer_event.h"
#include "oritw/min_heap.h"

#if (WHEEL_SIZE & (WHEEL_SIZE - 1)) != 0
#error "WHEEL_SIZE must be a power of 2 for optimal performance."
#endif
#define WHEEL_MASK (WHEEL_SIZE - 1)

typedef struct {
    timer_event_t *head;
    timer_event_t *tail;
    uint64_t min_expiration;
} timer_bucket_t;

typedef struct {
    timer_bucket_t buckets[WHEEL_SIZE];
    uint16_t current_index;
    uint64_t tick_factor;
    min_heap_t min_heap;
} timer_wheel_t;

typedef struct {
    timer_wheel_t timer_wheel;
    int tick_event_fd;
    int timeout_event_fd;
    timer_event_t *sorting_queue_head;
    timer_event_t *sorting_queue_tail;
    timer_event_t *ready_queue_head;
    timer_event_t *ready_queue_tail;
    uint64_t global_current_tick;
    uint64_t initial_system_tick;
    double last_delay_us;
    uint64_t next_expiration_tick;
    timer_event_t *event_pool_head;
    timer_event_t *event_pool_tail;
    bool cleanup;
} ori_timer_wheel_t;

typedef struct timer_id_t {
    timer_event_t *event;
    uint64_t id;
    double delay_us;
    struct timer_id_t *next;
} timer_id_t;

typedef struct {
    int add_event_fd;
    timer_id_t *add_queue_head;
    timer_id_t *add_queue_tail;
    ori_timer_wheel_t *timer[MAX_TIMER_LEVELS];
} ori_timer_wheels_t;

static inline void oritw_add_timer_id_queue(ori_timer_wheels_t *tws, uint64_t id, double delay_us) {
    timer_id_t *new_tid = (timer_id_t *)calloc(1, sizeof(timer_id_t));
    if (!new_tid) return;
    new_tid->delay_us = delay_us;
    new_tid->id = id;
    new_tid->event = NULL;
    new_tid->next = NULL;
    if (tws->add_queue_tail) {
        tws->add_queue_tail->next = new_tid;
    } else {
        tws->add_queue_head = new_tid;
    }
    tws->add_queue_tail = new_tid;
}

static inline void oritw_cleanup_timer_id_queue(ori_timer_wheels_t *tws) {
    timer_id_t *current = tws->add_queue_head;
    timer_id_t *next;
    while (current) {
        next = current->next;
        free(current);
        current = next;
    }
    tws->add_queue_head = NULL;
    tws->add_queue_tail = NULL;
}

static inline timer_id_t *oritw_pop_timer_id_queue(ori_timer_wheels_t *tws) {
    if (!tws->add_queue_head) return NULL;
    timer_id_t *node = tws->add_queue_head;
    tws->add_queue_head = node->next;
    if (!tws->add_queue_head)
        tws->add_queue_tail = NULL;
    node->next = NULL;
    return node;
}

static inline timer_event_t *oritw_pool_alloc(ori_timer_wheel_t *timer) {
    timer_event_t *event;
    event = timer_event_pop_head(&timer->event_pool_head, &timer->event_pool_tail); 
    if (event == NULL) {
        event = malloc(sizeof(timer_event_t));
        if (event == NULL) {
            return NULL;
        }
    }
    event->next = NULL;
    event->prev = NULL;
    event->sorting_next = NULL;
    event->sorting_prev = NULL;
    event->slot_index = WHEEL_SIZE;
    event->level_index = MAX_TIMER_LEVELS;
    event->expiration_tick = 0;
    event->timer_id = 0;
    return event;
}

static inline void oritw_pool_free_internal(ori_timer_wheel_t *timer, timer_event_t *event) {
    if (!event) return;
    event->expiration_tick = 0;
    event->timer_id = 0;
    event->slot_index = WHEEL_SIZE;
    event->level_index = MAX_TIMER_LEVELS;
    timer_event_sorting_remove(&timer->sorting_queue_head, &timer->sorting_queue_tail, event);
    timer_event_remove(&timer->ready_queue_head, &timer->ready_queue_tail, event);
    timer_event_add_head(&timer->event_pool_head, &timer->event_pool_tail, event);
}

static inline void oritw_pool_free(ori_timer_wheels_t *timers, timer_event_t *event) {
    if (!event) return;
    if (event->timer_id == 0 || event->slot_index >= WHEEL_SIZE || event->level_index >= MAX_TIMER_LEVELS) return;
    ori_timer_wheel_t *timer = timers->timer[event->level_index];
    if (!timer || timer->cleanup) return;
    oritw_pool_free_internal(timer, event);
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
    ori_timer_wheels_t *timers,
    uint32_t level
)
{
    ori_timer_wheel_t *timer = timers->timer[level];
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
    uint64_t expire = event_to_remove->expiration_tick;
    uint64_t current_min_exp = min_heap_get_min(&timer->timer_wheel.min_heap);
    *should_reschedule = (expire <= current_min_exp);
    timer_wheel_t *timer_wheel = &timer->timer_wheel;
    timer_bucket_t *bucket = &timer_wheel->buckets[event_to_remove->slot_index];
    timer_event_remove(&bucket->head, &bucket->tail, event_to_remove);
    timer_event_sorting_remove(&timer->sorting_queue_head, &timer->sorting_queue_tail, event_to_remove);
    if (bucket->head == NULL) {
        bucket->min_expiration = ULLONG_MAX;
    }
    min_heap_update(&timer_wheel->min_heap, event_to_remove->slot_index, bucket->min_expiration);
    event_to_remove->slot_index = WHEEL_SIZE;
    oritw_pool_free_internal(timer, event_to_remove);
    return SUCCESS;
}

static inline status_t oritw_remove_event(
    const char *label,
    async_type_t *async,
    ori_timer_wheels_t *timers,
    timer_event_t *event_to_remove
)
{
    if (!event_to_remove) return SUCCESS;
    uint32_t level_index = event_to_remove->level_index;
    if (level_index >= MAX_TIMER_LEVELS) return FAILURE;
    ori_timer_wheel_t *timer = timers->timer[level_index];
    if (!timer || timer->cleanup) return FAILURE;
    bool should_reschedule = false;
    if (oritw_remove_event_internal(timer, event_to_remove, &should_reschedule) != SUCCESS) return FAILURE;
    if (should_reschedule) {
        if (oritw_reschedule_main_timer(label, async, timers, level_index) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

static inline timer_event_t *oritw_validate_min_gap_and_long_jump(
    ori_timer_wheels_t *timers,
    uint64_t delay_us,
    uint32_t level,
    bool *reschedule
) {
    ori_timer_wheel_t *timer = timers->timer[level];
    if (!timer || timer->cleanup) return NULL;
    uint64_t min_gap_us = (uint64_t)MIN_GAP_US;
    uint64_t expire;
    if (UINT64_MAX - timer->global_current_tick < delay_us)
        expire = UINT64_MAX;
    else
        expire = timer->global_current_tick + delay_us;
    if (!timer->sorting_queue_head) {
        timer_event_t *new_event = oritw_pool_alloc(timer);
        if (!new_event) {
            return NULL;
        }
        new_event->expiration_tick = expire;
        new_event->level_index = level;
        new_event->next = NULL;
        new_event->prev = NULL;
        new_event->sorting_next = NULL;
        new_event->sorting_prev = NULL;
        *reschedule = true;
        timer_event_sorting_add_tail(&timer->sorting_queue_head, &timer->sorting_queue_tail, new_event);
        return new_event;
    }
    *reschedule = false;
    uint64_t first_exp = timer->sorting_queue_head->expiration_tick;
    if (first_exp == expire) {
        return NULL;
    }
    uint64_t diff;
    if (first_exp > expire) {
        if (expire <= timer->global_current_tick) {
            return NULL;
        }
        diff = expire - timer->global_current_tick;
        if (diff < min_gap_us) {
            return NULL;
        }
        timer_event_t *new_event = oritw_pool_alloc(timer);
        if (!new_event) {
            return NULL;
        }
        new_event->expiration_tick = expire;
        new_event->level_index = level;
        new_event->next = NULL;
        new_event->prev = NULL;
        new_event->sorting_next = NULL;
        new_event->sorting_prev = NULL;
        *reschedule = true;
        timer_event_sorting_insert_before(&timer->sorting_queue_head, &timer->sorting_queue_tail, timer->sorting_queue_head, new_event);
        return new_event;
    }
    diff = expire - first_exp;
    if (diff < min_gap_us) {
        return NULL;
    }
    uint64_t exp_i;
    uint32_t i = 0;
    timer_event_t *cur = timer->sorting_queue_head;
    do {
        if (i == WHEEL_SIZE) {
            return NULL;
        }
        cur = cur->sorting_next;
        if (!cur) {
            timer_event_t *new_event = oritw_pool_alloc(timer);
            if (!new_event) {
                return NULL;
            }
            new_event->expiration_tick = expire;
            new_event->level_index = level;
            new_event->next = NULL;
            new_event->prev = NULL;
            new_event->sorting_next = NULL;
            new_event->sorting_prev = NULL;
            timer_event_sorting_add_tail(&timer->sorting_queue_head, &timer->sorting_queue_tail, new_event);
            return new_event;
        }
        exp_i = cur->expiration_tick;
        if (exp_i == expire) {
            return NULL;
        }
        if (exp_i > expire) {
            diff = exp_i - expire;
            if (diff >= min_gap_us) {
                timer_event_t *new_event = oritw_pool_alloc(timer);
                if (!new_event) {
                    return NULL;
                }
                new_event->expiration_tick = expire;
                new_event->level_index = level;
                new_event->next = NULL;
                new_event->prev = NULL;
                new_event->sorting_next = NULL;
                new_event->sorting_prev = NULL;
                timer_event_sorting_insert_before(&timer->sorting_queue_head, &timer->sorting_queue_tail, cur, new_event);
                return new_event;
            }
        }
        diff = expire - exp_i;
        if (diff < min_gap_us) {
            return NULL;
        }
        i++;
    } while (cur);
    return NULL;
}

static inline timer_event_t *oritw_calculate_level(
    ori_timer_wheels_t *timers,
    uint64_t delay_us,
    uint32_t *level_index,
    bool *reschedule
)
{
    for (uint16_t llvl=0;llvl<MAX_TIMER_LEVELS;++llvl) {
        timer_event_t *new_event = oritw_validate_min_gap_and_long_jump(timers, delay_us, llvl, reschedule);
        if (new_event) {
            *level_index = llvl;
            return new_event;
        }
    }
    *level_index = 0xffffffff;
    return NULL;
}

static inline void oritw_calculate_slot(
    ori_timer_wheel_t *timer,
    uint64_t expiration_tick,
    uint32_t *slot_index
)
{
    timer_wheel_t *level = &timer->timer_wheel;
    uint64_t abs_slot_index = expiration_tick / level->tick_factor;
    *slot_index = (uint32_t)(abs_slot_index & WHEEL_MASK);
    if (expiration_tick <= timer->global_current_tick) {
        *slot_index = level->current_index;
    }
}

static inline status_t oritw_add_event(
    const char *label,
    async_type_t *async,
    ori_timer_wheels_t *timers,
    timer_id_t *timer_id
)
{
    if (!timer_id) return FAILURE;
    timer_id->event = NULL;
    uint64_t delay_us = (uint64_t)ceil(timer_id->delay_us);
    if (delay_us == 0 && timer_id->delay_us > 0.0) {
        delay_us = 1;
    }
    uint32_t level_index;
    bool should_reschedule = false;
    timer_event_t *new_event = oritw_calculate_level(timers, delay_us, &level_index, &should_reschedule);
    if (new_event == NULL) {
        oritw_add_timer_id_queue(timers, timer_id->id, timer_id->delay_us);
        if (timers->add_event_fd == -1) {
            if (async_create_event(label, &timers->add_event_fd) != SUCCESS) return FAILURE;
            if (async_create_incoming_event(label, async, &timers->add_event_fd) != SUCCESS) return FAILURE;
        }
        uint64_t val = 1ULL;
        ssize_t w;
        do {
            w = write(timers->add_event_fd, &val, sizeof(uint64_t));
        } while (w == -1 && errno == EINTR);
        if (w == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return SUCCESS;
            }
            LOG_ERROR("%sFailed to write add_event_fd: %s", label, strerror(errno));
            return FAILURE;
        }
        if (w != sizeof(uint64_t)) {
            LOG_ERROR("%sPartial write to add_event_fd: %zd bytes", label, w);
            return FAILURE;
        }
        return SUCCESS;
    }
    new_event->timer_id = timer_id->id;
    timer_id->event = new_event;
    ori_timer_wheel_t *timer = timers->timer[level_index];
    if (!timer || timer->cleanup) return FAILURE;
    uint32_t slot_index;
    oritw_calculate_slot(timer, new_event->expiration_tick, &slot_index);
    timer_wheel_t *wheel = &timer->timer_wheel;
    timer_bucket_t *bucket = &wheel->buckets[slot_index];
    new_event->slot_index = (uint16_t)slot_index;
    timer_event_add_tail(&bucket->head, &bucket->tail, new_event); 
    if (new_event->expiration_tick < bucket->min_expiration) {
        bucket->min_expiration = new_event->expiration_tick;
        min_heap_update(&wheel->min_heap, (uint16_t)slot_index, bucket->min_expiration);
    }
    timer->next_expiration_tick = min_heap_get_min(&timer->timer_wheel.min_heap);
    if (should_reschedule) {
        uint64_t_status_t system_tick = get_monotonic_time_ns(label);
        if (system_tick.status != SUCCESS) {
            return FAILURE;
        }
        double double_system_tick = (double)system_tick.r_uint64_t / (double)1e3;
        uint64_t ull_system_tick = (uint64_t)ceil(double_system_tick);
        timer->initial_system_tick = ull_system_tick;
        if (oritw_reschedule_main_timer(label, async, timers, level_index) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

static inline status_t oritw_process_expired_level(
    ori_timer_wheel_t *timer,
    uint32_t start_index,
    uint32_t end_index
) {
    timer_wheel_t *level = &timer->timer_wheel;
    uint32_t current_slot_index = start_index;
    while (true) {
        timer_bucket_t *bucket = &level->buckets[current_slot_index];
        timer_event_t *cur = bucket->head;
        timer_event_t *remain_head = NULL;
        timer_event_t *remain_tail = NULL;
        uint64_t new_min_exp = ULLONG_MAX;
        while (cur) {
            timer_event_t *next = cur->next;
            cur->next = NULL;
            cur->prev = NULL;
            if (cur->expiration_tick <= timer->global_current_tick) {
                timer_event_sorting_remove(&timer->sorting_queue_head, &timer->sorting_queue_tail, cur);
                timer_event_add_tail(&timer->ready_queue_head, &timer->ready_queue_tail, cur);
            } else {
                timer_event_add_tail(&remain_head, &remain_tail, cur);
                cur->slot_index = (uint16_t)current_slot_index;
                if (cur->expiration_tick < new_min_exp) new_min_exp = cur->expiration_tick;
            }
            cur = next;
        }
        bucket->head = remain_head;
        bucket->tail = remain_tail;
        bucket->min_expiration = (remain_head ? new_min_exp : ULLONG_MAX);
        min_heap_update(&level->min_heap, (uint16_t)current_slot_index, bucket->min_expiration);
        if (current_slot_index == end_index) break;
        current_slot_index = (current_slot_index + 1) & WHEEL_MASK;
    }
    oritw_find_earliest_event(timer, NULL);
    return SUCCESS;
}

static inline timer_event_t *oritw_pop_ready_queue(ori_timer_wheel_t *timer) {
    timer_event_t *ev = timer_event_pop_head(&timer->ready_queue_head, &timer->ready_queue_tail);
    if (ev) {
        timer_event_sorting_remove(&timer->sorting_queue_head, &timer->sorting_queue_tail, ev);
    }
    return ev;
}

static inline status_t oritw_advance_time_and_process_expired_internal(
    const char *label,
    async_type_t *async,
    ori_timer_wheels_t *timers,
    uint32_t level,
    uint64_t ticks_to_advance
)
{
    ori_timer_wheel_t *timer = timers->timer[level];
    uint64_t remaining_ticks = ticks_to_advance;
    while (remaining_ticks > 0) {
        uint32_t level_start_index = timer->timer_wheel.current_index;
        uint64_t slots_until_wrap = WHEEL_SIZE - level_start_index;
        uint64_t chunk_advance = remaining_ticks < slots_until_wrap ? remaining_ticks : slots_until_wrap;
        if (chunk_advance == 0) break;
        uint32_t level_end_index = (level_start_index + (uint32_t)chunk_advance) & WHEEL_MASK;
        timer->timer_wheel.current_index = (uint16_t)level_end_index;
        timer->global_current_tick += chunk_advance;
        if (oritw_process_expired_level(timer, level_start_index, level_end_index) != SUCCESS) {
            return FAILURE;
        }
        remaining_ticks -= chunk_advance;
    }
    return SUCCESS;
}

static inline status_t oritw_advance_time_and_process_expired(
    const char *label,
    async_type_t *async,
    ori_timer_wheels_t *timers,
    uint32_t level,
    uint64_t ticks_to_advance
)
{
    if (ticks_to_advance == 0) return SUCCESS;
    ori_timer_wheel_t *timer = timers->timer[level];
    if (!timer || timer->cleanup) return FAILURE;
    if (oritw_advance_time_and_process_expired_internal(label, async, timers, level, ticks_to_advance) != SUCCESS) return FAILURE;
    uint64_t min_abs_expiration = min_heap_get_min(&timer->timer_wheel.min_heap);
    if (min_abs_expiration != ULLONG_MAX) {
        uint64_t_status_t system_tick = get_monotonic_time_ns(label);
        if (system_tick.status != SUCCESS) {
            return FAILURE;
        }
        double double_system_tick = (double)system_tick.r_uint64_t / (double)1e3;
        uint64_t ull_system_tick = (uint64_t)ceil(double_system_tick);
        ull_system_tick -= timer->initial_system_tick;
        if (ull_system_tick > timer->global_current_tick) {
            uint64_t tta_plus = ull_system_tick - timer->global_current_tick;
            if (oritw_advance_time_and_process_expired_internal(label, async, timers, level, tta_plus) != SUCCESS) return FAILURE;
        }
    }
    return oritw_reschedule_main_timer(label, async, timers, level);
}

static inline status_t oritw_setup(const char *label, async_type_t *async, ori_timer_wheels_t *timers) {
    if (!timers) return FAILURE_NOMEM;
    timers->add_event_fd = -1;
    timers->add_queue_head = NULL;
    timers->add_queue_tail = NULL;
    for (uint32_t llv = 0; llv < MAX_TIMER_LEVELS; ++llv) {
        timers->timer[llv] = (ori_timer_wheel_t *)calloc(1, sizeof(ori_timer_wheel_t));
        if (!timers->timer[llv]) return FAILURE_NOMEM;
        ori_timer_wheel_t *tw = timers->timer[llv];
        tw->cleanup = false;
        tw->tick_event_fd = -1;
        tw->timeout_event_fd = -1;
        tw->sorting_queue_head = NULL;
        tw->sorting_queue_tail = NULL;
        tw->ready_queue_head = NULL;
        tw->ready_queue_tail = NULL;
        tw->event_pool_head = NULL;
        tw->event_pool_tail = NULL;
        tw->initial_system_tick = 0ULL;
        tw->global_current_tick = 0;
        tw->last_delay_us = 0.0;
        tw->next_expiration_tick = ULLONG_MAX;
        timer_wheel_t *wheel = &tw->timer_wheel;
        wheel->current_index = 0;
        wheel->tick_factor = 1;
        min_heap_init(&wheel->min_heap);
        for (uint32_t s = 0; s < WHEEL_SIZE; ++s) {
            wheel->buckets[s].head = NULL;
            wheel->buckets[s].tail = NULL;
            wheel->buckets[s].min_expiration = ULLONG_MAX;
        }
    }
    return SUCCESS;
}

static inline void oritw_cleanup(const char *label, async_type_t *async, ori_timer_wheels_t *timers) {
    if (!timers) return;
    for (uint32_t llv = 0; llv < MAX_TIMER_LEVELS; ++llv) {
        ori_timer_wheel_t *tw = timers->timer[llv];
        if (!tw) continue;
        tw->cleanup = true;
        tw->initial_system_tick = 0ULL;
        timer_wheel_t *wheel = &tw->timer_wheel;
        for (uint32_t s = 0; s < WHEEL_SIZE; ++s) {
            timer_bucket_t *bucket = &wheel->buckets[s];
            bucket->head = NULL;
            bucket->tail = NULL;
            bucket->min_expiration = ULLONG_MAX;
        }
        for (uint32_t i = 0; i < wheel->min_heap.size; ++i) {
            wheel->min_heap.nodes[i].expiration_tick = ULLONG_MAX;
        }
        tw->sorting_queue_head = NULL;
        tw->sorting_queue_tail = NULL;
        tw->ready_queue_head = NULL;
        tw->ready_queue_tail = NULL;
        timer_event_cleanup(&tw->event_pool_head, &tw->event_pool_tail);
        tw->global_current_tick = 0;
        tw->next_expiration_tick = ULLONG_MAX;
        tw->last_delay_us = 0.0;
        async_delete_event(label, async, &tw->tick_event_fd);
        CLOSE_FD(&tw->tick_event_fd);
        async_delete_event(label, async, &tw->timeout_event_fd);
        CLOSE_FD(&tw->timeout_event_fd);
        free(tw);
        timers->timer[llv] = NULL;
    }
    oritw_cleanup_timer_id_queue(timers);
    async_delete_event(label, async, &timers->add_event_fd);
    CLOSE_FD(&timers->add_event_fd);
}

#endif
