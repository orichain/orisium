#ifndef ORITW_H
#define ORITW_H

/*
   ori_timer_wheels_t
   └── timer[shard_index]  ← engine selector (bukan level!)
   └── ori_timer_wheel_t
   ├── timer_wheel_t
   │   ├── buckets[WHEEL_SIZE]
   │   ├── current_index
   │   ├── tick_factor
   │   └── min_heap (bucket → min expiration)
   ├── sorting_queue (global order constraint)
   ├── ready_queue
   ├── global_current_tick   ← logical time
   └── initial_system_tick   ← anchor ke monotonic clock
   */

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#if defined(__OpenBSD__)
#include <sys/limits.h>
#else
#include <limits.h>
#if defined(__NetBSD__)
#include <sys/common_int_limits.h>
#elif defined(__FreeBSD__)
#include <x86/_stdint.h>
#endif
#endif

#include "async.h"
#include "constants.h"
#include "log.h"
#include "types.h"
#include "utilities.h"
#include "oritw/timer_event.h"
#include "oritw/min_heap.h"
#include "oritw/timer_id.h"
#include "oritlsf.h"

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
    et_buffered_event_id_t *tick_event_fd;
    et_buffered_event_id_t *timeout_event_fd;
    timer_event_t *sorting_queue_head;
    timer_event_t *sorting_queue_tail;
    timer_event_t *ready_queue_head;
    timer_event_t *ready_queue_tail;
    uint64_t global_current_tick;
    uint64_t initial_system_tick;
    double last_delay_us;
    uint64_t next_expiration_tick;
} ori_timer_wheel_t;

typedef struct {
    et_buffered_event_id_t *add_event_fd;
    timer_id_t *add_queue_head;
    timer_id_t *add_queue_tail;
    ori_timer_wheel_t *timer[MAX_TIMER_SHARD];
} ori_timer_wheels_t;

static inline timer_id_t *oritw_id_alloc(oritlsf_pool_t *pool, ori_timer_wheels_t *tws, uint64_t id, double delay_us, timer_event_type_t event_type) {
	timer_id_t *new_id = (timer_id_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(timer_id_t));
    new_id->next = NULL;
    new_id->prev = NULL;
    new_id->delay_us = delay_us;
    new_id->event_type = event_type;
    new_id->id = id;
    new_id->event = NULL;
    return new_id;
}

static inline void oritw_id_free(oritlsf_pool_t *pool, ori_timer_wheels_t *tws, timer_id_t **pid) {
    if (!pid) return;
    timer_id_t *id = *pid;
    if (!id) {
		*pid = NULL;
		return;
	}
    if (id->id == 0) return;
    id->delay_us = 0;
    id->id = 0;
    id->event_type = TE_UNKNOWN;
    timer_id_remove(&tws->add_queue_head, &tws->add_queue_tail, id);
    oritlsf_free(pool, (void **)pid);
}

static inline void oritw_add_timer_id_queue(oritlsf_pool_t *pool, ori_timer_wheels_t *tws, uint64_t id, double delay_us, timer_event_type_t event_type) {
    timer_id_t *new_id = oritw_id_alloc(pool, tws, id, delay_us, event_type);
    if (!new_id) return;
    timer_id_add_tail(&tws->add_queue_head, &tws->add_queue_tail, new_id);
}

static inline timer_id_t *oritw_pop_timer_id_queue(ori_timer_wheels_t *tws) {
    return timer_id_pop_head(&tws->add_queue_head, &tws->add_queue_tail);
}

static inline timer_event_t *oritw_alloc(oritlsf_pool_t *pool, ori_timer_wheel_t *timer) {
    timer_event_t *event = (timer_event_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(timer_event_t));
    event->next = NULL;
    event->prev = NULL;
    event->sorting_next = NULL;
    event->sorting_prev = NULL;
    event->bucket_index = WHEEL_SIZE;
    event->shard_index = MAX_TIMER_SHARD;
    event->expiration_tick = 0;
    event->timer_id = 0;
    return event;
}

static inline void oritw_free_internal(oritlsf_pool_t *pool, ori_timer_wheel_t *timer, timer_event_t **pevent) {
    if (!pevent) return;
    timer_event_t *event = *pevent;
    if (!event) {
		*pevent = NULL;
		return;
	}
    event->expiration_tick = 0;
    event->timer_id = 0;
    event->bucket_index = WHEEL_SIZE;
    event->shard_index = MAX_TIMER_SHARD;
    timer_event_remove(&timer->ready_queue_head, &timer->ready_queue_tail, event);
    oritlsf_free(pool, (void **)pevent);
}

static inline void oritw_free(oritlsf_pool_t *pool, ori_timer_wheels_t *timers, timer_event_t **pevent) {
    if (!pevent) return;
    timer_event_t *event = *pevent;
    if (!event) {
		*pevent = NULL;
		return;
	}
    if (event->timer_id == 0 || event->bucket_index >= WHEEL_SIZE || event->shard_index >= MAX_TIMER_SHARD) {
		*pevent = NULL;
		return;
	}
    ori_timer_wheel_t *timer = timers->timer[event->shard_index];
    if (!timer) {
		*pevent = NULL;
		return;
	}
    oritw_free_internal(pool, timer, pevent);
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
        uint32_t shard_index
        )
{
    ori_timer_wheel_t *timer = timers->timer[shard_index];
    if (!timer) return FAILURE;
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
        if (timer->timeout_event_fd->event_id == -1) {
            if (async_create_event(label, &timer->timeout_event_fd->event_id, timer->timeout_event_fd->event_type) != SUCCESS) return FAILURE;
            if (async_create_inout_event(label, async, &timer->timeout_event_fd->event_id, timer->timeout_event_fd->event_type) != SUCCESS) return FAILURE;
        }
        if (async_create_timer_oneshot(label, async, &timer->tick_event_fd->event_id, delay_s, timer->tick_event_fd->event_type) != SUCCESS) {
            LOG_ERROR("%sFailed to re-arm main tick timer (delay_us=%.2f).", label, delay_us);
            return FAILURE;
        }
    } else {
        timer->last_delay_us = 0.0;
        timer->next_expiration_tick = ULLONG_MAX;
        if (timer->tick_event_fd->event_id != -1) {
            if (async_update_timer_oneshot(label, async, &timer->tick_event_fd->event_id, 0.0, timer->tick_event_fd->event_type) != SUCCESS) {
                LOG_ERROR("%sFailed to disarm main tick timer.", label);
                return FAILURE;
            }
        }
    }
    return SUCCESS;
}

static inline void oritw_remove_event_internal(oritlsf_pool_t *pool, ori_timer_wheel_t *timer, timer_event_t **pevent_to_remove, bool *should_reschedule) {
    if (!pevent_to_remove) return;
    timer_event_t *event_to_remove = *pevent_to_remove;
    if (!event_to_remove) {
		*pevent_to_remove = NULL;
		return;
	}
    uint64_t expire = event_to_remove->expiration_tick;
    timer_wheel_t *wheel = &timer->timer_wheel;
    timer_bucket_t *bucket = &wheel->buckets[event_to_remove->bucket_index];
    uint64_t current_min_exp = min_heap_get_min(&wheel->min_heap);
    *should_reschedule = (expire <= current_min_exp);
    timer_event_remove(&bucket->head, &bucket->tail, event_to_remove);
    timer_event_sorting_remove(&timer->sorting_queue_head, &timer->sorting_queue_tail, event_to_remove);
    if (bucket->head == NULL) {
        bucket->min_expiration = ULLONG_MAX;
    }
    min_heap_update(&wheel->min_heap, event_to_remove->bucket_index, bucket->min_expiration);
    event_to_remove->bucket_index = WHEEL_SIZE;
    oritw_free_internal(pool, timer, pevent_to_remove);
}

static inline void oritw_remove_event(
        const char *label,
        oritlsf_pool_t *pool,
        async_type_t *async,
        ori_timer_wheels_t *timers,
        timer_event_t **pevent_to_remove
        )
{
    if (!pevent_to_remove) return;
    timer_event_t *event_to_remove = *pevent_to_remove;
    if (!event_to_remove) {
		*pevent_to_remove = NULL;
		return;
	}
    uint32_t shard_index = event_to_remove->shard_index;
    if (shard_index >= MAX_TIMER_SHARD) {
		*pevent_to_remove = NULL;
		return;
	}
    ori_timer_wheel_t *timer = timers->timer[shard_index];
    if (!timer) {
		*pevent_to_remove = NULL;
		return;
	}
    bool should_reschedule = false;
    oritw_remove_event_internal(pool, timer, pevent_to_remove, &should_reschedule);
    if (should_reschedule) {
        oritw_reschedule_main_timer(label, async, timers, shard_index);
    }
}

static inline timer_event_t *oritw_validate_min_gap_and_long_jump(
	    oritlsf_pool_t *pool,
        ori_timer_wheels_t *timers,
        uint64_t delay_us,
        uint32_t shard_index,
        bool *reschedule,
        timer_event_type_t event_type
        ) {
    ori_timer_wheel_t *timer = timers->timer[shard_index];
    if (!timer) return NULL;
    uint64_t min_gap_us = (uint64_t)MIN_GAP_US;
    uint64_t expire;
    if (UINT64_MAX - timer->global_current_tick < delay_us)
        expire = UINT64_MAX;
    else
        expire = timer->global_current_tick + delay_us;
    if (!timer->sorting_queue_tail) {
        timer_event_t *new_event = oritw_alloc(pool, timer);
        if (!new_event) {
            return NULL;
        }
        new_event->expiration_tick = expire;
        new_event->event_type = event_type;
        new_event->shard_index = shard_index;
        new_event->next = NULL;
        new_event->prev = NULL;
        new_event->sorting_next = NULL;
        new_event->sorting_prev = NULL;
        *reschedule = true;
        timer_event_sorting_add_tail(&timer->sorting_queue_head, &timer->sorting_queue_tail, new_event);
        return new_event;
    } else {
        uint64_t exp_i = timer->sorting_queue_tail->expiration_tick;
        if (exp_i >= expire) {
            return NULL;
        }
        uint64_t diff = expire - exp_i;
        if (diff < min_gap_us) {
            return NULL;
        }
        timer_event_t *new_event = oritw_alloc(pool, timer);
        if (!new_event) {
            return NULL;
        }
        new_event->expiration_tick = expire;
        new_event->event_type = event_type;
        new_event->shard_index = shard_index;
        new_event->next = NULL;
        new_event->prev = NULL;
        new_event->sorting_next = NULL;
        new_event->sorting_prev = NULL;
        *reschedule = false;
        timer_event_sorting_add_tail(&timer->sorting_queue_head, &timer->sorting_queue_tail, new_event);
        return new_event;
    }
}

static inline timer_event_t *oritw_calculate_shard_index(
	    oritlsf_pool_t *pool,
        ori_timer_wheels_t *timers,
        uint64_t delay_us,
        uint32_t *shard_index,
        bool *reschedule,
        timer_event_type_t event_type
        )
{
    uint16_t shrd_min = 0;
    uint16_t shrd_cnt = 0;
    switch (event_type) {
        case TE_CHECKHEALTHY: {
                                  shrd_min = 0;
                                  shrd_cnt = 1;
                                  break;
                              }
        case TE_HEARTBEAT: {
                               shrd_min = 1;
                               shrd_cnt = 4;
                               break;
                           }
        case TE_GENERAL: {
                             shrd_min = 5;
                             shrd_cnt = 10;
                             break;
                         }
        default:
                         LOG_ERROR("UNKNOWN TIMER _EVENT TYPE!!!");
                         return NULL;
    }
    for (uint16_t shrd=shrd_min;shrd<(shrd_min+shrd_cnt);++shrd) {
        timer_event_t *new_event = oritw_validate_min_gap_and_long_jump(pool, timers, delay_us, shrd, reschedule, event_type);
        if (new_event) {
            *shard_index = shrd;
            return new_event;
        }
    }
    *shard_index = 0xffffffff;
    return NULL;
}

static inline void oritw_calculate_bucket(
        ori_timer_wheel_t *timer,
        uint64_t expiration_tick,
        uint16_t *bucket_index
        )
{
    timer_wheel_t *wheel = &timer->timer_wheel;
    uint64_t abs_bucket_index = expiration_tick / wheel->tick_factor;
    *bucket_index = (uint16_t)(((uint16_t)abs_bucket_index) & WHEEL_MASK);
    if (expiration_tick <= timer->global_current_tick) {
        *bucket_index = wheel->current_index;
    }
}

static inline status_t oritw_add_event(
        const char *label,
        oritlsf_pool_t *pool,
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
    uint32_t shard_index;
    bool should_reschedule = false;
    timer_event_t *new_event = oritw_calculate_shard_index(pool, timers, delay_us, &shard_index, &should_reschedule, timer_id->event_type);
    if (new_event == NULL) {
        oritw_add_timer_id_queue(pool, timers, timer_id->id, timer_id->delay_us, timer_id->event_type);
        if (timers->add_event_fd->event_id == -1) {
            if (async_create_event(label, &timers->add_event_fd->event_id, timers->add_event_fd->event_type) != SUCCESS) return FAILURE;
            if (async_create_inout_event(label, async, &timers->add_event_fd->event_id, timers->add_event_fd->event_type) != SUCCESS) return FAILURE;
        }
        et_result_t wetr = async_write_event(pool, async, timers->add_event_fd, true);
        if (!wetr.failure) {
            if (!wetr.partial) {
                oritlsf_free(pool, (void **)&timers->add_event_fd->buffer->buffer_out);
                timers->add_event_fd->buffer->out_size_tb = 0;
                timers->add_event_fd->buffer->out_size_c = 0;
            }
        }
        return wetr.status;
    }
    new_event->timer_id = timer_id->id;
    timer_id->event = new_event;
    ori_timer_wheel_t *timer = timers->timer[shard_index];
    if (!timer) return FAILURE;
    uint16_t bucket_index;
    oritw_calculate_bucket(timer, new_event->expiration_tick, &bucket_index);
    timer_wheel_t *wheel = &timer->timer_wheel;
    timer_bucket_t *bucket = &wheel->buckets[bucket_index];
    new_event->bucket_index = bucket_index;
    timer_event_add_tail(&bucket->head, &bucket->tail, new_event);
    if (new_event->expiration_tick < bucket->min_expiration) {
        bucket->min_expiration = new_event->expiration_tick;
        min_heap_update(&wheel->min_heap, bucket_index, bucket->min_expiration);
    }
    timer->next_expiration_tick = min_heap_get_min(&wheel->min_heap);
    if (should_reschedule) {
        uint64_t_status_t system_tick = get_monotonic_time_ns(label);
        if (system_tick.status != SUCCESS) {
            return FAILURE;
        }
        double double_system_tick = (double)system_tick.r_uint64_t / (double)1e3;
        uint64_t ull_system_tick = (uint64_t)ceil(double_system_tick);
        timer->initial_system_tick = ull_system_tick;
        if (oritw_reschedule_main_timer(label, async, timers, shard_index) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

static inline timer_event_t *oritw_pop_ready_queue(ori_timer_wheel_t *timer) {
    return timer_event_pop_head(&timer->ready_queue_head, &timer->ready_queue_tail);
}

static inline status_t oritw_process_expired_level(
        ori_timer_wheel_t *timer,
        uint16_t start_index,
        uint16_t end_index
        ) {
    timer_wheel_t *wheel = &timer->timer_wheel;
    uint16_t current_bucket_index = start_index;
    while (true) {
        timer_bucket_t *bucket = &wheel->buckets[current_bucket_index];
        timer_event_t *cur = bucket->head;
        uint64_t new_min_exp = ULLONG_MAX;
        while (cur) {
            timer_event_t *next = cur->next;
            timer_event_remove(&bucket->head, &bucket->tail, cur);
            if (cur->expiration_tick <= timer->global_current_tick) {
                timer_event_sorting_remove(&timer->sorting_queue_head, &timer->sorting_queue_tail, cur);
                timer_event_add_tail(&timer->ready_queue_head, &timer->ready_queue_tail, cur);
            } else {
                /* Strict total ordering is intentionally NOT enforced here */
                /*
                 * DESIGN NOTE:
                 * Timer wheel processes timers in bucket-level windows, not strict global
                 * expiration order. A timer with a later absolute expiration may be processed
                 * before an earlier one if they fall into different buckets within the same
                 * advance window.
                 *
                 * This behavior is intentional and is the core trade-off of an O(1) timer wheel:
                 * it guarantees no early execution, high throughput, and scalability to millions
                 * of timers, at the cost of strict total ordering.
                 *
                 * DO NOT "fix" this by enforcing strict ordering; doing so will break
                 * performance and defeat the timer wheel design.
                 *
                 * if (timer->sorting_queue_head != NULL) {
                 *   timer_event_t *cur_min = timer->sorting_queue_head;
                 *   while (cur_min) {
                 *       timer_event_t *cur_min_next = cur_min->next;
                 *       if (cur_min != cur) {
                 *           if (cur_min->expiration_tick <= cur->expiration_tick) {
                 * <<<<=================================================
                 * <<<<=================================================
                 *           } else {
                 *               break;
                 *           }
                 *       }
                 *       cur_min = cur_min_next;
                 *   }
                 * }
                 */
                timer_event_add_tail(&bucket->head, &bucket->tail, cur);
                cur->bucket_index = current_bucket_index;
                if (cur->expiration_tick < new_min_exp) {
                    new_min_exp = cur->expiration_tick;
                }
            }
            cur = next;
        }
        bucket->min_expiration = new_min_exp;
        min_heap_update(&wheel->min_heap, current_bucket_index, bucket->min_expiration);
        if (current_bucket_index == end_index) break;
        current_bucket_index = (current_bucket_index + 1) & WHEEL_MASK;
    }
    oritw_find_earliest_event(timer, NULL);
    return SUCCESS;
}

static inline status_t oritw_advance_time_and_process_expired_internal(
        ori_timer_wheels_t *timers,
        uint32_t shard_index,
        uint64_t ticks_to_advance
        )
{
    ori_timer_wheel_t *timer = timers->timer[shard_index];
    uint64_t remaining_ticks = ticks_to_advance;
    while (remaining_ticks > 0) {
        uint16_t level_start_index = timer->timer_wheel.current_index;
        uint64_t buckets_until_wrap = WHEEL_SIZE - level_start_index;
        uint64_t chunk_advance = remaining_ticks < buckets_until_wrap ? remaining_ticks : buckets_until_wrap;
        if (chunk_advance == 0) break;
        if (chunk_advance > 1000) chunk_advance = 1000;
        uint16_t level_end_index = (level_start_index + chunk_advance) & WHEEL_MASK;
        timer->timer_wheel.current_index = level_end_index;
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
        uint32_t shard_index,
        uint64_t ticks_to_advance
        )
{
    if (ticks_to_advance == 0) return SUCCESS;
    ori_timer_wheel_t *timer = timers->timer[shard_index];
    if (!timer) return FAILURE;
    if (oritw_advance_time_and_process_expired_internal(timers, shard_index, ticks_to_advance) != SUCCESS) return FAILURE;
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
            if (oritw_advance_time_and_process_expired_internal(timers, shard_index, tta_plus) != SUCCESS) return FAILURE;
        }
    }
    return oritw_reschedule_main_timer(label, async, timers, shard_index);
}

static inline status_t oritw_setup(const char *label, oritlsf_pool_t *pool, async_type_t *async, ori_timer_wheels_t *timers) {
    if (!timers) return FAILURE_NOMEM;
    timers->add_event_fd = (et_buffered_event_id_t *)oritlsf_calloc(__FILE__, __LINE__,
            pool,
            1,
            sizeof(et_buffered_event_id_t)
            );
    timers->add_event_fd->event_id = -1;
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
    timers->add_event_fd->event_type = EIT_USER;
#else
    timers->add_event_fd->event_type = EIT_FD;
#endif
    timers->add_event_fd->buffer = (et_buffer_t *)oritlsf_calloc(__FILE__, __LINE__,
            pool,
            1,
            sizeof(et_buffer_t)
            );
    timers->add_event_fd->buffer->read_step = 0;
    timers->add_event_fd->buffer->buffer_in = NULL;
    timers->add_event_fd->buffer->in_size_tb = 0;
    timers->add_event_fd->buffer->in_size_c = 0;
    timers->add_event_fd->buffer->buffer_out = NULL;
    timers->add_event_fd->buffer->out_size_tb = 0;
    timers->add_event_fd->buffer->out_size_c = 0;
    timers->add_queue_head = NULL;
    timers->add_queue_tail = NULL;
    for (uint32_t llv = 0; llv < MAX_TIMER_SHARD; ++llv) {
        timers->timer[llv] = (ori_timer_wheel_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ori_timer_wheel_t));
        if (!timers->timer[llv]) return FAILURE_NOMEM;
        ori_timer_wheel_t *tw = timers->timer[llv];
        tw->tick_event_fd = (et_buffered_event_id_t *)oritlsf_calloc(__FILE__, __LINE__,
                pool,
                1,
                sizeof(et_buffered_event_id_t)
                );
        tw->tick_event_fd->event_id = -1;
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
        tw->tick_event_fd->event_type = EIT_TIMER;
#else
        tw->tick_event_fd->event_type = EIT_FD;
#endif
        tw->tick_event_fd->buffer = (et_buffer_t *)oritlsf_calloc(__FILE__, __LINE__,
                pool,
                1,
                sizeof(et_buffer_t)
                );
        tw->tick_event_fd->buffer->read_step = 0;
        tw->tick_event_fd->buffer->buffer_in = NULL;
        tw->tick_event_fd->buffer->in_size_tb = 0;
        tw->tick_event_fd->buffer->in_size_c = 0;
        tw->tick_event_fd->buffer->buffer_out = NULL;
        tw->tick_event_fd->buffer->out_size_tb = 0;
        tw->tick_event_fd->buffer->out_size_c = 0;
        tw->timeout_event_fd = (et_buffered_event_id_t *)oritlsf_calloc(__FILE__, __LINE__,
                pool,
                1,
                sizeof(et_buffered_event_id_t)
                );
        tw->timeout_event_fd->event_id = -1;
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
        tw->timeout_event_fd->event_type = EIT_USER;
#else
        tw->timeout_event_fd->event_type = EIT_FD;
#endif
        tw->timeout_event_fd->buffer = (et_buffer_t *)oritlsf_calloc(__FILE__, __LINE__,
                pool,
                1,
                sizeof(et_buffer_t)
                );
        tw->timeout_event_fd->buffer->read_step = 0;
        tw->timeout_event_fd->buffer->buffer_in = NULL;
        tw->timeout_event_fd->buffer->in_size_tb = 0;
        tw->timeout_event_fd->buffer->in_size_c = 0;
        tw->timeout_event_fd->buffer->buffer_out = NULL;
        tw->timeout_event_fd->buffer->out_size_tb = 0;
        tw->timeout_event_fd->buffer->out_size_c = 0;
        tw->sorting_queue_head = NULL;
        tw->sorting_queue_tail = NULL;
        tw->ready_queue_head = NULL;
        tw->ready_queue_tail = NULL;
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

static inline void oritw_cleanup(const char *label, oritlsf_pool_t *pool, async_type_t *async, ori_timer_wheels_t *timers) {
    if (!timers) return;
    for (uint32_t llv = 0; llv < MAX_TIMER_SHARD; ++llv) {
        ori_timer_wheel_t *tw = timers->timer[llv];
        if (!tw) continue;
        tw->initial_system_tick = 0ULL;
        timer_event_sorting_remove_all(
                &tw->sorting_queue_head,
                &tw->sorting_queue_tail
                );
        timer_event_cleanup(pool, &tw->ready_queue_head, &tw->ready_queue_tail);
        timer_wheel_t *wheel = &tw->timer_wheel;
        for (uint32_t s = 0; s < WHEEL_SIZE; ++s) {
            timer_bucket_t *bucket = &wheel->buckets[s];
            timer_event_cleanup(pool, &bucket->head, &bucket->tail);
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
        tw->global_current_tick = 0;
        tw->next_expiration_tick = ULLONG_MAX;
        tw->last_delay_us = 0.0;
        async_delete_event(label, async, &tw->tick_event_fd->event_id, tw->tick_event_fd->event_type);
        CLOSE_EVENT_ID(pool, &tw->tick_event_fd);
        async_delete_event(label, async, &tw->timeout_event_fd->event_id, tw->timeout_event_fd->event_type);
        CLOSE_EVENT_ID(pool, &tw->timeout_event_fd);
        oritlsf_free(pool, (void **)&tw);
        timers->timer[llv] = NULL;
    }
    timer_id_cleanup(pool, &timers->add_queue_head, &timers->add_queue_tail);
    async_delete_event(label, async, &timers->add_event_fd->event_id, timers->add_event_fd->event_type);
    CLOSE_EVENT_ID(pool, &timers->add_event_fd);
}

#endif
