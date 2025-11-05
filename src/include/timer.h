#ifndef TIMER_H
#define TIMER_H

#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <inttypes.h>
#include <errno.h>
 
#include "types.h"
#include "timer_hashmap.h"

typedef struct timer_event_t {
    struct timer_event_t *next;
    uint64_t expiration_tick;
    uint64_t timer_id;
    struct timer_event_t **prev_next_ptr; 
    uint8_t level_index;
    uint16_t slot_index; 
} timer_event_t;

typedef struct {
    timer_event_t *head;
    timer_event_t *tail;
} timer_bucket_t;

typedef struct {
    timer_bucket_t buckets[WHEEL_SIZE];
    uint16_t current_index;
    uint64_t tick_factor;
    uint64_t current_tick_count;
} timer_wheel_level_t;

typedef struct {
    timer_wheel_level_t levels[MAX_TIMER_LEVELS];
    int tick_event_fd;
    int add_event_fd;
    int cancel_event_fd;
    int timeout_event_fd;
    hash_map_context_t hash_map_ctx;
    timer_event_t *new_event_queue_head;
    timer_event_t *new_event_queue_tail;
    timer_event_t *ready_queue_head;
    timer_event_t *ready_queue_tail;
    uint64_t global_current_tick;
    double last_delay_ms;
    uint64_t next_expiration_tick;
} hierarchical_timer_wheel_t;

static inline void free_linked_list_internal(timer_event_t *head) {
    timer_event_t *cur = head;
    while (cur != NULL) {
        timer_event_t *n = cur->next;
        free(cur);
        cur = n;
    }
}

static inline status_t htw_add_event(hierarchical_timer_wheel_t *timer, uint64_t timer_id, uint64_t delay_ms) {
    timer_event_t *new_event = malloc(sizeof(timer_event_t));
    if (!new_event) {
        return FAILURE_NOMEM;
    }   
    new_event->expiration_tick = timer->global_current_tick + delay_ms;
    new_event->timer_id = timer_id;
    new_event->next = NULL;
    new_event->prev_next_ptr = NULL; 
    new_event->level_index = (uint8_t)MAX_TIMER_LEVELS; 
    new_event->slot_index = WHEEL_SIZE; 
    if (hashmap_insert(timer->hash_map_ctx, timer_id, new_event) != SUCCESS) {
        free(new_event);
        return FAILURE;
    }
    if (timer->new_event_queue_head == NULL) {
        timer->new_event_queue_head = new_event;
        timer->new_event_queue_tail = new_event;
        new_event->prev_next_ptr = &timer->new_event_queue_head; 
    } else {
        new_event->prev_next_ptr = &timer->new_event_queue_tail->next; 
        timer->new_event_queue_tail->next = new_event;
        timer->new_event_queue_tail = new_event;
    }
    uint64_t val = 1ULL;
    if (write(timer->add_event_fd, &val, sizeof(uint64_t)) != sizeof(uint64_t)) {
        hashmap_remove(timer->hash_map_ctx, timer_id);
        free(new_event); 
        return FAILURE;
    }
    return SUCCESS;
}

static inline status_t htw_cancel_event(hierarchical_timer_wheel_t *timer, uint64_t timer_id) {
    timer_event_t *event_to_cancel = hashmap_lookup(timer->hash_map_ctx, timer_id);
    if (!event_to_cancel) {
        return FAILURE_NOTFOUND;
    }
    if (!event_to_cancel->prev_next_ptr) {
        LOG_ERROR("Internal error: Timer event found without prev_next_ptr.");
        return FAILURE;
    }
    timer_event_t **p_next = event_to_cancel->prev_next_ptr; 
    *p_next = event_to_cancel->next; 
    if (event_to_cancel->next != NULL) {
        event_to_cancel->next->prev_next_ptr = p_next;
    } else {
        uint8_t level = event_to_cancel->level_index;        
        if (level < MAX_TIMER_LEVELS) { 
            timer_bucket_t *bucket = &timer->levels[level].buckets[event_to_cancel->slot_index];
            if (bucket->tail == event_to_cancel) {
                bucket->tail = NULL;
            }
        } else if (level == MAX_TIMER_LEVELS) {
            if (timer->new_event_queue_tail == event_to_cancel) {
                timer->new_event_queue_tail = NULL;
            }
        }
    }
    hashmap_remove(timer->hash_map_ctx, timer_id);
    if (event_to_cancel->expiration_tick == timer->next_expiration_tick) {
        uint64_t val = 1ULL;
        if (write(timer->cancel_event_fd, &val, sizeof(uint64_t)) != sizeof(uint64_t)) {
            LOG_ERROR("Failed to signal cancel event to worker.");
            free(event_to_cancel); 
            return FAILURE;
        }
    }
    free(event_to_cancel); 
    return SUCCESS;
}

static inline void htw_calculate_level_and_slot(
    hierarchical_timer_wheel_t *timer,
    uint64_t expiration_tick,
    uint32_t *level_index,
    uint32_t *slot_index
)
{
    if (expiration_tick <= timer->global_current_tick) {
        *level_index = 0;
        *slot_index = timer->levels[0].current_index; 
        return;
    }
    uint64_t delta_tick = expiration_tick - timer->global_current_tick;
    uint64_t current_tick_factor = timer->levels[0].tick_factor;
    for (uint32_t level = 0; level < MAX_TIMER_LEVELS; ++level) {
        uint64_t wheel_span = current_tick_factor * WHEEL_SIZE;
        if (delta_tick < wheel_span) {
            *level_index = level;
            uint64_t ticks_at_level = delta_tick / current_tick_factor;
            *slot_index = (timer->levels[level].current_index + (uint32_t)ticks_at_level) % WHEEL_SIZE;
            return;
        }
        if (level < MAX_TIMER_LEVELS - 1) {
            current_tick_factor *= WHEEL_SIZE;
        }
    }
    *level_index = (uint32_t)MAX_TIMER_LEVELS - 1;
    *slot_index = WHEEL_SIZE - 1;
}

static inline status_t htw_move_queue_to_wheel(hierarchical_timer_wheel_t *timer) {
    timer_event_t *temp_head = timer->new_event_queue_head;
    timer->new_event_queue_head = NULL;
    timer->new_event_queue_tail = NULL;
    if (temp_head == NULL) {
        return SUCCESS;
    }
    timer_event_t *current = temp_head;
    timer_event_t *next_node = NULL;
    while (current != NULL) {
        next_node = current->next;
        uint32_t level_index;
        uint32_t slot_index;
        htw_calculate_level_and_slot(
            timer,
            current->expiration_tick,
            &level_index,
            &slot_index
        );
        timer_bucket_t *bucket = &timer->levels[level_index].buckets[slot_index];
        current->level_index = (uint8_t)level_index;
        current->slot_index = (uint16_t)slot_index;
        current->next = bucket->head;        
        if (bucket->head != NULL) {
            bucket->head->prev_next_ptr = &current->next; 
        } else {
            bucket->tail = current;
        }
        current->prev_next_ptr = &bucket->head; 
        bucket->head = current;
        if (current->expiration_tick < timer->next_expiration_tick) {
            timer->next_expiration_tick = current->expiration_tick;
        }
        current = next_node;
    }
    return SUCCESS;
}

static inline uint64_t htw_find_earliest_event(hierarchical_timer_wheel_t *timer) {
    uint64_t min_abs_expiration = ULLONG_MAX;
    for (uint32_t l = 0; l < MAX_TIMER_LEVELS; ++l) {
        timer_wheel_level_t *level = &timer->levels[l];
        for (uint32_t s = 0; s < WHEEL_SIZE; ++s) {
            timer_bucket_t *bucket = &level->buckets[s];
            if (bucket->head != NULL) {
                uint64_t exp_tick = bucket->head->expiration_tick;
                if (exp_tick > timer->global_current_tick && exp_tick < min_abs_expiration) {
                    min_abs_expiration = exp_tick;
                }
            }
        }
    }
    if (min_abs_expiration == ULLONG_MAX) {
        timer->next_expiration_tick = ULLONG_MAX;
        return 0ULL;
    }
    timer->next_expiration_tick = min_abs_expiration;
    return min_abs_expiration;
}

static inline status_t htw_cascading_events(hierarchical_timer_wheel_t *timer, uint32_t source_level_index, uint32_t target_slot_index) {
    if (source_level_index >= MAX_TIMER_LEVELS) return SUCCESS; 
    timer_bucket_t *source_bucket = &timer->levels[source_level_index].buckets[target_slot_index];
    timer_event_t *current = source_bucket->head;
    timer_event_t *next_node = NULL;
    source_bucket->head = NULL;
    source_bucket->tail = NULL;
    while (current != NULL) {
        next_node = current->next;
        uint32_t new_level_index;
        uint32_t new_slot_index;
        htw_calculate_level_and_slot(
            timer,
            current->expiration_tick,
            &new_level_index,
            &new_slot_index
        );
        timer_bucket_t *target_bucket = &timer->levels[new_level_index].buckets[new_slot_index];
        current->level_index = (uint8_t)new_level_index;
        current->slot_index = (uint16_t)new_slot_index;
        current->next = target_bucket->head;
        if (target_bucket->head != NULL) {
            target_bucket->head->prev_next_ptr = &current->next;
        } else {
            target_bucket->tail = current;
        }
        current->prev_next_ptr = &target_bucket->head; 
        target_bucket->head = current;
        if (current->expiration_tick < timer->next_expiration_tick) {
            timer->next_expiration_tick = current->expiration_tick;
        }
        current = next_node;
    }
    return SUCCESS;
}

static inline status_t htw_process_expired_l0(hierarchical_timer_wheel_t *timer, uint32_t start_index, uint32_t end_index) {
    uint32_t current_slot_index = start_index;
    while (true) {
        timer_bucket_t *bucket = &timer->levels[0].buckets[current_slot_index];
        timer_event_t *cur = bucket->head;
        timer_event_t *next_event = NULL;
        bucket->head = NULL;
        bucket->tail = NULL;
        while (cur) {
            next_event = cur->next;
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
                hashmap_remove(timer->hash_map_ctx, cur->timer_id);
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
                cur->level_index = 0;
                cur->slot_index = (uint16_t)current_slot_index;
            }
            cur = next_event;
        }
        if (current_slot_index == end_index) break;
        current_slot_index = (current_slot_index + 1) % WHEEL_SIZE;
    }
    timer->next_expiration_tick = ULLONG_MAX;
    htw_find_earliest_event(timer);
    return SUCCESS;
}

static inline status_t htw_advance_time_and_process_expired(hierarchical_timer_wheel_t *timer, uint64_t ticks_to_advance) {
    if (ticks_to_advance == 0) return SUCCESS;    
    uint64_t remaining_ticks = ticks_to_advance;
    while (remaining_ticks > 0) {
        uint32_t l0_start_index = timer->levels[0].current_index;
        uint64_t slots_until_wrap = WHEEL_SIZE - l0_start_index;
        uint64_t chunk_advance = remaining_ticks < slots_until_wrap ? remaining_ticks : slots_until_wrap;
        if (chunk_advance == 0) break;
        uint32_t l0_end_index = (l0_start_index + (uint32_t)chunk_advance) % WHEEL_SIZE;
        timer->levels[0].current_index = (uint16_t)l0_end_index;
        timer->global_current_tick += chunk_advance;
        if (l0_end_index == 0) {
            uint64_t carry = 1; 
            for (uint32_t level = 1; level < MAX_TIMER_LEVELS && carry > 0; ++level) {
                timer_wheel_level_t *lvl = &timer->levels[level];
                uint64_t sum = (uint64_t)lvl->current_index + carry;
                uint32_t new_index = (uint32_t)(sum % WHEEL_SIZE);
                carry = sum / WHEEL_SIZE;
                lvl->current_index = (uint16_t)new_index;
                if (htw_cascading_events(timer, level, new_index) != SUCCESS) {
                     return FAILURE;
                }
            }
        }
        if (htw_process_expired_l0(timer, l0_start_index, l0_end_index) != SUCCESS) {
            return FAILURE;
        }
        remaining_ticks -= chunk_advance;
    }
    return SUCCESS;
}

static inline status_t htw_reschedule_main_timer(const char *label, async_type_t *async, hierarchical_timer_wheel_t *timer) {
    uint64_t next_expiration_tick = timer->next_expiration_tick;
    if (next_expiration_tick == ULLONG_MAX || next_expiration_tick <= timer->global_current_tick) {
        next_expiration_tick = htw_find_earliest_event(timer);
    }
    if (next_expiration_tick > timer->global_current_tick) { 
        uint64_t delay_tick = next_expiration_tick - timer->global_current_tick;
        double delay_ms = (double)delay_tick;
        double delay_s = delay_ms / 1000.0; 
        timer->last_delay_ms = delay_ms;
        if (create_timer_oneshot(label, async, &timer->tick_event_fd, delay_s) != SUCCESS) {
            LOG_ERROR("%sFailed to re-arm main tick timer.", label);
            return FAILURE;
        }
    } else {
        timer->last_delay_ms = 0.0;
        timer->next_expiration_tick = ULLONG_MAX;
        if (timer->tick_event_fd != -1) {
            if (update_timer_oneshot(label, &timer->tick_event_fd, (double)0.0) != SUCCESS) {
                LOG_ERROR("%sFailed to disarm main tick timer.", label);
                return FAILURE;
            }
        }
    }
    return SUCCESS;
}

static inline status_t htw_setup(const char *label, async_type_t *async, hierarchical_timer_wheel_t *timer) {
    timer->add_event_fd = -1;
    timer->cancel_event_fd = -1;
    timer->tick_event_fd = -1;
    timer->timeout_event_fd = -1;
    timer->new_event_queue_head = NULL;
    timer->new_event_queue_tail = NULL;
    timer->ready_queue_head = NULL;
    timer->ready_queue_tail = NULL;
    timer->global_current_tick = 0;
    timer->last_delay_ms = 0.0;
    timer->next_expiration_tick = ULLONG_MAX;
    if (hashmap_init(&timer->hash_map_ctx) != SUCCESS) return FAILURE;
    uint64_t current_factor = 1;
    for (uint32_t l = 0; l < MAX_TIMER_LEVELS; ++l) {
        timer_wheel_level_t *level = &timer->levels[l];
        memset(level->buckets, 0, sizeof(timer_bucket_t) * WHEEL_SIZE);
        level->current_index = 0;
        level->tick_factor = current_factor;
        level->current_tick_count = 0;
        if (l < MAX_TIMER_LEVELS - 1) {
            current_factor *= WHEEL_SIZE;
        }
    }
    if (async_create_event(label, &timer->add_event_fd) != SUCCESS) return FAILURE;
    if (async_create_incoming_event(label, async, &timer->add_event_fd) != SUCCESS) {
        return FAILURE;
    }
    if (async_create_event(label, &timer->cancel_event_fd) != SUCCESS) return FAILURE;
    if (async_create_incoming_event(label, async, &timer->cancel_event_fd) != SUCCESS) {
        return FAILURE;
    }
    if (async_create_event(label, &timer->timeout_event_fd) != SUCCESS) return FAILURE;
    if (async_create_incoming_event(label, async, &timer->timeout_event_fd) != SUCCESS) {
        return FAILURE;
    }
    return SUCCESS;
}

static inline void htw_cleanup(const char *label, async_type_t *async, hierarchical_timer_wheel_t *timer) {
    hashmap_cleanup(timer->hash_map_ctx);   
    for (uint32_t l = 0; l < MAX_TIMER_LEVELS; ++l) {
        timer_wheel_level_t *level = &timer->levels[l];
        for (uint32_t s = 0; s < WHEEL_SIZE; ++s) {
            timer_bucket_t *bucket = &level->buckets[s];
            free_linked_list_internal(bucket->head);
            bucket->head = NULL;
            bucket->tail = NULL;
        }
    }
    free_linked_list_internal(timer->new_event_queue_head);
    timer->new_event_queue_head = NULL;
    timer->new_event_queue_tail = NULL;
    free_linked_list_internal(timer->ready_queue_head);
    timer->ready_queue_head = NULL;
    timer->ready_queue_tail = NULL;
    timer->global_current_tick = 0;
    timer->next_expiration_tick = ULLONG_MAX;
    async_delete_event(label, async, &timer->tick_event_fd);
    CLOSE_FD(&timer->tick_event_fd);
    async_delete_event(label, async, &timer->add_event_fd);
    CLOSE_FD(&timer->add_event_fd);
    async_delete_event(label, async, &timer->cancel_event_fd);
    CLOSE_FD(&timer->cancel_event_fd);
    async_delete_event(label, async, &timer->timeout_event_fd);
    CLOSE_FD(&timer->timeout_event_fd);
}

#endif
