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
#include <math.h>

#include "types.h"

typedef struct {
    uint64_t expiration_tick;
    uint16_t bucket_index;
} min_heap_node_t;

typedef struct {
    min_heap_node_t nodes[WHEEL_SIZE];
    uint32_t size;
    uint16_t bucket_to_heap_index[WHEEL_SIZE];
} min_heap_t;

typedef struct {
    uint64_t expiration_tick;
    uint8_t level_index;
} global_min_heap_node_t;

typedef struct {
    global_min_heap_node_t nodes[MAX_TIMER_LEVELS];
    uint32_t size;
    uint8_t level_to_heap_index[MAX_TIMER_LEVELS];
} global_min_heap_t;


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

static inline void global_min_heap_swap(global_min_heap_node_t *a, global_min_heap_node_t *b, global_min_heap_t *heap) {
    heap->level_to_heap_index[a->level_index] = (uint8_t)(b - heap->nodes);
    heap->level_to_heap_index[b->level_index] = (uint8_t)(a - heap->nodes);
    global_min_heap_node_t temp = *a;
    *a = *b;
    *b = temp;
}

static inline void global_min_heapify_down(global_min_heap_t *heap, uint32_t i) {
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
        global_min_heap_swap(&heap->nodes[i], &heap->nodes[smallest], heap);
        global_min_heapify_down(heap, smallest);
    }
}

static inline void global_min_heapify_up(global_min_heap_t *heap, uint32_t i) {
    while (i != 0 && heap->nodes[(i - 1) / 2].expiration_tick > heap->nodes[i].expiration_tick) {
        global_min_heap_swap(&heap->nodes[i], &heap->nodes[(i - 1) / 2], heap);
        i = (i - 1) / 2;
    }
}

static inline void global_min_heap_init(global_min_heap_t *heap) {
    heap->size = MAX_TIMER_LEVELS;
    for (uint32_t i = 0; i < MAX_TIMER_LEVELS; ++i) {
        heap->nodes[i].expiration_tick = ULLONG_MAX;
        heap->nodes[i].level_index = (uint8_t)i;
        heap->level_to_heap_index[i] = (uint8_t)i;
    }
}

static inline void global_min_heap_update(global_min_heap_t *heap, uint8_t level_index, uint64_t new_expiration) {
    uint32_t i = heap->level_to_heap_index[level_index];
    if (i >= heap->size) return; 
    uint64_t old_expiration = heap->nodes[i].expiration_tick;
    heap->nodes[i].expiration_tick = new_expiration;
    if (new_expiration < old_expiration) {
        global_min_heapify_up(heap, i);
    } else if (new_expiration > old_expiration) {
        global_min_heapify_down(heap, i);
    }
}

static inline uint64_t global_min_heap_get_min(global_min_heap_t *heap) {
    return heap->nodes[0].expiration_tick;
}

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
    uint64_t min_expiration; 
} timer_bucket_t;

typedef struct {
    timer_bucket_t buckets[WHEEL_SIZE];
    uint16_t current_index;
    uint64_t tick_factor;
    uint64_t current_tick_count;
    min_heap_t min_heap;
} timer_wheel_level_t;

typedef struct {
    timer_wheel_level_t levels[MAX_TIMER_LEVELS];
    global_min_heap_t global_min_heap;
    int tick_event_fd;
    int add_event_fd;
    int timeout_event_fd;
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

static inline status_t htw_add_event(hierarchical_timer_wheel_t *timer, uint64_t timer_id, double double_delay_ms) {
    uint64_t delay_ms = (uint64_t)ceil(double_delay_ms);
    if (delay_ms == 0 && double_delay_ms > 0.0) {
        delay_ms = 1;
    }
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
        free(new_event);
        return FAILURE;
    }
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
            uint64_t abs_slot_index = expiration_tick / current_tick_factor;
            *slot_index = (uint32_t)(abs_slot_index % WHEEL_SIZE);
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
        timer_wheel_level_t *level = &timer->levels[level_index];
        timer_bucket_t *bucket = &level->buckets[slot_index];
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
        if (current->expiration_tick < bucket->min_expiration) {
            bucket->min_expiration = current->expiration_tick;
            min_heap_update(&level->min_heap, (uint16_t)slot_index, bucket->min_expiration);
            if (bucket->min_expiration < global_min_heap_get_min(&timer->global_min_heap)) {
                global_min_heap_update(&timer->global_min_heap, (uint8_t)level_index, bucket->min_expiration);
            }
        }
        current = next_node;
    }
    return SUCCESS;
}

static inline uint64_t htw_find_earliest_event(hierarchical_timer_wheel_t *timer) {
    uint64_t min_abs_expiration = global_min_heap_get_min(&timer->global_min_heap);
    if (min_abs_expiration == ULLONG_MAX || min_abs_expiration <= timer->global_current_tick) {
        timer->next_expiration_tick = ULLONG_MAX;
        return 0ULL;
    }
    timer->next_expiration_tick = min_abs_expiration;
    return min_abs_expiration;
}

static inline status_t htw_cascading_events(hierarchical_timer_wheel_t *timer, uint32_t source_level_index, uint32_t target_slot_index) {
    if (source_level_index >= MAX_TIMER_LEVELS) return SUCCESS;
    timer_wheel_level_t *source_level = &timer->levels[source_level_index];
    timer_bucket_t *source_bucket = &source_level->buckets[target_slot_index];
    if (source_bucket->head == NULL) return SUCCESS;
    timer_event_t *current = source_bucket->head;
    timer_event_t *next_node = NULL;
    source_bucket->head = NULL;
    source_bucket->tail = NULL;
    source_bucket->min_expiration = ULLONG_MAX;
    min_heap_update(&source_level->min_heap, (uint16_t)target_slot_index, ULLONG_MAX);
    global_min_heap_update(&timer->global_min_heap, (uint8_t)source_level_index, min_heap_get_min(&source_level->min_heap));
    while (current != NULL) {
        next_node = current->next;
        if (current->expiration_tick <= timer->global_current_tick) {
            current->next = NULL;
            if (timer->ready_queue_tail) {
                current->prev_next_ptr = &timer->ready_queue_tail->next;
                timer->ready_queue_tail->next = current;
                timer->ready_queue_tail = current;
            } else {
                timer->ready_queue_head = current;
                timer->ready_queue_tail = current;
                current->prev_next_ptr = &timer->ready_queue_head;
            }
        } else {
            uint32_t new_level_index;
            uint32_t new_slot_index;
            htw_calculate_level_and_slot(
                timer,
                current->expiration_tick,
                &new_level_index,
                &new_slot_index
            );
            timer_wheel_level_t *target_level = &timer->levels[new_level_index];
            timer_bucket_t *target_bucket = &target_level->buckets[new_slot_index];
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
            if (current->expiration_tick < target_bucket->min_expiration) {
                target_bucket->min_expiration = current->expiration_tick;
                min_heap_update(&target_level->min_heap, (uint16_t)new_slot_index, target_bucket->min_expiration);
                if (target_bucket->min_expiration < global_min_heap_get_min(&timer->global_min_heap)) {
                    global_min_heap_update(&timer->global_min_heap, (uint8_t)new_level_index, target_bucket->min_expiration);
                }
            }
        }
        current = next_node;
    }
    return SUCCESS;
}

static inline status_t htw_process_expired_l0(hierarchical_timer_wheel_t *timer, uint32_t start_index, uint32_t end_index) {
    uint32_t current_slot_index = start_index;
    timer_wheel_level_t *l0 = &timer->levels[0];
    while (true) {
        timer_bucket_t *bucket = &l0->buckets[current_slot_index];
        timer_event_t *cur = bucket->head;
        timer_event_t *next_event = NULL;
        bucket->head = NULL;
        bucket->tail = NULL;
        uint64_t new_min_exp = ULLONG_MAX;
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
                if (cur->expiration_tick < new_min_exp) {
                    new_min_exp = cur->expiration_tick;
                }
            }
            cur = next_event;
        }
        bucket->min_expiration = new_min_exp;
        min_heap_update(&l0->min_heap, (uint16_t)current_slot_index, new_min_exp);
        if (current_slot_index == end_index) break;
        current_slot_index = (current_slot_index + 1) % WHEEL_SIZE;
    }
    global_min_heap_update(&timer->global_min_heap, 0, min_heap_get_min(&l0->min_heap));
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
                timer_bucket_t *bucket_to_cascade = &timer->levels[level].buckets[new_index];
                if (bucket_to_cascade->head != NULL) {
                    if (htw_cascading_events(timer, level, new_index) != SUCCESS) {
                        return FAILURE;
                    }
                } else {
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
        double delay_s = delay_ms / (double)1e3;
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
    timer->tick_event_fd = -1;
    timer->timeout_event_fd = -1;
    timer->new_event_queue_head = NULL;
    timer->new_event_queue_tail = NULL;
    timer->ready_queue_head = NULL;
    timer->ready_queue_tail = NULL;
    timer->global_current_tick = 0;
    timer->last_delay_ms = 0.0;
    timer->next_expiration_tick = ULLONG_MAX;
    global_min_heap_init(&timer->global_min_heap);
    uint64_t current_factor = 1;
    for (uint32_t l = 0; l < MAX_TIMER_LEVELS; ++l) {
        timer_wheel_level_t *level = &timer->levels[l];
        memset(level->buckets, 0, sizeof(timer_bucket_t) * WHEEL_SIZE);
        level->current_index = 0;
        level->tick_factor = current_factor;
        level->current_tick_count = 0;
        min_heap_init(&level->min_heap);
        for (uint32_t s = 0; s < WHEEL_SIZE; ++s) {
            level->buckets[s].min_expiration = ULLONG_MAX;
        }
        global_min_heap_update(&timer->global_min_heap, (uint8_t)l, ULLONG_MAX);
        if (l < MAX_TIMER_LEVELS - 1) {
            current_factor *= WHEEL_SIZE;
        }
    }
    if (async_create_event(label, &timer->add_event_fd) != SUCCESS) return FAILURE;
    if (async_create_incoming_event(label, async, &timer->add_event_fd) != SUCCESS) {
        return FAILURE;
    }
    if (async_create_event(label, &timer->timeout_event_fd) != SUCCESS) return FAILURE;
    if (async_create_incoming_event(label, async, &timer->timeout_event_fd) != SUCCESS) {
        return FAILURE;
    }
    return SUCCESS;
}

static inline void htw_cleanup(const char *label, async_type_t *async, hierarchical_timer_wheel_t *timer) {
    for (uint32_t l = 0; l < MAX_TIMER_LEVELS; ++l) {
        timer_wheel_level_t *level = &timer->levels[l];
        for (uint32_t s = 0; s < WHEEL_SIZE; ++s) {
            timer_bucket_t *bucket = &level->buckets[s];
            free_linked_list_internal(bucket->head);
            bucket->head = NULL;
            bucket->tail = NULL;
            bucket->min_expiration = ULLONG_MAX;
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
    async_delete_event(label, async, &timer->timeout_event_fd);
    CLOSE_FD(&timer->timeout_event_fd);
}

#endif
