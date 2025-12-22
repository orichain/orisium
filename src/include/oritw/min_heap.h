#ifndef ORITW_MIN_HEAP_H
#define ORITW_MIN_HEAP_H

#include <stdbool.h>
#include <stdint.h>

#if defined(__OpenBSD__)
    #include <sys/limits.h>
#else
    #include <limits.h>
#endif

#include "constants.h"

typedef struct {
    uint64_t expiration_tick;
    uint16_t bucket_index;
} min_heap_node_t;

typedef struct {
    min_heap_node_t nodes[WHEEL_SIZE];
    uint32_t size;
    uint16_t bucket_to_heap_index[WHEEL_SIZE];
} min_heap_t;

static inline void min_heap_swap(min_heap_t *heap, uint32_t i, uint32_t j) {
    heap->bucket_to_heap_index[heap->nodes[i].bucket_index] = (uint16_t)j;
    heap->bucket_to_heap_index[heap->nodes[j].bucket_index] = (uint16_t)i;
    min_heap_node_t temp = heap->nodes[i];
    heap->nodes[i] = heap->nodes[j];
    heap->nodes[j] = temp;
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
            min_heap_swap(heap, current, smallest);
            current = smallest;
        } else {
            break;
        }
    }
}

static inline void min_heapify_up(min_heap_t *heap, uint32_t i) {
    while (i != 0) {
        uint32_t parent = (i - 1) / 2;
        if (heap->nodes[parent].expiration_tick > heap->nodes[i].expiration_tick) {
            min_heap_swap(heap, i, parent);
            i = parent;
        } else {
            break;
        }
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

#endif
