#ifndef TIMER_HASHMAP_H
#define TIMER_HASHMAP_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

typedef struct timer_event_t timer_event_t; 

typedef struct hash_entry_t {
    uint64_t timer_id;
    timer_event_t *event_ptr;
    struct hash_entry_t *next;
} hash_entry_t;

typedef struct {
    hash_entry_t *buckets[TIMER_HASHMAP_SIZE];
    uint64_t count;
} timer_hash_map_t;

typedef timer_hash_map_t *hash_map_context_t; 

static inline uint64_t hash_timer_id(uint64_t timer_id) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    hash ^= (timer_id >> 32);
    hash *= 0x100000001b3ULL;
    hash ^= (timer_id & 0xFFFFFFFF);
    hash *= 0x100000001b3ULL; 
    return hash % TIMER_HASHMAP_SIZE;
}

static inline status_t hashmap_init(hash_map_context_t *ctx) {
    timer_hash_map_t *map = (timer_hash_map_t *)malloc(sizeof(timer_hash_map_t));
    if (!map) {
        return FAILURE_NOMEM;
    }
    memset(map->buckets, 0, sizeof(map->buckets));
    map->count = 0;
    *ctx = map;
    return SUCCESS;
}

static inline timer_event_t *hashmap_lookup(hash_map_context_t ctx, uint64_t timer_id) {
    timer_hash_map_t *map = (timer_hash_map_t *)ctx;
    if (!map) return NULL;
    uint64_t index = hash_timer_id(timer_id);
    hash_entry_t *current = map->buckets[index];
    while (current != NULL) {
        if (current->timer_id == timer_id) {
            return current->event_ptr;
        }
        current = current->next;
    }
    return NULL;
}

static inline status_t hashmap_insert(hash_map_context_t ctx, uint64_t timer_id, timer_event_t *event_ptr) {
    timer_hash_map_t *map = (timer_hash_map_t *)ctx;
    if (!map) return FAILURE;
    uint64_t index = hash_timer_id(timer_id);
    hash_entry_t *current = map->buckets[index];
    while (current != NULL) {
        if (current->timer_id == timer_id) {
            current->event_ptr = event_ptr;
            return SUCCESS;
        }
        current = current->next;
    }
    hash_entry_t *new_entry = (hash_entry_t *)malloc(sizeof(hash_entry_t));
    if (!new_entry) {
        return FAILURE_NOMEM;
    }
    new_entry->timer_id = timer_id;
    new_entry->event_ptr = event_ptr;
    new_entry->next = map->buckets[index];
    map->buckets[index] = new_entry;
    map->count++;
    return SUCCESS;
}

static inline status_t hashmap_remove(hash_map_context_t ctx, uint64_t timer_id) {
    timer_hash_map_t *map = (timer_hash_map_t *)ctx;
    if (!map) return FAILURE;
    uint64_t index = hash_timer_id(timer_id);
    hash_entry_t *current = map->buckets[index];
    hash_entry_t *prev = NULL;
    while (current != NULL) {
        if (current->timer_id == timer_id) {
            if (prev == NULL) {
                map->buckets[index] = current->next;
            } else {
                prev->next = current->next;
            }
            free(current);
            map->count--;
            return SUCCESS;
        }
        prev = current;
        current = current->next;
    }
    return FAILURE;
}

static inline void hashmap_cleanup(hash_map_context_t ctx) {
    timer_hash_map_t *map = (timer_hash_map_t *)ctx;
    if (!map) return;
    for (uint64_t i = 0; i < TIMER_HASHMAP_SIZE; ++i) {
        hash_entry_t *current = map->buckets[i];
        while (current != NULL) {
            hash_entry_t *next = current->next;
            free(current);
            current = next;
        }
    }
    free(map);
}

#endif
