#ifndef ORITLSF_H
#define ORITLSF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#ifndef ORITLSF_ALIGNMENT
#define ORITLSF_ALIGNMENT 8
#endif

#define SL_INDEX_COUNT_LOG2 4
#define SL_INDEX_COUNT (1u << SL_INDEX_COUNT_LOG2)
#define FL_INDEX_COUNT 32

#define MIN_BLOCK_PAYLOAD 16
#define MIN_BLOCK_SIZE (sizeof(block_header_t) + (MIN_BLOCK_PAYLOAD))

static inline size_t align_up(size_t x, size_t alignment) {
    return (x + (alignment - 1)) & ~(alignment - 1);
}

static inline size_t align_down(size_t x, size_t alignment) {
    return x & ~(alignment - 1);
}

static inline size_t oritlsf_align_up(size_t x) {
    return align_up(x, ORITLSF_ALIGNMENT);
}

static inline size_t oritlsf_align_down(size_t x) {
    return align_down(x, ORITLSF_ALIGNMENT);
}

typedef struct block_header_t {
    uint64_t size;
    struct block_header_t *prev_phys;
    struct block_header_t *next_free;
    struct block_header_t *prev_free;
} block_header_t;

typedef struct oritlsf_pool_t {
    uint32_t fl_bitmap;
    uint32_t sl_bitmap[FL_INDEX_COUNT];
    block_header_t *free_table[FL_INDEX_COUNT][SL_INDEX_COUNT];
    void *pool_start;
    size_t pool_size;
} oritlsf_pool_t;

static inline int fls_u64(uint64_t x) {
    return x ? (int)(64 - __builtin_clzll(x)) : 0;
}

static inline int ffs_u32(uint32_t x) {
    return x ? __builtin_ctz(x) + 1 : 0;
}

static inline void mapping_insert(size_t size, int *out_fl, int *out_sl) {
    if (size == 0) size = 1; 
    int fl = fls_u64((uint64_t)size) - 1; 
    if (fl < 0) fl = 0;
    if ((unsigned)fl >= FL_INDEX_COUNT) fl = (int)FL_INDEX_COUNT - 1;
    unsigned int shift = (unsigned)((fl > (int)SL_INDEX_COUNT_LOG2) ? (fl - SL_INDEX_COUNT_LOG2) : 0);
    unsigned int sl = (unsigned int)((size >> shift) & (SL_INDEX_COUNT - 1));
    *out_fl = fl;
    *out_sl = (int)sl;
}

static inline bool mapping_search(const oritlsf_pool_t *pool, size_t size, int *out_fl, int *out_sl) {
    int fl, sl; mapping_insert(size, &fl, &sl);
    if ((unsigned)fl >= FL_INDEX_COUNT) return false;
    uint32_t slmap = pool->sl_bitmap[fl] & (~0u << sl);
    if (slmap) { 
        *out_fl = fl; 
        *out_sl = ffs_u32(slmap) - 1; 
        return true; 
    }
    for (int f = fl + 1; f < (int)FL_INDEX_COUNT; ++f) {
        uint32_t sm = pool->sl_bitmap[f];
        if (sm) { 
            *out_fl = f; 
            *out_sl = ffs_u32(sm) - 1; 
            return true; 
        }
    }
    return false;
}

static inline bool ptr_in_pool(const oritlsf_pool_t *pool, const void *p) {
    if (!pool || !p) return false;
    uintptr_t start = (uintptr_t)pool->pool_start;
    uintptr_t end = start + pool->pool_size;
    uintptr_t v = (uintptr_t)p;
    return (v >= start) && (v < end);
}

static inline void insert_free_block(oritlsf_pool_t *pool, block_header_t *b) {
    size_t sz = (size_t)(b->size & ~1ULL);
    int fl, sl; mapping_insert(sz, &fl, &sl);
    block_header_t *head = pool->free_table[fl][sl];
    b->next_free = head; 
    b->prev_free = NULL;
    if (head) head->prev_free = b;
    pool->free_table[fl][sl] = b;
    pool->sl_bitmap[fl] |= (1u << sl);
    pool->fl_bitmap |= (1u << fl);
}

static inline void remove_free_block(oritlsf_pool_t *pool, block_header_t *b) {
    size_t sz = (size_t)(b->size & ~1ULL);
    int fl, sl; mapping_insert(sz, &fl, &sl);
    if (b->prev_free) b->prev_free->next_free = b->next_free;
    if (b->next_free) b->next_free->prev_free = b->prev_free;
    if (pool->free_table[fl][sl] == b) pool->free_table[fl][sl] = b->next_free;
    if (!pool->free_table[fl][sl]) {
        pool->sl_bitmap[fl] &= ~(1u << sl);
        if (!pool->sl_bitmap[fl]) pool->fl_bitmap &= ~(1u << fl);
    }
    b->next_free = b->prev_free = NULL;
}

static inline block_header_t *block_next_phys(const block_header_t *b) {
    return (block_header_t *)((uint8_t *)b + (size_t)(b->size & ~1ULL));
}

static inline void try_coalesce_next(oritlsf_pool_t *pool, block_header_t *b) {
    block_header_t *next = block_next_phys(b);
    uintptr_t pool_end = (uintptr_t)pool->pool_start + pool->pool_size;
    uintptr_t next_addr = (uintptr_t)next;
    if (next_addr < pool_end && ((next->size) & 1ULL)) {
        remove_free_block(pool, next);
        uint64_t newsz = (b->size & ~1ULL) + (next->size & ~1ULL);
        b->size = (uint64_t)(newsz | 1ULL);
        block_header_t *nn = block_next_phys(b);
        if ((uintptr_t)nn < pool_end) {
            nn->prev_phys = b;
        }
    }
}

static inline void split_block(oritlsf_pool_t *pool, block_header_t *b, size_t size_needed) {
    size_t cur = (size_t)(b->size & ~1ULL);
    if (cur < size_needed + MIN_BLOCK_SIZE) return; 
    block_header_t *rem = (block_header_t *)((uint8_t *)b + size_needed);
    size_t remsz = cur - size_needed;
    rem->size = (uint64_t)(remsz | 1ULL); 
    rem->prev_phys = b;
    b->size = (uint64_t)(size_needed & ~1ULL); 
    block_header_t *n = block_next_phys(rem);
    uintptr_t pool_start = (uintptr_t)pool->pool_start;
    uintptr_t pool_end = pool_start + pool->pool_size;
    if ((uintptr_t)n < pool_end) n->prev_phys = rem; 
    insert_free_block(pool, rem);
}

static inline int oritlsf_setup_pool(oritlsf_pool_t *pool, void *buf, size_t bufsz) {
    if (!pool || !buf) return -1;
    if (bufsz < MIN_BLOCK_SIZE + sizeof(block_header_t)) return -1;    
    uintptr_t raw_start = (uintptr_t)buf;
    uintptr_t raw_end = raw_start + bufsz;
    uintptr_t aligned_start = (uintptr_t)oritlsf_align_up((size_t)raw_start);
    uintptr_t aligned_end = (uintptr_t)oritlsf_align_down((size_t)(raw_end - sizeof(block_header_t)));
    if (aligned_end <= aligned_start + MIN_BLOCK_SIZE) return -1;
    size_t usable = (size_t)(aligned_end - aligned_start);
    if (usable < MIN_BLOCK_SIZE) return -1;
    memset(pool, 0, sizeof(*pool));
    pool->pool_start = (void *)aligned_start;
    pool->pool_size = usable;
    block_header_t *first = (block_header_t *)aligned_start;
    first->size = (uint64_t)(usable | 1ULL); 
    first->prev_phys = NULL;
    first->next_free = first->prev_free = NULL;
    insert_free_block(pool, first);
    block_header_t *sentinel = (block_header_t *)(aligned_start + usable);
    sentinel->size = 0; 
    sentinel->prev_phys = first;
    return 0;
}

static inline void *oritlsf_malloc(oritlsf_pool_t *pool, size_t size) {
    if (!pool || size == 0) return NULL;
    size_t req = oritlsf_align_up(size + sizeof(block_header_t));
    if (req < MIN_BLOCK_SIZE) req = MIN_BLOCK_SIZE;
    int fl, sl;
    if (!mapping_search(pool, req, &fl, &sl)) return NULL;
    block_header_t *b = pool->free_table[fl][sl];
    if (!b) return NULL;
    remove_free_block(pool, b);
    split_block(pool, b, req);
    b->size &= ~1ULL; 
    return (void *)((uint8_t *)b + sizeof(block_header_t));
}

static inline void oritlsf_free(oritlsf_pool_t *pool, void *ptr) {
    if (!pool || !ptr) return;
    block_header_t *b = (block_header_t *)((uint8_t *)ptr - sizeof(block_header_t));
    if (!ptr_in_pool(pool, b)) return;
    size_t bsize = (size_t)(b->size & ~1ULL);
    if (bsize < sizeof(block_header_t) || (bsize % ORITLSF_ALIGNMENT) != 0) return;
    b->size |= 1ULL; 
    if (b->prev_phys) {
        block_header_t *prev = b->prev_phys;
        if (ptr_in_pool(pool, prev) && ((prev->size) & 1ULL)) { 
            remove_free_block(pool, prev);
            prev->size = (uint64_t)(((prev->size & ~1ULL) + (b->size & ~1ULL)) | 1ULL);
            block_header_t *nn = block_next_phys(prev); 
            uintptr_t pool_end = (uintptr_t)pool->pool_start + pool->pool_size;
            if ((uintptr_t)nn < pool_end) {
                nn->prev_phys = prev;
            }            
            b = prev;
        }
    }
    try_coalesce_next(pool, b); 
    insert_free_block(pool, b);
}

static inline void *oritlsf_calloc(oritlsf_pool_t *pool, size_t nmemb, size_t sz) {
    if (!pool) return NULL;
    if (sz && nmemb > (SIZE_MAX / sz)) return NULL; 
    size_t total = nmemb * sz;
    void *p = oritlsf_malloc(pool, total);
    if (p) memset(p, 0, total);
    return p;
}

static inline void *oritlsf_realloc(oritlsf_pool_t *pool, void *ptr, size_t newsize) {
    if (!pool) return NULL;
    if (!ptr) return oritlsf_malloc(pool, newsize);
    if (newsize == 0) { oritlsf_free(pool, ptr); return NULL; }
    block_header_t *b = (block_header_t *)((uint8_t *)ptr - sizeof(block_header_t));
    if (!ptr_in_pool(pool, b)) return NULL;
    size_t cur = (size_t)(b->size & ~1ULL);
    size_t payload = (cur > sizeof(block_header_t)) ? (cur - sizeof(block_header_t)) : 0;
    size_t need = oritlsf_align_up(newsize + sizeof(block_header_t));
    if (need <= cur) return ptr; 
    block_header_t *next = block_next_phys(b);
    uintptr_t pool_start = (uintptr_t)pool->pool_start;
    uintptr_t pool_end = pool_start + pool->pool_size;
    if ((uintptr_t)next < pool_end && ((next->size) & 1ULL)) {
        size_t combined = (size_t)((b->size & ~1ULL) + (next->size & ~1ULL));
        if (combined >= need) {
            remove_free_block(pool, next);
            b->size = (uint64_t)(combined & ~1ULL); 
            block_header_t *nn = block_next_phys(b);
            if ((uintptr_t)nn < pool_end) {
                nn->prev_phys = b;
            }
            return ptr;
        }
    }
    void *newp = oritlsf_malloc(pool, newsize);
    if (!newp) return NULL;
    size_t tocopy = payload < newsize ? payload : newsize;
    if (tocopy) memcpy(newp, ptr, tocopy);
    oritlsf_free(pool, ptr);
    return newp;
}

static inline void *oritlsf_cleanup_pool(oritlsf_pool_t *pool) {
    if (!pool) return NULL;
    void *start = pool->pool_start;
    memset(pool, 0, sizeof(*pool));
    return start;
}

#endif
