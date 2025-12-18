#ifndef ORITLSF_H
#define ORITLSF_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#if defined(__NetBSD__)
    #include <sys/common_int_limits.h>
#elif defined(__FreeBSD__)
    #include <x86/_stdint.h>
#endif

#define TLSF_DEBUG

#if defined(TLSF_DEBUG)
static const size_t FOOTER_SIZE = sizeof(uint64_t);
#define GUARD_MAGIC 0xDEADBEEFABADBABEULL
#else
static const size_t FOOTER_SIZE = 0;
#endif

#define TLSF_BLOCKHEADER_PADDING_LEN 7
#define TLSF_BLOCKHEADER_DEBUGGING_LEN 48

#define FL_INDEX_COUNT 30
#define SL_INDEX_COUNT 8
#define SL_INDEX_COUNT_LOG2 3
#define MIN_BLOCK_PAYLOAD 8
#define ALIGN_SIZE 8u
#define ALIGN_SIZE_LOG2 3

#if SIZE_MAX == UINT64_MAX
#define ORITLSF_BITS 64
#elif SIZE_MAX == UINT32_MAX
#define ORITLSF_BITS 32
#else
#error "Unsupported size_t width"
#endif

#if FL_INDEX_COUNT > ORITLSF_BITS
#error "FL_INDEX_COUNT too large for size_t bitmapping"
#endif

#if SL_INDEX_COUNT > ORITLSF_BITS
#error "SL_INDEX_COUNT too large for size_t bitmapping"
#endif

static inline size_t align_up_size(size_t x) {
    return (x + (ALIGN_SIZE - 1)) & ~(size_t)(ALIGN_SIZE - 1);
}
static inline uintptr_t align_up_ptr(uintptr_t x) {
    return (x + (ALIGN_SIZE - 1)) & ~(uintptr_t)(ALIGN_SIZE - 1);
}
static inline uintptr_t align_down_ptr(uintptr_t x) {
    return x & ~(uintptr_t)(ALIGN_SIZE - 1);
}

typedef struct block_header_t {
    struct block_header_t *prev_phys_block;
    struct block_header_t *next_free;
    struct block_header_t *prev_free;
    size_t size;
    uint8_t status;
    #if defined(TLSF_DEBUG)
    uint8_t debugging[TLSF_BLOCKHEADER_DEBUGGING_LEN];
    #endif
    uint8_t padding[TLSF_BLOCKHEADER_PADDING_LEN];
} block_header_t;

#define BLOCK_HEADER_RAW_SIZE sizeof(block_header_t)
#define OVERHEAD align_up_size(BLOCK_HEADER_RAW_SIZE)
#define MIN_BLOCK_TOTAL (OVERHEAD + MIN_BLOCK_PAYLOAD + FOOTER_SIZE)

typedef struct oritlsf_pool_t {
    block_header_t *free_lists[FL_INDEX_COUNT][SL_INDEX_COUNT];
    size_t fl_bitmap;
    size_t sl_bitmap[FL_INDEX_COUNT];
    uint8_t *pool_start;
    uint8_t *pool_end;
} oritlsf_pool_t;

static inline bool in_pool(const oritlsf_pool_t *pool, const void *p) {
    if (!pool || !pool->pool_start || !pool->pool_end || !p) return false;
    return ((uint8_t*)p >= pool->pool_start) && ((uint8_t*)p < pool->pool_end);
}
static inline bool header_aligned(const void *p) {
    return (((uintptr_t)p & (ALIGN_SIZE - 1)) == 0);
}

static inline int ffs_size_t(size_t x) {
    if (x == 0) return 0;
    return __builtin_ffsll((unsigned long long)x);
}

static inline int msb_index_size_t(size_t x) {
    if (x == 0) return -1;
    return (int)(sizeof(size_t) * 8 - 1) - __builtin_clzll((unsigned long long)x);
}

static inline void get_indices(size_t size, int *out_fl, int *out_sl) {
    size = align_up_size(size);
    if (size < MIN_BLOCK_TOTAL) size = MIN_BLOCK_TOTAL;

    int msb = msb_index_size_t(size);
    if (msb < 0) msb = 0;

    if (msb < SL_INDEX_COUNT_LOG2) {
        *out_fl = 0;
        size_t s = (size >> ALIGN_SIZE_LOG2);
        int sl = (int)(s ? (s - 1) : 0);
        if (sl < 0) sl = 0;
        if (sl >= SL_INDEX_COUNT) sl = SL_INDEX_COUNT - 1;
        *out_sl = sl;
        return;
    }

    int fl = msb - SL_INDEX_COUNT_LOG2;
    if (fl >= FL_INDEX_COUNT) fl = FL_INDEX_COUNT - 1;
    *out_fl = fl;

    int shift = fl + SL_INDEX_COUNT_LOG2;
    if (shift >= 0) {
        *out_sl = (int)((size >> shift) & (SL_INDEX_COUNT - 1));
    } else {
        *out_sl = 0;
    }
}

#if defined(TLSF_DEBUG)
static inline void write_footer_guard(const oritlsf_pool_t *pool, block_header_t *block) {
    if (!pool || !block) return;
    if (block->size < OVERHEAD + FOOTER_SIZE) return;
    
    uint8_t *footer_ptr = (uint8_t*)block + block->size - FOOTER_SIZE;
    uint8_t *limit = pool->pool_end;
    if (in_pool(pool, footer_ptr) && (footer_ptr + FOOTER_SIZE) <= limit) {
        *(uint64_t*)footer_ptr = GUARD_MAGIC;
    }
}
#endif

static inline void link_next_phys(const oritlsf_pool_t *pool, block_header_t *block) {
    if (!pool || !block) return;
    if (block->size < OVERHEAD) return;
    
    uint8_t *next_addr = (uint8_t*)block + block->size;
    uint8_t *limit = pool->pool_end;

    if (next_addr > limit - OVERHEAD) return;
    
    block_header_t *next = (block_header_t*)next_addr;
    if (!in_pool(pool, next) || !header_aligned(next)) return;
    next->prev_phys_block = block;
}


static inline void init_free_block(block_header_t *block, size_t size, block_header_t *prev) {
    memset(block, 0, sizeof(block_header_t));
    block->size = size;
    block->status = 0;
    block->prev_phys_block = prev;
    block->next_free = block->prev_free = NULL;
}


static inline void tlsf_insert_block(oritlsf_pool_t *pool, block_header_t *block) {
    if (!pool || !block) return;
    block->status = 0;
    block->size = align_up_size(block->size);
    int fli, sli;
    get_indices(block->size, &fli, &sli);

    block->next_free = pool->free_lists[fli][sli];
    block->prev_free = NULL;
    if (pool->free_lists[fli][sli]) pool->free_lists[fli][sli]->prev_free = block;
    pool->free_lists[fli][sli] = block;

    pool->fl_bitmap |= ((size_t)1 << fli);
    pool->sl_bitmap[fli] |= ((size_t)1 << sli);

	#if defined(TLSF_DEBUG)
    write_footer_guard(pool, block);
    #endif
    link_next_phys(pool, block);
}

static inline block_header_t *tlsf_remove_block(oritlsf_pool_t *pool, block_header_t *block) {
    if (!pool || !block) return NULL;
    int fli, sli;
    get_indices(block->size, &fli, &sli);
    block_header_t **head = &pool->free_lists[fli][sli];

    if (block->prev_free) {
        block->prev_free->next_free = block->next_free;
    } else {
        *head = block->next_free;
    }
    if (block->next_free) block->next_free->prev_free = block->prev_free;

    block->next_free = block->prev_free = NULL;

    if (*head == NULL) {
        pool->sl_bitmap[fli] &= ~((size_t)1 << sli);
        if (pool->sl_bitmap[fli] == 0) pool->fl_bitmap &= ~((size_t)1 << fli);
    }
    return block;
}

static inline void tlsf_init(oritlsf_pool_t *pool) {
    if (!pool) return;
    pool->fl_bitmap = 0;
    for (int i = 0; i < FL_INDEX_COUNT; ++i) {
        pool->sl_bitmap[i] = 0;
        for (int j = 0; j < SL_INDEX_COUNT; ++j) pool->free_lists[i][j] = NULL;
    }
    pool->pool_start = pool->pool_end = NULL;
}

static inline int tlsf_add_pool(oritlsf_pool_t *pool, uint8_t *buffer, size_t size) {
    if (!pool || !buffer || size < MIN_BLOCK_TOTAL + OVERHEAD) return -1;
    uintptr_t raw = (uintptr_t)buffer;
    uintptr_t start = align_up_ptr(raw);
    uintptr_t end = align_down_ptr(raw + size);
    if (end <= start + MIN_BLOCK_TOTAL) return -1;

    pool->pool_start = (uint8_t*)start;
    pool->pool_end = (uint8_t*)end;

    size_t usable = (size_t)(pool->pool_end - pool->pool_start);
    memset(pool->pool_start, 0, usable);

    uint8_t *sentinel_addr = pool->pool_end - OVERHEAD;
    block_header_t *sentinel = (block_header_t*)sentinel_addr;
    
    if (!header_aligned(sentinel)) return -1; 
    
    memset(sentinel, 0, sizeof(block_header_t));
    sentinel->status = 1;
    sentinel->size = OVERHEAD;
    sentinel->prev_phys_block = NULL;
    sentinel->next_free = sentinel->prev_free = NULL;
    
    uint8_t *initial_addr = pool->pool_start;
    block_header_t *initial = (block_header_t*)initial_addr;
    memset(initial, 0, sizeof(block_header_t));
    size_t initial_size = (size_t)(sentinel_addr - (uint8_t*)initial);
    initial_size = (initial_size / ALIGN_SIZE) * ALIGN_SIZE;
    if (initial_size < MIN_BLOCK_TOTAL) return -1;
    initial->size = initial_size;
    initial->status = 0;
    initial->prev_phys_block = NULL;
    initial->next_free = initial->prev_free = NULL;

    sentinel->prev_phys_block = initial;
    #if defined(TLSF_DEBUG)
    write_footer_guard(pool, initial);
	#endif
	
    tlsf_insert_block(pool, initial);
    return 0;
}

static inline int oritlsf_setup_pool(oritlsf_pool_t *pool, void *mem, size_t bytes) {
    if (!pool || !mem || bytes == 0) return -1;
    tlsf_init(pool);
    return tlsf_add_pool(pool, (uint8_t*)mem, bytes);
}

static inline block_header_t* find_suitable_block(oritlsf_pool_t *pool, size_t required, int req_fl, int req_sl, int *out_fl, int *out_sl) {
    if (!pool) return NULL;
    for (int fl = req_fl; fl < FL_INDEX_COUNT; ++fl) {
        size_t slmap = pool->sl_bitmap[fl];
        if (slmap == 0) continue;
        size_t mask = (fl == req_fl) ? (~((size_t)0) << req_sl) : (~(size_t)0);
        size_t avail = slmap & mask;
        while (avail) {
            int sl = ffs_size_t(avail) - 1;
            if (sl < 0) break;
            block_header_t *b = pool->free_lists[fl][sl];
            while (b) {
                if (b->size >= required) {
                    if (out_fl) *out_fl = fl;
                    if (out_sl) *out_sl = sl;
                    return b;
                }
                b = b->next_free;
            }
            avail &= avail - 1;
        }
    }
    return NULL;
}

static inline void *oritlsf_malloc(const char *label, oritlsf_pool_t *pool, size_t size) {
    if (!pool || pool->pool_start == NULL) return NULL;
    if (size == 0) size = 1;
    
    size_t payload_aligned = align_up_size(size);
    size_t required_overhead = OVERHEAD + FOOTER_SIZE;

    if (payload_aligned > SIZE_MAX - required_overhead) return NULL;

    size_t required = payload_aligned + required_overhead;
    if (required < MIN_BLOCK_TOTAL) required = MIN_BLOCK_TOTAL;
    required = align_up_size(required);

    int req_fl = 0, req_sl = 0;
    get_indices(required, &req_fl, &req_sl);

    if ((pool->fl_bitmap & (~(size_t)0 << req_fl)) == 0) return NULL;

    int chosen_fl = -1, chosen_sl = -1;
    block_header_t *block = find_suitable_block(pool, required, req_fl, req_sl, &chosen_fl, &chosen_sl);
    if (!block) return NULL;

    tlsf_remove_block(pool, block);

    size_t bsize = block->size;
    if (bsize >= required + MIN_BLOCK_TOTAL) {
        uint8_t *new_addr = (uint8_t*)block + required;
        block_header_t *new_free = (block_header_t*)new_addr;
        
        uint8_t *limit = pool->pool_end;

        if (in_pool(pool, new_free) && (new_addr + MIN_BLOCK_TOTAL <= limit)) {
            size_t new_size = bsize - required;
            
            if (new_size >= MIN_BLOCK_TOTAL) {
                init_free_block(new_free, new_size, block);

                uint8_t *next_after_new_addr = (uint8_t*)new_free + new_free->size;
                if (next_after_new_addr <= limit - OVERHEAD) {
                    block_header_t *next_after_new = (block_header_t*)next_after_new_addr;
                    if (in_pool(pool, next_after_new) && header_aligned(next_after_new)) {
                        next_after_new->prev_phys_block = new_free;
                    }
                }

                block->size = required;
                #if defined(TLSF_DEBUG)
                write_footer_guard(pool, block);
                write_footer_guard(pool, new_free);
                #endif
                tlsf_insert_block(pool, new_free);
                link_next_phys(pool, block);
            }
        }
    }

    block->status = 1;
    #if defined(TLSF_DEBUG)
    snprintf((char *)block->debugging, TLSF_BLOCKHEADER_DEBUGGING_LEN, "%s", label);
    write_footer_guard(pool, block);
    #endif
    return (void*)((uint8_t*)block + OVERHEAD);
}

static inline void oritlsf_free(oritlsf_pool_t *pool, void **pptr) {
    if (!pool || !pptr) return;
    void *ptr = *pptr;
    *pptr = NULL;
    if (!ptr) return;

    block_header_t *block = (block_header_t*)((uint8_t*)ptr - OVERHEAD);
    if (!in_pool(pool, block) || !header_aligned(block)) return;

    block->status = 0;
    block_header_t *coalesce = block;
    uint8_t *limit = pool->pool_end;

    block_header_t *prev = block->prev_phys_block;
    if (prev && in_pool(pool, prev) && header_aligned(prev) && prev->status == 0) {
        if (prev->size < SIZE_MAX - coalesce->size) {
            tlsf_remove_block(pool, prev);
            prev->size = prev->size + coalesce->size;
            coalesce = prev;
            #if defined(TLSF_DEBUG)
            write_footer_guard(pool, coalesce); 
            #endif
        }
    }

    uint8_t *next_addr = (uint8_t*)coalesce + coalesce->size;
    if (next_addr <= limit - OVERHEAD) {
        block_header_t *next = (block_header_t*)next_addr;
        if (in_pool(pool, next) && header_aligned(next) && next->status == 0) {
            if (coalesce->size < SIZE_MAX - next->size) {
                tlsf_remove_block(pool, next);
                coalesce->size = coalesce->size + next->size;
                #if defined(TLSF_DEBUG)
                write_footer_guard(pool, coalesce); 
                #endif
            }
        }
    }

    uint8_t *next_next = (uint8_t*)coalesce + coalesce->size;
    if (next_next <= limit - OVERHEAD) {
        block_header_t *next_blk = (block_header_t*)next_next;
        if (in_pool(pool, next_blk) && header_aligned(next_blk)) {
            next_blk->prev_phys_block = coalesce;
        }
    }
    tlsf_insert_block(pool, coalesce);
}

static inline void *oritlsf_calloc(const char *file_name, int line_num, oritlsf_pool_t *pool, size_t nmemb, size_t size) {
    if (size != 0 && nmemb > SIZE_MAX / size) return NULL;
    char label[TLSF_BLOCKHEADER_DEBUGGING_LEN];
    snprintf(label, sizeof(label), "%s:%d", file_name, line_num);
    size_t total = nmemb * size;
    void *p = oritlsf_malloc(label, pool, total);
    if (p && total) memset(p, 0, total);
    return p;
}

static inline void *oritlsf_realloc(const char *file_name, int line_num, oritlsf_pool_t *pool, void *ptr, size_t newsize) {
    if (!pool) return NULL;
    char label[TLSF_BLOCKHEADER_DEBUGGING_LEN];
    snprintf(label, sizeof(label), "%s:%d", file_name, line_num);
    if (ptr == NULL) return oritlsf_malloc(label, pool, newsize);
    if (newsize == 0) { void *tmp = ptr; oritlsf_free(pool, &tmp); return NULL; }

    block_header_t *block = (block_header_t*)((uint8_t*)ptr - OVERHEAD);
    if (!in_pool(pool, block) || !header_aligned(block) || block->status != 1) {
        return NULL;
    }
	
	#if defined(TLSF_DEBUG)
    uint8_t *footer_ptr = (uint8_t*)block + block->size - FOOTER_SIZE;
    if (!in_pool(pool, footer_ptr) || footer_ptr + FOOTER_SIZE > pool->pool_end) return NULL;
    if (*(const uint64_t*)footer_ptr != GUARD_MAGIC) return NULL;
	#endif
	
    size_t payload_aligned = align_up_size(newsize);
    size_t required_overhead = OVERHEAD + FOOTER_SIZE;

    if (payload_aligned > SIZE_MAX - required_overhead) return NULL;

    size_t required = payload_aligned + required_overhead;
    if (required < MIN_BLOCK_TOTAL) required = MIN_BLOCK_TOTAL;
    required = align_up_size(required);

    size_t old_block_size = block->size;
    size_t old_payload = (old_block_size > OVERHEAD + FOOTER_SIZE) ? (old_block_size - OVERHEAD - FOOTER_SIZE) : 0;
    uint8_t *limit = pool->pool_end;

    if (old_block_size >= required) {
        if (old_block_size >= required + MIN_BLOCK_TOTAL) {
            uint8_t *new_addr = (uint8_t*)block + required;
            block_header_t *new_free = (block_header_t*)new_addr;
            
            if (in_pool(pool, new_free) && (new_addr + MIN_BLOCK_TOTAL <= limit)) {
                size_t new_size = old_block_size - required;

                if (new_size >= MIN_BLOCK_TOTAL) {
                    init_free_block(new_free, new_size, block);

                    uint8_t *next_after_new = (uint8_t*)new_free + new_free->size;
                    if (next_after_new <= limit - OVERHEAD) {
                        block_header_t *next_after = (block_header_t*)next_after_new;
                        if (in_pool(pool, next_after) && header_aligned(next_after)) {
                            next_after->prev_phys_block = new_free;
                        }
                    }

                    block->size = required;
                    #if defined(TLSF_DEBUG)
                    write_footer_guard(pool, block);
                    write_footer_guard(pool, new_free);
                    #endif
                    tlsf_insert_block(pool, new_free);
                    link_next_phys(pool, block);
                }
            }
        }
        #if defined(TLSF_DEBUG)
        write_footer_guard(pool, block);
        #endif
        return ptr;
    }

    uint8_t *next_addr = (uint8_t*)block + old_block_size;
    if (next_addr <= limit - OVERHEAD) {
        block_header_t *next = (block_header_t*)next_addr;
        if (in_pool(pool, next) && header_aligned(next) && next->status == 0) {
            if (old_block_size < SIZE_MAX - next->size) {
                size_t combined = old_block_size + next->size;
                if (combined >= required) {
                    tlsf_remove_block(pool, next);
                    block->size = combined;

                    if (combined >= required + MIN_BLOCK_TOTAL) {
                        uint8_t *new_addr = (uint8_t*)block + required;
                        block_header_t *new_free = (block_header_t*)new_addr;
                        size_t new_size = combined - required;
                        
                        if (new_size >= MIN_BLOCK_TOTAL) {
                            init_free_block(new_free, new_size, block);

                            uint8_t *next_next = (uint8_t*)new_free + new_free->size;
                            if (next_next <= limit - OVERHEAD) {
                                block_header_t *nn = (block_header_t*)next_next;
                                if (in_pool(pool, nn) && header_aligned(nn)) nn->prev_phys_block = new_free;
                            }

                            block->size = required;
                            #if defined(TLSF_DEBUG)
                            write_footer_guard(pool, block);
                            write_footer_guard(pool, new_free);
                            #endif
                            tlsf_insert_block(pool, new_free);
                            link_next_phys(pool, block);
                        }
                    } else {
                        link_next_phys(pool, block);
                        #if defined(TLSF_DEBUG)
                        write_footer_guard(pool, block);
                        #endif
                    }
                    return ptr;
                }
            }
        }
    }

    void *newptr = oritlsf_malloc(label, pool, newsize);
    if (!newptr) return NULL;
    size_t to_copy = (old_payload < newsize) ? old_payload : newsize;
    if (to_copy) memcpy(newptr, ptr, to_copy);
    void *tmp = ptr;
    oritlsf_free(pool, &tmp);
    return newptr;
}

#if defined(TLSF_DEBUG)
static inline size_t tlsf_check_leaks_and_report(const char *label, const oritlsf_pool_t *pool) {
    if (!pool || !pool->pool_start || pool->pool_start >= pool->pool_end) return 0;

    fprintf(stderr, "\n%s=== TLSF POOL REPORT ===\n", label);
    fprintf(stderr, "%sPool %p - %p (size=%zu)\n", label, (void*)pool->pool_start, (void*)pool->pool_end, (size_t)(pool->pool_end - pool->pool_start));

    size_t total_leaked = 0;
    size_t leaked_count = 0;
    uint8_t *cur = pool->pool_start;
    block_header_t *prev = NULL;

    while (cur + (ptrdiff_t)OVERHEAD <= pool->pool_end) {
        block_header_t *bh = (block_header_t*)cur;
        if (!in_pool(pool, bh) || !header_aligned(bh) || bh->size == 0 || cur + (ptrdiff_t)bh->size > pool->pool_end) {
            fprintf(stderr, "%sCORRUPTION at %p: invalid metadata (size=%zu). Abort scan.\n", label, (void*)bh, bh->size);
            break;
        }

        if (prev && bh->prev_phys_block != prev) {
            fprintf(stderr, "%sBROKEN prev_phys chain: block %p expects %p but has %p\n", label, (void*)bh, (void*)prev, (void*)bh->prev_phys_block);
        }
        
        bool is_sentinel = (cur == pool->pool_end - OVERHEAD) && (bh->size == OVERHEAD) && (bh->status == 1);

        if (!is_sentinel) {
            uint8_t *footer_ptr = (uint8_t*)bh + bh->size - FOOTER_SIZE;
            if (in_pool(pool, footer_ptr) && footer_ptr + FOOTER_SIZE <= pool->pool_end) {
                uint64_t f = *(uint64_t*)footer_ptr;
                if (f != GUARD_MAGIC) {
                    fprintf(stderr, "%sFOOTER CORRUPTED at %p (got %llu)\n", label, (void*)bh, (unsigned long long)f);
                }
            }
        }

        if (bh->status == 1) {
            size_t payload = (bh->size > OVERHEAD + FOOTER_SIZE) ? (bh->size - OVERHEAD - FOOTER_SIZE) : 0;
            
            if (is_sentinel) {
                fprintf(stderr, "%sSENTINEL: block=%p size=%zu (ignored)\n", label, (void*)bh, bh->size);
            } else {
                fprintf(stderr, "%sALLOC: block=%p size=%zu payload=%zu -> payload_ptr=%p debugging=%s\n", label, (void*)bh, bh->size, payload, (void*)((uint8_t*)bh + OVERHEAD), (char *)bh->debugging);
                total_leaked += bh->size;
                leaked_count++;
            }
        }

        prev = bh;
        cur += bh->size;
        if (cur > pool->pool_end) {
            fprintf(stderr, "%sCORRUPTION: Block size leads past pool end. Abort scan.\n", label);
            break;
        }
    }

    if (leaked_count) {
        fprintf(stderr, "%sTOTAL LEAKED: %zu blocks, %zu bytes\n", label, leaked_count, total_leaked);
    } else {
        fprintf(stderr, "%sNo allocations outstanding.\n", label);
    }
    fprintf(stderr, "%s=== END TLSF REPORT ===\n", label);
    return total_leaked;
}
#endif

static inline void *oritlsf_cleanup_pool(const char *label, oritlsf_pool_t *pool) {
    if (!pool) return NULL;
    #if defined(TLSF_DEBUG)
    if (pool->pool_start) tlsf_check_leaks_and_report(label, pool);
    #endif
    void *start = pool->pool_start;
    memset(pool, 0, sizeof(*pool));
    return start;
}

#if defined(TLSF_DEBUG)
static inline void tlsf_dump_free_lists(const oritlsf_pool_t *pool) {
    if (!pool) return;
    fprintf(stderr, "=== TLSF FREE LISTS DUMP ===\n");
    fprintf(stderr, "pool_start=%p pool_end=%p fl_bitmap=0x%zx\n", (void*)pool->pool_start, (void*)pool->pool_end, pool->fl_bitmap);
    for (int f = 0; f < FL_INDEX_COUNT; ++f) {
        if ((pool->fl_bitmap & ((size_t)1 << f)) == 0) continue;
        fprintf(stderr, " FL %d: sl_bitmap=0x%zx\n", f, pool->sl_bitmap[f]);
        for (int s = 0; s < SL_INDEX_COUNT; ++s) {
            block_header_t *cur = pool->free_lists[f][s];
            if (!cur) continue;
            fprintf(stderr, " SL %d: ", s);
            while (cur) {
                fprintf(stderr, "[%p sz=%zu st=%u] -> ", (void*)cur, cur->size, (unsigned)cur->status);
                cur = cur->next_free;
                if (!cur) break;
            }
            fprintf(stderr, "NULL\n");
        }
    }
    fprintf(stderr, "=== END DUMP ===\n");
}

static inline void tlsf_validate_all(const oritlsf_pool_t *pool) {
    if (!pool || !pool->pool_start || !pool->pool_end) return;
    size_t pool_sz = (size_t)(pool->pool_end - pool->pool_start);
    size_t max_blocks = pool_sz / MIN_BLOCK_TOTAL + 16;
    block_header_t **phy = malloc(sizeof(block_header_t*) * max_blocks);
    if (!phy) { fprintf(stderr, "tlsf_validate_all: malloc failed\n"); abort(); }
    size_t phy_count = 0;

    uint8_t *cur = pool->pool_start;
    while (cur < pool->pool_end) {
        if (!header_aligned(cur)) { fprintf(stderr, "tlsf_validate_all: header not aligned at %p\n", (void*)cur); abort(); }
        block_header_t *bh = (block_header_t*)cur;
        if (!in_pool(pool, bh)) { fprintf(stderr, "tlsf_validate_all: header out of pool at %p\n", (void*)bh); abort(); }
        if (bh->size == 0 || (uint8_t*)bh + bh->size > pool->pool_end) { fprintf(stderr, "tlsf_validate_all: invalid size at %p\n", (void*)bh); abort(); }
        
        bool is_sentinel = (cur == pool->pool_end - OVERHEAD) && (bh->size == OVERHEAD) && (bh->status == 1);
        if (!is_sentinel && bh->size < MIN_BLOCK_TOTAL) { fprintf(stderr, "tlsf_validate_all: size too small at %p\n", (void*)bh); abort(); }

		#if defined(TLSF_DEBUG)
        if (!is_sentinel && bh->size >= OVERHEAD + FOOTER_SIZE) {
            uint8_t *footer = (uint8_t*)bh + bh->size - FOOTER_SIZE;
            if (!in_pool(pool, footer) || footer + FOOTER_SIZE > pool->pool_end) { fprintf(stderr, "tlsf_validate_all: footer OOB for %p\n", (void*)bh); abort(); }
            uint64_t f = *(const uint64_t*)footer;
            if (f != GUARD_MAGIC) { fprintf(stderr, "tlsf_validate_all: footer mismatch at %p\n", (void*)bh); abort(); }
        }
        #endif

        phy[phy_count++] = bh;
        cur += bh->size;
        if (phy_count >= max_blocks) { fprintf(stderr, "tlsf_validate_all: too many blocks\n"); abort(); }
    }

    for (size_t i = 1; i < phy_count; ++i) {
        if (phy[i]->prev_phys_block != phy[i-1]) { fprintf(stderr, "tlsf_validate_all: prev_phys mismatch\n"); abort(); }
    }

    size_t computed_fl = 0;
    size_t computed_sl[FL_INDEX_COUNT];
    memset(computed_sl, 0, sizeof(computed_sl));
    char *phy_is_free = calloc(phy_count, 1);
    if (!phy_is_free) { fprintf(stderr, "tlsf_validate_all: calloc failed\n"); abort(); }

    for (int f = 0; f < FL_INDEX_COUNT; ++f) {
        for (int s = 0; s < SL_INDEX_COUNT; ++s) {
            block_header_t *node = pool->free_lists[f][s];
            while (node) {
                if (!in_pool(pool, node) || !header_aligned(node)) { fprintf(stderr, "tlsf_validate_all: invalid free-list node\n"); abort(); }
                if (node->status != 0) { fprintf(stderr, "tlsf_validate_all: free-list node marked used\n"); abort(); }
                
                size_t found = (size_t)-1;
                for (size_t i = 0; i < phy_count; ++i) { if (phy[i] == node) { found = i; break; } }
                if (found == (size_t)-1) { fprintf(stderr, "tlsf_validate_all: free-list node not found in physical\n"); abort(); }
                if (phy_is_free[found]) { fprintf(stderr, "tlsf_validate_all: duplicate free-list entry\n"); abort(); }
                phy_is_free[found] = 1;
                int cf, cs;
                get_indices(node->size, &cf, &cs);
                if (cf != f || cs != s) { fprintf(stderr, "tlsf_validate_all: wrong bucket for node (found %d:%d, expected %d:%d)\n", cf, cs, f, s); abort(); }
                computed_fl |= ((size_t)1 << f);
                computed_sl[f] |= ((size_t)1 << s);
                if (node->next_free && node->next_free->prev_free != node) { fprintf(stderr, "tlsf_validate_all: next->prev mismatch\n"); abort(); }
                node = node->next_free;
            }
        }
    }

    if (computed_fl != pool->fl_bitmap) { fprintf(stderr, "tlsf_validate_all: fl_bitmap mismatch (computed 0x%zx, pool 0x%zx)\n", computed_fl, pool->fl_bitmap); abort(); }
    for (int f = 0; f < FL_INDEX_COUNT; ++f) {
        if (computed_sl[f] != pool->sl_bitmap[f]) { fprintf(stderr, "tlsf_validate_all: sl_bitmap[%d] mismatch (computed 0x%zx, pool 0x%zx)\n", f, computed_sl[f], pool->sl_bitmap[f]); abort(); }
    }

    for (size_t i = 0; i < phy_count; ++i) {
        if (phy[i]->status == 0 && !phy_is_free[i]) { fprintf(stderr, "tlsf_validate_all: physical free block not in lists at %p\n", (void*)phy[i]); abort(); }
        if (phy[i]->status == 1 && phy_is_free[i]) { fprintf(stderr, "tlsf_validate_all: physical used block is in lists at %p\n", (void*)phy[i]); abort(); }
    }

    free(phy);
    free(phy_is_free);
    fprintf(stderr, "TLSF VALIDATION SUCCESSFUL\n");
}
#else
static inline void tlsf_dump_free_lists(const oritlsf_pool_t *pool) { (void)pool; }
static inline void tlsf_validate_all(const oritlsf_pool_t *pool) { (void)pool; }
#endif

#endif
