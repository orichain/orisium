#ifndef ORITLSF_H
#define ORITLSF_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

#ifndef TLSF_DEBUG
#define TLSF_DEBUG 0
#endif
#define GUARD_MAGIC 0xDEADBEEFABADBABEULL

#define TLSF_BLOCKHEADER_PADDING_LEN 15
#define FL_INDEX_COUNT 30
#define SL_INDEX_COUNT 8
#define SL_INDEX_COUNT_LOG2 3
#define MIN_BLOCK_PAYLOAD 16
#define ALIGN_SIZE 16u

static inline size_t align_up_size(size_t x) {
    return (x + (ALIGN_SIZE - 1)) & ~(size_t)(ALIGN_SIZE - 1);
}

static inline uintptr_t align_up_ptr(uintptr_t x) {
    return (x + (ALIGN_SIZE - 1)) & ~(uintptr_t)(ALIGN_SIZE - 1);
}

static inline uintptr_t align_down_ptr(uintptr_t x) {
    return x & ~(uintptr_t)(ALIGN_SIZE - 1);
}

typedef struct block_header {
    struct block_header *prev_phys_block;
    struct block_header *next_free;
    struct block_header *prev_free;
    size_t size;
    uint8_t status : 1;
    uint8_t padding[TLSF_BLOCKHEADER_PADDING_LEN];
} block_header_t;

typedef struct tlsf_list {
    block_header_t *free_lists[FL_INDEX_COUNT][SL_INDEX_COUNT];
    size_t fl_bitmap;
    size_t sl_bitmap[FL_INDEX_COUNT];
    uint8_t *pool_start;
    uint8_t *pool_end;
} oritlsf_pool_t;

static const size_t FOOTER_SIZE = sizeof(uint64_t);
#define OVERHEAD ( (sizeof(block_header_t) + (ALIGN_SIZE - 1)) & ~(size_t)(ALIGN_SIZE - 1) )
#define MIN_BLOCK_TOTAL (OVERHEAD + MIN_BLOCK_PAYLOAD + FOOTER_SIZE)

static inline bool in_pool(const oritlsf_pool_t *a, const void *p) {
    return (p && (uint8_t*)p >= a->pool_start && (uint8_t*)p < a->pool_end);
}

static inline bool header_aligned(const void *p) {
    return (((uintptr_t)p % ALIGN_SIZE) == 0);
}

static inline int ffs_size_t(size_t x) {
#if ULONG_MAX > 0xffffffffUL
    return __builtin_ffsll((unsigned long long)x);
#else
    return __builtin_ffs((unsigned int)x);
#endif
}

static inline void get_indices(size_t size, int *fl, int *sl) {
    if (size < (size_t)MIN_BLOCK_TOTAL) size = (size_t)MIN_BLOCK_TOTAL;
    int fli;
    if (sizeof(size_t) == 8) fli = (int)(63 - __builtin_clzll(size));
    else fli = (int)(31 - __builtin_clz((unsigned)size));
    if (fli < SL_INDEX_COUNT_LOG2) fli = SL_INDEX_COUNT_LOG2;
    if (fli >= FL_INDEX_COUNT) fli = FL_INDEX_COUNT - 1;
    *fl = fli;
    size_t f_base = ((size_t)1 << fli);
    size_t rem = (size > f_base) ? (size - f_base) : 0;
    int sli = 0;
    if (fli - SL_INDEX_COUNT_LOG2 >= 0) {
        sli = (int)((rem >> (fli - SL_INDEX_COUNT_LOG2)) & (SL_INDEX_COUNT - 1));
    } else sli = 0;
    *sl = sli;
}

static inline void write_footer_guard(const oritlsf_pool_t *a, block_header_t *block) {
    if (!block) return;
    uint8_t *footer_ptr = (uint8_t*)block + block->size - FOOTER_SIZE;
    if (in_pool(a, footer_ptr) && footer_ptr + FOOTER_SIZE <= a->pool_end) {
        *(uint64_t*)footer_ptr = GUARD_MAGIC;
    }
}

static inline void link_next_phys(const oritlsf_pool_t *a, block_header_t *block) {
    if (!block) return;
    block_header_t *next = (block_header_t *)((uint8_t*)block + block->size);
    if ((uint8_t*)next < a->pool_end) {
        if (!in_pool(a, next) || !header_aligned(next)) {
            return;
        }
        next->prev_phys_block = block;
    }
}

static inline void tlsf_insert_block(oritlsf_pool_t *a, block_header_t *block) {
    if (!block) return;
    write_footer_guard(a, block);
    link_next_phys(a, block);
    int fli, sli;
    get_indices(block->size, &fli, &sli);
    block->next_free = a->free_lists[fli][sli];
    block->prev_free = NULL;
    if (a->free_lists[fli][sli]) {
        a->free_lists[fli][sli]->prev_free = block;
    }
    a->free_lists[fli][sli] = block;

    a->fl_bitmap |= ((size_t)1 << fli);
    a->sl_bitmap[fli] |= ((size_t)1 << sli);
}

static inline block_header_t *tlsf_remove_block(oritlsf_pool_t *a, block_header_t *block) {
    if (!block) return NULL;
    int fli, sli;
    get_indices(block->size, &fli, &sli);
    block_header_t **list_head = &a->free_lists[fli][sli];
    if (block->prev_free) {
        block->prev_free->next_free = block->next_free;
    } else {
        *list_head = block->next_free;
    }
    if (block->next_free) {
        block->next_free->prev_free = block->prev_free;
    }
    block->next_free = NULL;
    block->prev_free = NULL;
    if (*list_head == NULL) {
        a->sl_bitmap[fli] &= ~((size_t)1 << sli);
        if (a->sl_bitmap[fli] == 0) {
            a->fl_bitmap &= ~((size_t)1 << fli);
        }
    }
    return block;
}

static inline void tlsf_init(oritlsf_pool_t *a) {
    a->fl_bitmap = 0;
    for (int i=0;i<FL_INDEX_COUNT;++i) {
        a->sl_bitmap[i] = 0;
        for (int j=0;j<SL_INDEX_COUNT;++j) a->free_lists[i][j] = NULL;
    }
    a->pool_start = a->pool_end = NULL;
}

static inline void tlsf_add_pool(oritlsf_pool_t *a, uint8_t *buffer, size_t size) {
    uintptr_t rawp = (uintptr_t)buffer;
    uintptr_t aligned_start = align_up_ptr(rawp);
    uintptr_t aligned_end = align_down_ptr((uintptr_t)(buffer + size));
    a->pool_start = (uint8_t*)aligned_start;
    a->pool_end = (uint8_t*)aligned_end;
    memset(a->pool_start, 0, a->pool_end - a->pool_start);
    uint8_t *sentinel_addr = a->pool_end - OVERHEAD;
    block_header_t *sentinel = (block_header_t*)sentinel_addr;
    memset(sentinel, 0, sizeof(block_header_t));
    sentinel->status = 1;
    sentinel->size = OVERHEAD;
    sentinel->prev_phys_block = NULL;
    sentinel->next_free = sentinel->prev_free = NULL;
    block_header_t *initial = (block_header_t*)a->pool_start;
    memset(initial, 0, sizeof(block_header_t));
    size_t initial_size = (size_t)(sentinel_addr - (uint8_t*)initial);
    initial_size = (initial_size / ALIGN_SIZE) * ALIGN_SIZE;
    initial->size = initial_size;
    initial->status = 0;
    initial->prev_phys_block = NULL;
    initial->next_free = initial->prev_free = NULL;
    write_footer_guard(a, initial);
    sentinel->prev_phys_block = initial;
    tlsf_insert_block(a, initial);
}

static inline int oritlsf_setup_pool(oritlsf_pool_t *a, void *mem, size_t bytes) {
	tlsf_init(a);
    tlsf_add_pool(a, mem, bytes);
    return 0;
}

static inline void *oritlsf_cleanup_pool(oritlsf_pool_t *a) {
    if (!a) return NULL;
    void *s = a->pool_start;
    memset(a, 0, sizeof(*a));
    return s;
}

static inline block_header_t* find_suitable_block(oritlsf_pool_t *a, size_t required, int req_fl, int req_sl, int *out_fl, int *out_sl) {
    for (int fl = req_fl; fl < FL_INDEX_COUNT; ++fl) {
        size_t sl_bitmap = a->sl_bitmap[fl];
        if (sl_bitmap == 0) continue;
        if (fl == req_fl) sl_bitmap &= (~((size_t)0) << req_sl);
        while (sl_bitmap) {
            int sl = ffs_size_t(sl_bitmap) - 1;
            if (sl < 0) break;
            block_header_t *b = a->free_lists[fl][sl];
            while (b) {
                if (b->size >= required) {
                    *out_fl = fl; *out_sl = sl;
                    return b;
                }
                b = b->next_free;
            }
            sl_bitmap &= sl_bitmap - 1; 
        }
    }
    return NULL;
}

static inline void *oritlsf_malloc(oritlsf_pool_t *a, size_t size) {
    if (a->pool_start == NULL) return NULL;
    if (size == 0) size = 1;
    size_t payload_aligned = align_up_size(size);
    size_t required = payload_aligned + OVERHEAD + FOOTER_SIZE;
    if (required < MIN_BLOCK_TOTAL) required = MIN_BLOCK_TOTAL;
    required = align_up_size(required);
    int req_fl, req_sl;
    get_indices(required, &req_fl, &req_sl);
    size_t candidate_fl = a->fl_bitmap & (~((size_t)0) << req_fl);
    if (candidate_fl == 0) return NULL;
    int chosen_fl=-1, chosen_sl=-1;
    block_header_t *block = find_suitable_block(a, required, req_fl, req_sl, &chosen_fl, &chosen_sl);
    if (!block) return NULL;
    tlsf_remove_block(a, block);
    size_t block_size = block->size;
    if (block_size >= required + MIN_BLOCK_TOTAL) {
        uint8_t *new_addr = (uint8_t*)block + required;
        block_header_t *new_free = (block_header_t*)new_addr;
        if (in_pool(a, new_free) && ((uint8_t*)new_free + MIN_BLOCK_TOTAL <= a->pool_end)) {
            size_t new_size = block_size - required;
            if (new_size >= MIN_BLOCK_TOTAL) {
                memset(new_free, 0, sizeof(block_header_t));
                new_free->size = new_size;
                new_free->status = 0;
                new_free->prev_phys_block = block;
                new_free->next_free = new_free->prev_free = NULL;
                block_header_t *next_phys = (block_header_t *)((uint8_t*)new_free + new_free->size);
                if ((uint8_t*)next_phys < a->pool_end) {
                    next_phys->prev_phys_block = new_free;
                }
                write_footer_guard(a, new_free);
                tlsf_insert_block(a, new_free);
                block->size = required;
                link_next_phys(a, block);
            }
        }
    }
    write_footer_guard(a, block);
    block->status = 1;
    return (void *)((uint8_t*)block + OVERHEAD);
}

static inline void oritlsf_free(oritlsf_pool_t *a, void *ptr) {
    if (!ptr) return;
    if (!a->pool_start) return;
    block_header_t *block = (block_header_t *)((uint8_t*)ptr - OVERHEAD);
    block->status = 0;
    block_header_t *coalesce = block;
    size_t cur_size = block->size;
    block_header_t *prev_phys = block->prev_phys_block;
    if (prev_phys) {
        if (prev_phys->status == 0) {
            tlsf_remove_block(a, prev_phys);
            coalesce = prev_phys;
            coalesce->size += cur_size;
            cur_size = coalesce->size;
        }
    }
    block_header_t *next_phys = (block_header_t *)((uint8_t*)coalesce + cur_size);
    if ((uint8_t*)next_phys < a->pool_end) {
        if (next_phys->status == 0) {
            tlsf_remove_block(a, next_phys);
            coalesce->size += next_phys->size;
            block_header_t *next_next = (block_header_t *)((uint8_t*)coalesce + coalesce->size);
            if ((uint8_t*)next_next < a->pool_end) {
                next_next->prev_phys_block = coalesce;
            }
        }
    }
    write_footer_guard(a, coalesce);
    link_next_phys(a, coalesce);
    tlsf_insert_block(a, coalesce);
}

static inline void *oritlsf_calloc(oritlsf_pool_t *a, size_t nmemb, size_t size) {
    if (size != 0 && nmemb > SIZE_MAX / size) return NULL;
    size_t total = nmemb * size;
    void *p = oritlsf_malloc(a, total);
    if (p) memset(p, 0, total);
    return p;
}

static inline void *oritlsf_realloc(oritlsf_pool_t *a, void *ptr, size_t newsize) {
    if (ptr == NULL) return oritlsf_malloc(a, newsize);
    if (newsize == 0) {
        oritlsf_free(a, ptr);
        return NULL;
    }
    size_t payload_aligned = align_up_size(newsize);
    size_t required = payload_aligned + OVERHEAD + FOOTER_SIZE;
    if (required < MIN_BLOCK_TOTAL) required = MIN_BLOCK_TOTAL;
    required = align_up_size(required);
    block_header_t *block = (block_header_t *)((uint8_t*)ptr - OVERHEAD);
//----------------------------------------------------------------------
    if (!in_pool(a, block) || !header_aligned(block) || block->status != 1) {
        fprintf(stderr, "oritlsf_realloc: Corrupted or invalid pointer %p\n", ptr);
        abort();
    }
    uint8_t *footer_ptr = (uint8_t*)block + block->size - FOOTER_SIZE;
    if (*(const uint64_t*)footer_ptr != GUARD_MAGIC) {
        fprintf(stderr, "oritlsf_realloc: Footer guard mismatch (corruption detected) for block %p\n", (void*)block);
        abort();
    }
//----------------------------------------------------------------------
    size_t old_block_size = block->size;
    size_t old_payload = (old_block_size > OVERHEAD + FOOTER_SIZE) ? (old_block_size - OVERHEAD - FOOTER_SIZE) : 0;
    if (old_block_size >= required) {
        if (old_block_size >= required + MIN_BLOCK_TOTAL) {
            uint8_t *new_addr = (uint8_t*)block + required;
            block_header_t *new_free = (block_header_t*)new_addr;
            size_t new_size = old_block_size - required;
            memset(new_free, 0, sizeof(block_header_t));
            new_free->size = new_size;
            new_free->status = 0;
            new_free->prev_phys_block = block;
            new_free->next_free = new_free->prev_free = NULL;
            block_header_t *next_after_new = (block_header_t *)((uint8_t*)new_free + new_free->size);
            if ((uint8_t*)next_after_new < a->pool_end) {
                next_after_new->prev_phys_block = new_free;
            }
            write_footer_guard(a, new_free);
            link_next_phys(a, block);
            tlsf_insert_block(a, new_free);
            block->size = required;
        }
        write_footer_guard(a, block);
        return ptr;
    }
    block_header_t *next_phys = (block_header_t *)((uint8_t*)block + old_block_size);
    if (in_pool(a, next_phys) && header_aligned(next_phys) && next_phys->status == 0) {
        size_t combined = old_block_size + next_phys->size;
        if (combined >= required) {
            tlsf_remove_block(a, next_phys);
            block->size = combined;
            if (combined >= required + MIN_BLOCK_TOTAL) {
                uint8_t *new_addr = (uint8_t*)block + required;
                block_header_t *new_free = (block_header_t*)new_addr;
                size_t new_size = combined - required;
                memset(new_free, 0, sizeof(block_header_t));
                new_free->size = new_size;
                new_free->status = 0;
                new_free->prev_phys_block = block;
                new_free->next_free = new_free->prev_free = NULL;
                block_header_t *next_next = (block_header_t *)((uint8_t*)new_free + new_free->size);
                if ((uint8_t*)next_next < a->pool_end) {
                    next_next->prev_phys_block = new_free;
                }
                write_footer_guard(a, new_free);
                link_next_phys(a, block);
                tlsf_insert_block(a, new_free);
                block->size = required;
            } else {
                link_next_phys(a, block);
            }
            write_footer_guard(a, block);
            return ptr;
        }
    }
    void *new_ptr = oritlsf_malloc(a, newsize);
    if (!new_ptr) return NULL;
    size_t to_copy = (old_payload < newsize) ? old_payload : newsize;
    if (to_copy > 0) memcpy(new_ptr, ptr, to_copy);
    oritlsf_free(a, ptr);
    return new_ptr;
}

#if TLSF_DEBUG
#define VALIDATE_EVERY 1000
static inline void tlsf_dump_free_lists(const oritlsf_pool_t *a) {
    fprintf(stderr, "=== TLSF FREE LIST DUMP ===\n");
    fprintf(stderr, "pool_start=%p pool_end=%p fl_bitmap=0x%zx\n", 
            (void*)a->pool_start, (void*)a->pool_end, a->fl_bitmap);
    for (int f=0; f<FL_INDEX_COUNT; ++f) {
        if ((a->fl_bitmap & ((size_t)1 << f)) == 0) continue;
        fprintf(stderr, " FL %d: sl_bitmap=0x%zx\n", f, a->sl_bitmap[f]);
        for (int s=0; s<SL_INDEX_COUNT; ++s) {
            block_header_t *cur = a->free_lists[f][s];
            if (!cur) continue;
            fprintf(stderr, "  SL %d: ", s);
            while (cur) {
                if (!in_pool(a, cur) || !header_aligned(cur) || cur->size > (size_t)(a->pool_end-a->pool_start) || cur->size < MIN_BLOCK_TOTAL) {
                    fprintf(stderr, "!!! CORRUPTED BLOCK ENCOUNTERED %p (sz=%zu). ABORTING DUMP. !!!\n", (void*)cur, cur->size);
                    return;
                }
                fprintf(stderr, "[%p sz=%zu st=%u] -> ", (void*)cur, cur->size, (unsigned)cur->status);
                cur = cur->next_free;
            }
            fprintf(stderr, "NULL\n");
        }
    }
    fprintf(stderr, "=== END DUMP ===\n");
}

static inline void tlsf_validate_all(const oritlsf_pool_t *a) {
    if (!a->pool_start || !a->pool_end) {
        free(NULL);
        return;
    }
    size_t pool_sz = (size_t)(a->pool_end - a->pool_start);
    size_t max_blocks = pool_sz / MIN_BLOCK_TOTAL + 16;
    block_header_t **phy = malloc(sizeof(block_header_t*) * max_blocks);
    if (!phy) {
        fprintf(stderr, "tlsf_validate_all: malloc failed\n");
        abort();
    }
    size_t phy_count = 0;
    uint8_t *cur = a->pool_start;
    while (cur < a->pool_end) {
        if (!header_aligned(cur)) {
            fprintf(stderr, "tlsf_validate_all: header not aligned at %p\n", (void*)cur);
            abort();
        }
        block_header_t *bh = (block_header_t*)cur;
        if (!in_pool(a, bh)) {
            fprintf(stderr, "tlsf_validate_all: header out of pool at %p\n", (void*)bh);
            abort();
        }
        if (bh->size == OVERHEAD && (uint8_t*)bh + bh->size == a->pool_end) {
            phy[phy_count++] = bh;
            break;
        }
        if (bh->size < MIN_BLOCK_TOTAL || bh->size > (size_t)(a->pool_end - (uint8_t*)bh)) {
            fprintf(stderr, "tlsf_validate_all: Invalid block size at %p size=%zu\n", (void*)bh, bh->size);
            abort();
        }
        uint8_t *footer_loc = (uint8_t*)bh + bh->size - FOOTER_SIZE;
        if (!in_pool(a, footer_loc) || footer_loc + FOOTER_SIZE > a->pool_end) {
            fprintf(stderr, "tlsf_validate_all: Footer OOB at %p for block %p\n", (void*)footer_loc, (void*)bh);
            abort();
        }
        uint64_t f = *(const uint64_t*)footer_loc;
        if (f != GUARD_MAGIC) {
            fprintf(stderr, "tlsf_validate_all: Footer mismatch at %p (got 0x%016" PRIu64 " exp 0x%016" PRIu64 ")\n",
                    (void*)footer_loc, f, (uint64_t)GUARD_MAGIC);
            abort();
        }
        phy[phy_count++] = bh;
        cur += bh->size;
        if (phy_count >= max_blocks) {
            fprintf(stderr, "tlsf_validate_all: too many blocks (>%zu). abort.\n", max_blocks);
            abort();
        }
    }
    for (size_t i = 1; i < phy_count; ++i) {
        block_header_t *prev = phy[i-1];
        block_header_t *curb = phy[i];
        if (curb->prev_phys_block != prev) {
            fprintf(stderr, "tlsf_validate_all: prev_phys mismatch: block %p expects prev %p actual %p\n",
                    (void*)curb, (void*)prev, (void*)curb->prev_phys_block);
            abort();
        }
    }
    size_t computed_fl_bitmap = 0;
    size_t computed_sl_bitmap[FL_INDEX_COUNT];
    memset(computed_sl_bitmap, 0, sizeof(computed_sl_bitmap));
    char *phy_is_free = calloc(phy_count, 1);
    if (!phy_is_free) {
        fprintf(stderr, "tlsf_validate_all: calloc failed\n");
        abort();
    }
    for (int f = 0; f < FL_INDEX_COUNT; ++f) {
        for (int s = 0; s < SL_INDEX_COUNT; ++s) {
            block_header_t *node = a->free_lists[f][s];
            while (node) {
                if (!in_pool(a, node) || !header_aligned(node)) {
                    fprintf(stderr, "tlsf_validate_all: free-list node invalid pointer %p (fl=%d sl=%d)\n", (void*)node, f, s);
                    abort();
                }
                if (node->status != 0) {
                    fprintf(stderr, "tlsf_validate_all: free-list node %p status != 0\n", (void*)node);
                    abort();
                }
                if (node->size < MIN_BLOCK_TOTAL || node->size > (size_t)(a->pool_end - a->pool_start)) {
                    fprintf(stderr, "tlsf_validate_all: free-list node %p has bad size %zu\n", (void*)node, node->size);
                    abort();
                }
                size_t found_idx = (size_t)-1;
                for (size_t pi = 0; pi < phy_count; ++pi) {
                    if (phy[pi] == node) { found_idx = pi; break; }
                }
                if (found_idx == (size_t)-1) {
                    fprintf(stderr, "tlsf_validate_all: free-list node %p not found in physical scan\n", (void*)node);
                    abort();
                }
                if (phy_is_free[found_idx]) {
                    fprintf(stderr, "tlsf_validate_all: physical block %p appears multiple times in free-lists\n", (void*)node);
                    abort();
                }
                phy_is_free[found_idx] = 1;
                int comp_f, comp_s;
                get_indices(node->size, &comp_f, &comp_s);
                if (comp_f != f || comp_s != s) {
                    fprintf(stderr, "tlsf_validate_all: free-list node %p placed in wrong bucket (expected fl=%d sl=%d got fl=%d sl=%d)\n",
                            (void*)node, comp_f, comp_s, f, s);
                    abort();
                }
                computed_fl_bitmap |= ((size_t)1 << f);
                computed_sl_bitmap[f] |= ((size_t)1 << s);
                block_header_t *next = node->next_free;
                if (next && next->prev_free != node) {
                    fprintf(stderr, "tlsf_validate_all: next->prev_free mismatch for node %p (next %p)\n", (void*)node, (void*)next);
                    abort();
                }
                node = node->next_free;
            }
        }
    }
    if (computed_fl_bitmap != a->fl_bitmap) {
        fprintf(stderr, "tlsf_validate_all: fl_bitmap mismatch computed=0x%zx actual=0x%zx\n", computed_fl_bitmap, a->fl_bitmap);
        abort();
    }
    for (int f = 0; f < FL_INDEX_COUNT; ++f) {
        if (computed_sl_bitmap[f] != a->sl_bitmap[f]) {
            fprintf(stderr, "tlsf_validate_all: sl_bitmap[%d] mismatch computed=0x%zx actual=0x%zx\n", f, computed_sl_bitmap[f], a->sl_bitmap[f]);
            abort();
        }
    }
    for (size_t pi = 0; pi < phy_count; ++pi) {
        block_header_t *bh = phy[pi];
        if (bh->status == 0) {
            if (!phy_is_free[pi]) {
                fprintf(stderr, "tlsf_validate_all: physical free block %p not present in free-lists\n", (void*)bh);
                abort();
            }
        } else {
            if (phy_is_free[pi]) {
                fprintf(stderr, "tlsf_validate_all: block %p marked free but status==1\n", (void*)bh);
                abort();
            }
        }
    }
    free(phy);
    free(phy_is_free);
    fprintf(stderr, "TLSF VALIDATION SUCCESSFUL: Allocator state is consistent.\n");
}
#else
static inline void tlsf_validate_all(const oritlsf_pool_t *a) {}
#endif

#endif
