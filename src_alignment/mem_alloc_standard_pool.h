#ifndef   	_MEM_ALLOC_STANDARD_POOL_H_
#define   	_MEM_ALLOC_STANDARD_POOL_H_

#include <stdint.h>

#include "mem_alloc.h"
#include "mem_alloc_types.h"


/////////////////////////////////////////////////////////////////////////////

/* Placement policy to use for the standard pool allocator */
typedef enum {FIRST_FIT = 1, NEXT_FIT = 2} std_pool_placement_policy_t;

#define DEFAULT_STDPOOL_POLICY FIRST_FIT

/////////////////////////////////////////////////////////////////////////////

/* Structure declaration for the header or footer of a standard block */
typedef struct mem_standard_block_headerfooter{
    uint64_t flag_and_size; // bit 63: boolean (0 = free); bits 62-0: payload size
} mem_standard_block_header_footer_t;

/* Structure declaration for the start of a standard free block */
typedef struct mem_standard_free_block{
    mem_standard_block_header_footer_t header;
    struct mem_standard_free_block *prev;
    struct mem_standard_free_block *next;
} mem_standard_free_block_t;

/* Structure declaration for the start of a standard used block */
typedef struct mem_standard_used_block{
    mem_standard_block_header_footer_t header;
} mem_standard_used_block_t;

/////////////////////////////////////////////////////////////////////////////

/* Functions for the management of a standard pool */
void init_standard_pool(mem_pool_t *p, size_t size, size_t min_request_size, size_t max_request_size);
void *mem_alloc_standard_pool(mem_pool_t *pool, size_t size);
void mem_free_standard_pool(mem_pool_t *pool, void *addr);
size_t mem_get_allocated_block_size_standard_pool(mem_pool_t *pool, void *addr);

/////////////////////////////////////////////////////////////////////////////

/* Functions for managing the contents of a header or footer */

/* Returns 1 if the block is used, or 0 if the block is free */
int is_block_used(mem_standard_block_header_footer_t *m);

/* Returns 1 the if block is free, or 0 if the block is used */
int is_block_free (mem_standard_block_header_footer_t *m);

/* Modifies a block header (or footer) to mark it as used */
void set_block_used(mem_standard_block_header_footer_t *m);

/* Modifies a block header (or footer) to mark it as free */
void set_block_free(mem_standard_block_header_footer_t *m);

/* Returns the size of a block (as stored in the header/footer) */
size_t get_block_size(mem_standard_block_header_footer_t *m);

/* Modifies a block header (or footer) to update the size of the block */
void set_block_size(mem_standard_block_header_footer_t *m, size_t size);

/////////////////////////////////////////////////////////////////////////////

#endif      /* !_MEM_ALLOC_STANDARD_POOL_H_ */
