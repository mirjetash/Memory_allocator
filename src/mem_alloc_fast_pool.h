#ifndef   	_MEM_ALLOC_FAST_POOL_H_
#define   	_MEM_ALLOC_FAST_POOL_H_

#include "mem_alloc.h"
#include "mem_alloc_types.h"


/* Structure declaration for a free block in a 'fast' pool. */
typedef struct mem_fast_free_block{
    struct mem_fast_free_block *next;
} mem_fast_free_block_t;


/* Functions for the management of a fast pool */
void init_fast_pool(mem_pool_t *p, size_t size, size_t min_request_size, size_t max_request_size);
void *mem_alloc_fast_pool(mem_pool_t *pool, size_t size);
void mem_free_fast_pool(mem_pool_t *pool, void *b);
size_t mem_get_allocated_block_size_fast_pool(mem_pool_t *pool, void *addr);

#endif      /* !_MEM_ALLOC_FAST_POOL_H_ */
