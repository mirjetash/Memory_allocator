#include <assert.h>
#include <stdio.h>

#include "mem_alloc_fast_pool.h"
#include "my_mmap.h"
#include "mem_alloc.h"


void init_fast_pool(mem_pool_t *p, size_t size, size_t min_request_size, size_t max_request_size) {
    /* TO BE IMPLEMENTED */
    mem_fast_free_block_t* address = (mem_fast_free_block_t*) my_mmap(size);
    
    p->start = address; 
    p->first_free = address;
    int block_numbers = size/max_request_size;
    
    for(int i = 0; i < block_numbers-1; i++){
        address->next = (char*) address + max_request_size;
        address = address->next;
    }
    address->next = NULL;
    p->end = (char *) address + max_request_size;
    p->first_free = p->start;  
    mem_fast_free_block_t* free_list = p->first_free; 
}


void *mem_alloc_fast_pool(mem_pool_t *pool, size_t size) {
    /* TO BE IMPLEMENTED */
    mem_fast_free_block_t* free_list = pool->first_free;
    if (free_list != NULL)
    {
        mem_fast_free_block_t* allocated_block = free_list;        
        pool->first_free = free_list->next;
        allocated_block->next = NULL;
        return allocated_block;
    }
    return NULL;
}

void mem_free_fast_pool(mem_pool_t *pool, void *b) {
    /* TO BE IMPLEMENTED */
    mem_fast_free_block_t* new_free_block = (mem_fast_free_block_t*) b;
    new_free_block->next = pool->first_free;
    pool->first_free = new_free_block;
}

size_t mem_get_allocated_block_size_fast_pool(mem_pool_t *pool, void *addr) {
    size_t res;
    res = pool->max_request_size;
    return res;
}
