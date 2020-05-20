#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "mem_alloc_types.h"
#include "mem_alloc_standard_pool.h"
#include "my_mmap.h"
#include "mem_alloc.h"


/////////////////////////////////////////////////////////////////////////////

#ifdef STDPOOL_POLICY
    /* Get the value provided by the Makefile */
    std_pool_placement_policy_t std_pool_policy = STDPOOL_POLICY;
#else
    std_pool_placement_policy_t std_pool_policy = DEFAULT_STDPOOL_POLICY;
#endif

/////////////////////////////////////////////////////////////////////////////
static mem_standard_free_block_t *pivot; // pivot used in next fit policy

static size_t header_size = MEM_ALIGNMENT < 8 ? 8 : MEM_ALIGNMENT;

void init_standard_pool(mem_pool_t *p, size_t size, size_t min_request_size, size_t max_request_size) {
    /* TO BE IMPLEMENTED */
    mem_standard_free_block_t* heap = (mem_standard_free_block_t*) my_mmap(size);
    p->start = heap;
    uint64_t heap_payload_size = size - 2 * header_size;
    // heap header
    mem_standard_block_header_footer_t header;
    set_block_size(&header, heap_payload_size);  //remove the space for the header and footer
    set_block_free(&header);
    // heap footer
    mem_standard_block_header_footer_t *footer;
    footer = (char*)heap + heap_payload_size + header_size; // pointer to the footer
    set_block_size(footer, heap_payload_size);
    set_block_free(footer);

    mem_standard_free_block_t* free_list = heap;
    free_list->header = header;  // pass the header point to the payload
    free_list->next = NULL;
    free_list->prev = NULL;
    p->first_free = free_list;
    p->end = (char*)heap + size; // end of the heap

    pivot = p->first_free;

    printf("Heap Address: %d\n", free_list );
    printf("Heap size: %d\n", size);
    printf("Heap payload size: %d\n", heap_payload_size );
    printf("Heap start: %d\n", p->start );
    printf("Heap end: %d\n", p->end );
    printf("Policy: %d\n", std_pool_policy);
    printf("Header size: %d\n", header_size);
    printf("***********************************************\n");
}

void update_pivot(mem_standard_free_block_t* coalesced_block){
    if(coalesced_block < pivot && pivot < (char *) coalesced_block + get_block_size(&(coalesced_block->header)) + 2 * header_size)
        pivot = coalesced_block;
}

/* Given the address to be freed coaleses it if possible and return the new block*/
void *coalesce(mem_pool_t *pool, mem_standard_free_block_t *free_block){    
    size_t free_block_size = get_block_size(&(free_block->header));
    int coalesced = 0;
    if(free_block != pool->start){ //there is a previous -> free_block is not in the beginning of the heap
        mem_standard_block_header_footer_t *prev_footer = (char *)free_block - header_size;

        if(is_block_free(prev_footer)){ //previous block is free so coalesce with it
            size_t prev_block_size = get_block_size(prev_footer);
            free_block = (char *)free_block - prev_block_size - 2 * header_size;
            set_block_size(&(free_block->header), prev_block_size + 2 * header_size + free_block_size);
            set_block_free(&(free_block->header));
        }
        coalesced = 1;
    }
    if(((char *)free_block + get_block_size(&(free_block->header)) + 2 * header_size) != pool->end){ //there is a next -> free_block is not in the end of the heap
        mem_standard_block_header_footer_t* next_header = (char *)free_block + get_block_size(&(free_block->header)) + 2 * header_size;
        
        if(is_block_free(next_header)){ //next block is free so coalesce with it
            size_t next_block_size = get_block_size(next_header);     
            set_block_size(&(free_block->header), next_block_size + 2 * header_size + get_block_size(&(free_block->header)));
            set_block_free(&(free_block->header));
        }
        coalesced = 1;
    }
    if(coalesced == 1){//if coalescing happened set the info in the footer of the block
        size_t curr_block_size = get_block_size(&(free_block->header));
        mem_standard_block_header_footer_t *curr_footer = (char *)free_block + curr_block_size + header_size;
        set_block_size(curr_footer, curr_block_size);
        set_block_free(curr_footer);
        if(std_pool_policy == 2)//In Next fit policy update pivot if it is being coalesced
            update_pivot(free_block);
    }
    return free_block;
}



/*returns the block address whose previous is going to be the newly inserted block*/
void *find_address_to_insert_free_block(mem_standard_free_block_t* free_list, mem_standard_free_block_t *address){
    while (free_list < address && free_list->next != NULL){
        free_list = free_list->next;
    }
    return free_list;
}

/* Given the current pointer of the list travers the list and returns the  pointer to the first list*/
void reset_pool_first_free(mem_pool_t *pool, mem_standard_free_block_t* free_list){
    if(free_list == NULL){
        pool->first_free = NULL;
    }
    else{
        while(free_list->prev != NULL){
            free_list = free_list->prev;
        }
        pool->first_free = free_list;
    }
}

void mem_free_standard_pool(mem_pool_t *pool, void *addr) {
    size_t alloc_block_size = mem_get_allocated_block_size_standard_pool(pool, addr);
    mem_standard_free_block_t* address = addr - header_size;

    if(is_block_free(&(address->header))){//block is free
        printf("Block is already free!!!\n");
        return;//ignore call to free
    }
    
    mem_standard_free_block_t* free_list = pool->first_free;  

    set_block_free(&(address->header));
    mem_standard_block_header_footer_t *curr_footer = (char *)addr + alloc_block_size;
    set_block_size(curr_footer, alloc_block_size);
    set_block_free(curr_footer);

    if (free_list == NULL)
    {
        free_list = address;
        if(std_pool_policy == 2)
            pivot = free_list;
    }
    else if(free_list->next == NULL){ // free list is one block only
        address = coalesce(pool, address);

        // coalesced and returned one block stored in address
        if(free_list == address || free_list == (char *)address + alloc_block_size + 2 * header_size ){ 
            free_list = address;
        }
        //no coalescing happened check if you should add in the right or left side of free list
        else if (free_list < address){ // insert on the right side
            address->prev = free_list;
            free_list->next = address;
        }else{    // insert on the left side of the list
            address->next = free_list;
            free_list->prev = address;
        }
    }else{ //free list is more than 1 block
        free_list = find_address_to_insert_free_block(free_list, address);

        mem_standard_free_block_t *prev = free_list->prev;
        mem_standard_free_block_t *next = free_list->next;
        address = coalesce(pool, address);

        // coalesced with both next and prev
        if(prev != NULL && address == prev && (char *)address + get_block_size(&(address->header)) + 2 * header_size == (char *)free_list + get_block_size(&(free_list->header)) + 2 * header_size){
            mem_standard_free_block_t *prev_prev = prev->prev;
            if(prev_prev != NULL){//prev of prev of free list was not null so set it as the prev of the coalesced block
                address->prev = prev_prev;
                prev_prev->next = address;
            }else{
                address->prev = NULL;
            }
            if(next != NULL){// free list has next so set the next of coalesced block to the next of free list and prev of next to address
                address->next = next;
                next->prev = address;
            }else{
                address->next = NULL;
            }
            free_list = address;
        }
        else if (free_list == (char *)address + alloc_block_size + 2 * header_size){ //coalesced with next only            
            if (next != NULL){
                address->next = next;
                next->prev = address;
            }
            if(prev != NULL){                
                address->prev = prev;
                prev->next = address;
            }
            free_list = address;        
        }
        else if (prev == address ){  //coalesced with previous only
            mem_standard_free_block_t *prev_prev = prev->prev;
            if(prev_prev != NULL){            
                address->prev = prev_prev;
                prev_prev->next = address;
            }
            address->next = free_list;
            free_list->prev = address;
        }
        else{//no coalescing happened
            if(prev!= NULL){ // prev is not null so address is being added somewhere in the middle of the list
                prev->next = address;
                address->prev = prev;
            }
            address->next = free_list;
            free_list->prev = address;
        }
    }

    reset_pool_first_free(pool, free_list);  
    // print_free(pool);
}

void *get_first_fit(mem_standard_free_block_t* free_list, size_t size){
    while (free_list != NULL){
        size_t current_block_size = get_block_size(&(free_list->header));
        if(current_block_size >= size){  
            return free_list;
        }
        free_list = free_list->next;
    }
    return NULL;
}

void *get_next_fit(mem_standard_free_block_t* free_list, size_t size){
    mem_standard_free_block_t* last_fit = pivot;
    while (pivot != NULL){
        size_t current_block_size = get_block_size(&(pivot->header));
        if(current_block_size >= size){  
            return pivot;
        }
        pivot = pivot->next;
        if (pivot == NULL)// reached the end of the list
        {
            pivot = free_list;       
        }
        if (pivot == last_fit)//made one circle and no suitable block was found
            break;
    }
    return NULL;
}

void *mem_alloc_standard_pool(mem_pool_t *pool, size_t size) {
    /* TO BE IMPLEMENTED */
    size_t modulo = size % MEM_ALIGNMENT;
    if(modulo != 0){
        size = size - modulo + MEM_ALIGNMENT;
    }
    mem_standard_free_block_t* fit;
    if(std_pool_policy == 1)
        fit = get_first_fit(pool->first_free, size);
    else
        fit = get_next_fit(pool->first_free, size);
    if(fit != NULL){   // found a free block to allocate 
        mem_standard_used_block_t* allocated = fit;
        size_t current_block_size = get_block_size(&(fit->header));
        
        if(current_block_size - size < 2 * header_size + 1){  // not split if remaining block would not have at least 1 byte to use as payload
            if(fit->next == NULL && fit->prev == NULL){
                fit = NULL;
            }
            else if (fit->next == NULL){
                fit = fit->prev; 
                fit->next = NULL;
            }
            else if (fit->prev == NULL){
                fit = fit->next;
                fit->prev = NULL;
            }
            else{ // if allocating between two other blocks in the list
                mem_standard_free_block_t* next = fit->next;
                mem_standard_free_block_t* prev = fit->prev;
                prev->next = next;
                next->prev = prev;
            }
            mem_standard_block_header_footer_t *used_footer;
            used_footer = (char*)allocated + size + header_size;
            set_block_size(used_footer, size);
            set_block_used(used_footer);

            set_block_size(&(allocated->header), size);
            set_block_used(&(allocated->header));

            reset_pool_first_free(pool, fit); 
            if(std_pool_policy == 2){
                if(fit != NULL && fit->next!=NULL){
                    pivot = fit->next;
                }else{
                    pivot = pool->first_free;
                }
            }
        }
        else if (current_block_size > size)
        {
            // allocated block header
            mem_standard_block_header_footer_t used_header;
            set_block_size(&used_header, size);
            set_block_used(&used_header);
            // allocated block footer
            mem_standard_block_header_footer_t *used_footer;
            used_footer = (char*)allocated + size + header_size;
            set_block_size(used_footer, size);
            set_block_used(used_footer);

            allocated->header = used_header;

            // free part of the block
            mem_standard_free_block_t* temporary = fit;
            fit = (char *) fit + size + 2 * header_size; // update free_list pointer 

            mem_standard_block_header_footer_t new_header;
            set_block_size(&new_header, current_block_size - size - 2 * header_size);
            set_block_free(&new_header);
            fit->header = new_header;

            mem_standard_block_header_footer_t *new_footer;
            new_footer = (char *)allocated + current_block_size + header_size;
            set_block_size(new_footer, current_block_size - size - 2 * header_size);
            set_block_free(new_footer);
            
            if(temporary->prev != NULL){
                mem_standard_free_block_t* prev = temporary->prev;
                prev->next = fit;
                fit->prev = prev;
            }
            if(temporary->next != NULL){
                mem_standard_free_block_t* next = temporary->next;
                next->prev = fit;
                fit->next = temporary->next;
            }
            if(std_pool_policy == 2)
                pivot = fit;
            reset_pool_first_free(pool, fit);
        }         

        return (char *) allocated + header_size;
    }  
    return NULL;
}


size_t mem_get_allocated_block_size_standard_pool(mem_pool_t *pool, void *addr) {
    /* TO BE IMPLEMENTED */
    mem_standard_used_block_t* address = addr;
    address = (char *) address - header_size;
    size_t alloc_size = get_block_size(&(address->header));
    return alloc_size;
}


