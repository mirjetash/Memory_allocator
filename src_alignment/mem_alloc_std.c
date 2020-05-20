/* #define _GNU_SOURCE */


#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "mem_alloc.h"
#include "mem_alloc_types.h"


static int __mem_alloc_init_flag=0;


void *malloc(size_t size){
  void *res;
  if(!__mem_alloc_init_flag){
      __mem_alloc_init_flag = 1;
      init_bootstrap_buffers();
      memory_init();
      __mem_alloc_init_completed = 1;
  } else if (!__mem_alloc_init_completed) {
      res = handle_bootstrap_alloc(size);
      return res;
  }  
  res = memory_alloc(size);
  return res;
}

void free(void *p){
    if (is_bootstrap_buffer(p)) {
        handle_bootstrap_free(p);
        return;
    }
    if (p == NULL) return;
    memory_free(p);
}

void *calloc(size_t nmemb, size_t size)
{
    void *res;
    
    if(!__mem_alloc_init_flag){
        __mem_alloc_init_flag = 1;
        init_bootstrap_buffers();
        memory_init();
        __mem_alloc_init_completed = 1;
    } else if (!__mem_alloc_init_completed) {
        return handle_bootstrap_alloc(size);
    }
    res = memory_alloc(size*nmemb);
    if (res != NULL) {
        explicit_bzero(res, size);
    }
    return res;
}

void *realloc(void *ptr, size_t size){

    void *new;
    size_t old_size;
    void *res;

    /* This should not be needed if realloc is used properly but just in case ... */
    if(!__mem_alloc_init_flag){ 
        __mem_alloc_init_flag = 1;
        init_bootstrap_buffers();
        memory_init();
        __mem_alloc_init_completed = 1;
    }

    if (ptr == NULL) { 
        res = memory_alloc(size); /* according to the specification (malloc man page) */
        return res;
    }

    if ((size == 0) && (ptr != NULL)) { 
        memory_free(ptr); /* according to the specification (malloc man page) */
        res = NULL;
        return res;
    }

    /*
     * The reallocation is naive/suboptimal (systematic copy) but does not require to
     * expose much of the allocator internals, nor to support realloc within the allocator.
     */
    new = memory_alloc(size);
    if (new == NULL) {
        /* The original block is left untouched, as required in the specification. */
        return NULL; 
    }
    old_size = memory_get_allocated_block_size(ptr);
    memcpy(new, ptr, old_size); /* works because the two areas do not overlap */
    free(ptr);
    debug_printf("return = %p\n", new);
    return new;
}
