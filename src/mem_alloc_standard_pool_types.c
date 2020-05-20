#include "mem_alloc_standard_pool.h"

/* Note: 1UL corresponds to the value 1 represented as an unsigned long int (64 bits). */

/* Returns 1 if the block is used, or 0 if the block is free */
int is_block_used(mem_standard_block_header_footer_t *m) {
    return (((m->flag_and_size)>>63) & 1UL);
}

/* Returns 1 the if block is free, or 1 if the block is free */
int is_block_free (mem_standard_block_header_footer_t *m) {
    return (is_block_used(m) == 0);
}

/* Modifies a block header (or footer) to mark it as used */
void set_block_used(mem_standard_block_header_footer_t *m) {
    m->flag_and_size = ((m->flag_and_size) | (1UL<<63));
}

/* Modifies a block header (or footer) to mark it as free */
void set_block_free(mem_standard_block_header_footer_t *m) {
    m->flag_and_size = ((m->flag_and_size) & ~(1UL<<63));
}

/* Returns the size of a block (as stored in the header/footer) */
size_t get_block_size(mem_standard_block_header_footer_t *m) {
    uint64_t res = ((m->flag_and_size) & ~(1UL<<63));
    return (size_t)res;
}

/* Modifies a block header (or footer) to update the size of the block */
void set_block_size(mem_standard_block_header_footer_t *m, size_t size) {
    uint64_t s = (uint64_t)size;
    uint64_t flag = (m->flag_and_size) & (1UL<<63);
    m->flag_and_size = flag | s;
}
