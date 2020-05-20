## Memory Allocator

A Dynamic memory allocator in C.

## Tests
Please read [README_tests](./README_tests.html) for a description of the provided tests and how to run them.

## Compiling the code

A Makefile is provided to automatically build the memory allocator and
run tests.

### Basic commands

To run a test, simply use the following command:
```
    make -B tests/alloc1.test
```

To simply build the interective shell, run:
```
    make -B mem_shell
```

**Note**: It is important to use option `-B` when running `make` to
force all files to be recompiled and be sure that all your changes have
been taken into account.

Please read the Makefile directly for more information.

### Configuring properties

The file *Makefile.config* defines the main properties of the memory
allocator.

## Allocator Features

  * The allocator uses different pools of (free) memory to fulfill the various memory allocation requests, depending on the requested sizes for the memory blocks. More precisely, there are 4 different pools:
	- Pool 0: for requests ≤ 64 bytes
	- Pool 1: for requests ≤ 256 bytes (and ≥ 65 bytes)
	- Pool 2: for requests ≤ 1024 bytes (and ≥ 257 bytes)
	- Pool 3: for requests > 1024 bytes
  * Each Pool is managed independentely
	- When an allocated block is freed by the application, it is always returened to its origin pool
	- If the suitable pool for one request is not able to fulfill the request, the allocation fails. The other pools are not used as fallback solutions to try to statisfy the request.

  * Each Pool is managed using a linked list of free blocks.
  * Pool 0,1,2 use a single block size (64, 256, and 1024 bytes respectively). Allocations are rounded up to these values, even if the request is smaller (results in internal fragmentation).
  * Pool 3 is based on a free-list of variable-sized blocks. The block chosen to satisfy an allocatio request is selected according to a specific policy (e.g., first fit), split if necessary and, when freed is immediately coalesced with other adjacent free blocks (if any).


### Directory content:
  *  ./src:  simple version of the allocator where one can allocate and manage memory in Pool 0,1,2. Based on the principle of linking free memory blocks with a singly linked list. The blocks of a pool are never split or coalesced. To fulfill a request a LIFO policy is applied in select the block.  
  *  ./src_alignment: a more advanced version of the allocator where there are additional Alignment Constraints.
















