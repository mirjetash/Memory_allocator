This is the README file for the memory allocator project of the OS course in M1 Mosig.

## About tests

Please read [README_tests](./README_tests.html) for a description of the provided tests and
how to run them.


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
allocator. You can modify this file to change the properties of your
allocator (for instance, regarding the policy applied to the standard
pool). Do not forget to recompile your code after any modification
made to this file.

Note that a property can also be changed from the command line when
calling `make` (without editing the Makefile). Here is an exemple that selects the *next fit* strategy:
```
    make -B STDPOOL_POLICY=NF mem_shell
```

***

## List of provided files

  * *mem_alloc.h*: The interface of your allocator.
  
  * *mem_alloc_types.h*: The data types used by the allocator.
  
  * *mem_alloc.c*: Creates the different pools and provides the dispatcher functions to invoke the approriate pool for a given request.
  
  * *mem_alloc_fast_pool.h*: The data types used by the code in charge of the fast pools.
  
  * *mem_alloc_fast_pool.c*: The code for the management of fast pools. 
  
  * *mem_alloc_standard_pool.h* and *mem_alloc_standard_pool_types.c*: The data types and helper functions used by the code in charge of the standard pools.
  
  * *mem_alloc_standard_pool.c*: The code for the management of the standard pool.
  
  * *my_mmap.h* and *my_mmap.c*: Wrapper code for simplifying the usage of mmap.
  
  * *mem_alloc_std.c*: Re-implements default allocation (malloc, free, ...) so that existing programs can be run with your allocator.
  
  * *mem_shell.c*: a simple program to test your allocator.
  
  * *bin/mem_shell_sim*: Program that generates the expected trace
    for a scenario
    
  * *tests/allocX.in*: Test scenarios
  
  * *Makefile*: Rules to build the project
  
  * *Makefile.config*: Definition of the (default) parameters of the memory
    allocator
 
  * *README.md*: this file
 
  * *README_tests.md*: Readme file about the tests



