# About
This library contains helper functions for developing enclaves. These include

- debugging helpers (printf function)
- file operations


# Usage
Page 43 in the SGX SDK guide v1.1 gives details on how to create and use an enclave library.

A reference project that consumes this library can be found at `github.com/ftes/sgx-lib-consumer/`

## Import `sgx_lib_{u,t}` projects

## Switch configuration to `Simulation`

## Consume library in Untrusted Project (application)
- `Properties -> Common Properties -> Frameworks and References -> Add `sgx_lib_u`
- Add additional include directory: `..\include` (relative path may differ, depending on your setup)

## Consume library in Trusted Project (enclave)
- `Properties -> Common Properties -> Frameworks and References -> Add `sgx_lib_t`
- Add additional include directories: `..\include` and `..\sgx_lib_t\include` (relative path may differ, depending on your setup)
- Set macro `SGX_ENCLAVE` (header problem with `sgx_lib_stdio.h`)


# Configuration

## Insecure I/O operations
Enabled by the `SGX_INSECURE_IO_OPERATIONS` macro.

During development, insecure I/O operations can be used. These allow data to leave the enclave unencrypted.
When including legacy code, this allows legacy compatible behaviour, **without** security garuantees.

Without this macro, writes and reads to standard and file streams are sealed (encrypted).
Replay protection **IS NOT** added.


# Development Caveats

## No errors in libraries showing
Currently, no errors are showing in the two library projects `sgx_lib_t` and `sgx_lib_u`. An erronuous project will compile and even run.