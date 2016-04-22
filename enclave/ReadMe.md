# About
This library contains helper functions for developing enclaves. These include

- logging
- file operations


# Configuration
## General
Macro `SGX_ENCLAVE` has to be set in enclave project (`mystdio.h` header problem).

## Insecure I/O operations
Enabled by the `SGX_INSECURE_IO_OPERATIONS` macro.

During development, insecure I/O operations can be used. These allow data to leave the enclave unencrypted.
When including legacy code, this allows legacy compatible behaviour, **without** security garuantees.

Without this macro, writes and reads to standard and file streams are sealed (encrypted).
Replay protection **IS NOT** added.
