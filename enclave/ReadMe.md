# About
This library contains helper functions for developing enclaves. These include

- logging
- file operations


# Configuration
## General
Macro `SGX_ENCLAVE` has to be set in enclave project (`mystdio.h` header problem).

## File operations
Reading from and writing to files can be done in *legacy mode* or *secure mode*.
In the latter, the contents are sealed to the platform. Replay protection **IS NOT** added.
Legacy mode is enabled by defining the `SGX_INSECURE_FILE_OPERATIONS` macro.