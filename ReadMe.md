# About
This library contains helper functions for developing enclaves. These include

- debugging helpers (printf function)
- file operations


# Usage
Page 43 in the SGX SDK guide v1.1 gives details on how to create and use an enclave library.

A reference project that consumes this library can be found at `github.com/ftes/sgx-lib-consumer/`

**Steps**:

1. Import `sgx_lib_{u,t}` projects
2. Switch configuration to `Simulation`
3. Consume library in untrusted app (see below)
4. Consume library in trusted enclave (see below)
5. Use and configure SGX debugger (see below)

## Consume library in Untrusted Project (application)
- `Properties -> Common Properties -> Frameworks and References -> Add `sgx_lib_u`
- Add additional include directory: `..\sgx-lib\include` and `..\sgx-lib\sgx_lib_u\include` (relative path may differ, depending on your setup)

## Consume library in Trusted Project (enclave)
- `Properties -> Common Properties -> Frameworks and References -> Add `sgx_lib_t`
- Add additional include directories: `..\sgx-lib\include` and `..\sgx-lib\sgx_lib_t\include` (relative path may differ, depending on your setup)
- Set macro `SGX_ENCLAVE` (header problem with `sgx_lib_stdio.h`)
- Import OCALLs and ECALLs by adding to your `enclave.edl`: `from "../sgx-lib/sgx_lib_t/sgx_lib.edl" import *;` (relative path may differ, depending on your setup)

## Configure Debugger
- Use the `Intel SGX Debugger`
- Set `Configuration Properties->Debugging->WorkingDirectory` to `$(OutDir)`


# Configuration

## Insecure I/O operations
Enabled by the `SGX_INSECURE_IO_OPERATIONS` macro.

During development, insecure I/O operations can be used. These allow data to leave the enclave unencrypted.
When including legacy code, this allows legacy compatible behaviour, **without** security garuantees.

Without this macro, writes and reads to standard and file streams are sealed (encrypted).
Replay protection **IS NOT** added.

## Secure I/O operations
Use either

1. `seal/unseal` or
2. `encrypt/decrypt`

as the underlying encryption primitive. (1) is the default, (2) is enabled by setting the `SGX_SECURE_IO_OPERATIONS_KEY` macro.

(2) requires a symmetric encryption key, which can be set using `set_secure_io_key()`. This key is used to en/decrypt all subsequent I/O operations, until it is overwritten by another call to `set_secure_io_key()`.