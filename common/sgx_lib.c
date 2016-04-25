#include "sgx_lib.h"

char* get_error_description(int error_code) {
switch (error_code) {
case 0x0001 : return "UNEXPECTED Unexpected error ";
case 0x0002 : return "INVALID_PARAMETER The parameter is incorrect ";
case 0x0003 : return "OUT_OF_MEMORY Not enough memory is available to complete this operation ";
case 0x0004 : return "ENCLAVE_LOST Enclave lost after power transition or used in child process created by linux:fork(";
case 0x0005 : return "INVALID_STATE SGX API is invoked in incorrect order or state ";
case 0x0006 : return "VMM_INCOMPATIBLE Virtual Machine Monitor is not compatible ";
case 0x0007 : return "HYPERV_ENABLED Win10 platform with Hyper-V enabled ";
case 0x0008 : return "FEATURE_NOT_SUPPORTED Feature is not supported on this platform ";
case 0x1001 : return "INVALID_FUNCTION The ecall/ocall index is invalid ";
case 0x1003 : return "OUT_OF_TCS The enclave is out of TCS ";
case 0x1006 : return "ENCLAVE_CRASHED The enclave is crashed ";
case 0x1007 : return "ECALL_NOT_ALLOWED The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization ";
case 0x1008 : return "OCALL_NOT_ALLOWED The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling ";
case 0x2000 : return "UNDEFINED_SYMBOL The enclave image has undefined symbol. ";
case 0x2001 : return "INVALID_ENCLAVE The enclave image is not correct. ";
case 0x2002 : return "INVALID_ENCLAVE_ID The enclave id is invalid ";
case 0x2003 : return "INVALID_SIGNATURE The signature is invalid ";
case 0x2004 : return "NDEBUG_ENCLAVE The enclave is signed as product enclave, and can not be created as debuggable enclave. ";
case 0x2005 : return "OUT_OF_EPC Not enough EPC is available to load the enclave ";
case 0x2006 : return "NO_DEVICE Can't open SGX device ";
case 0x2007 : return "MEMORY_MAP_CONFLICT Page mapping failed in driver ";
case 0x2009 : return "INVALID_METADATA The metadata is incorrect. ";
case 0x200c : return "DEVICE_BUSY Device is busy, mostly EINIT failed. ";
case 0x200d : return "INVALID_VERSION Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform. ";
case 0x200e : return "MODE_INCOMPATIBLE The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS. ";
case 0x200f : return "ENCLAVE_FILE_ACCESS Can't open enclave file. ";
case 0x2010 : return "INVALID_MISC The MiscSelct/MiscMask settings are not correct.";
case 0x3001 : return "MAC_MISMATCH Indicates verification error for reports, sealed datas, etc ";
case 0x3002 : return "INVALID_ATTRIBUTE The enclave is not authorized ";
case 0x3003 : return "INVALID_CPUSVN The cpu svn is beyond platform's cpu svn value ";
case 0x3004 : return "INVALID_ISVSVN The isv svn is greater than the enclave's isv svn ";
case 0x3005 : return "INVALID_KEYNAME The key name is an unsupported value ";
case 0x4001 : return "SERVICE_UNAVAILABLE Indicates aesm not response or the requested service is not supported ";
case 0x4002 : return "SERVICE_TIMEOUT Request to aesm time out ";
case 0x4003 : return "AE_INVALID_EPIDBLOB Indicates epid blob verification error ";
case 0x4004 : return "SERVICE_INVALID_PRIVILEGE Get launch token error ";
case 0x4005 : return "EPID_MEMBER_REVOKED The EPID group membership revoked. ";
case 0x4006 : return "UPDATE_NEEDED SGX needs to be updated ";
case 0x4007 : return "NETWORK_FAILURE Network connecting or proxy setting issue is encountered ";
case 0x4008 : return "AE_SESSION_INVALID Session is invalid or ended by server ";
case 0x400a : return "BUSY The requested service is temporarily not availabe ";
case 0x400c : return "MC_NOT_FOUND The Monotonic Counter doesn't exist or has been invalided ";
case 0x400d : return "MC_NO_ACCESS_RIGHT Caller doesn't have the access right to specified VMC ";
case 0x400e : return "MC_USED_UP Monotonic counters are used out ";
case 0x400f : return "MC_OVER_QUOTA Monotonic counters exceeds quota limitation ";
case 0x5001 : return "EFI_NOT_SUPPORTED The OS doesn't support EFI ";
case 0x5002 : return "NO_PRIVILEGE Not enough privelige to perform the operation ";
default : return "unknown error code";
}}