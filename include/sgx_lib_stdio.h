//only define FILE in enclave (application's stdio.h should have this typedef already)

#if defined(SGX_ENCLAVE) && !defined(SGX_LIB_STDIO_H)
#define SGX_LIB_STDIO_H

struct _iobuf {
        char *_ptr;
        int   _cnt;
        char *_base;
        int   _flag;
        int   _file;
        int   _charbuf;
        int   _bufsiz;
        char *_tmpfname;
        };
typedef struct _iobuf FILE;

#define SEEK_CUR    1
#define SEEK_END    2
#define SEEK_SET    0
#define FILENAME_MAX    260
#define FOPEN_MAX       20
#define _SYS_OPEN       20
#define TMP_MAX         32767  /* SHRT_MAX */

#endif