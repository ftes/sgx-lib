//only define FILE in enclave (application's stdio.h should have this typedef already)

#if defined(SGX_ENCLAVE) && !defined(MYSTDIO_H)
#define MYSTDIO_H

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

#endif