#ifndef FIB_IPC_H
#define FIB_IPC_H
#include "fib.h"
#define FIB_SOCK_NAME    "fibd.sock"
#define FIB_SOCK_DEFAULT "/tmp/fibd.sock"
int ipc_serve(fib_table_t *fib, const char *sock_path, volatile int *running);
#endif
