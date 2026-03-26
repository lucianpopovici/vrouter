#ifndef RIB_IPC_H
#define RIB_IPC_H
#include "rib.h"
#include "fib.h"
#define RIB_SOCK_NAME    "ribd.sock"
#define RIB_SOCK_DEFAULT "/tmp/ribd.sock"
int rib_ipc_serve(rib_table_t *rib, fib_table_t *fib,
                  const char *sock_path, volatile int *running);
#endif
