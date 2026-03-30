#ifndef FDB_IPC_H
#define FDB_IPC_H
#include "fdb.h"
#define FDB_SOCK_NAME   "fdb.sock"
#define FDB_SOCK_DEFAULT "/tmp/fdb.sock"
struct l2_config;
int fdb_ipc_serve(fdb_table_t *fdb, struct l2_config *cfg,
                  const char *sock_path, volatile int *running);
#endif
