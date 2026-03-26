#ifndef L2RIB_IPC_H
#define L2RIB_IPC_H
#include "l2rib.h"
#include "fdb.h"
#define L2RIB_SOCK_NAME   "l2rib.sock"
#define L2RIB_SOCK_DEFAULT "/tmp/l2rib.sock"
struct l2_config;
int l2rib_ipc_serve(l2rib_table_t *rib, fdb_table_t *fdb,
                    struct l2_config *cfg, const char *sock_path,
                    volatile int *running);
#endif
