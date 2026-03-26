#ifndef STP_IPC_H
#define STP_IPC_H
#include "stp.h"
#include "fdb.h"
#define STP_SOCK_NAME   "l2stp.sock"
#define STP_SOCK_DEFAULT "/tmp/l2stp.sock"
struct l2_config;
int  stp_ipc_serve(stp_bridge_t *br, fdb_table_t *fdb,
                   struct l2_config *cfg, const char *sock_path,
                   volatile int *running);
void recalculate_roles_pub(stp_bridge_t *br);
#endif
