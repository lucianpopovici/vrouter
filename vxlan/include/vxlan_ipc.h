#ifndef VXLAN_IPC_H
#define VXLAN_IPC_H
#include "vxlan.h"
#define VXLAN_IPC_MAX_MSG 131072
int   vxlan_ipc_init(vxlan_ctx_t *ctx);
void  vxlan_ipc_stop(vxlan_ctx_t *ctx);
void *vxlan_ipc_thread(void *arg);
char *vxlan_ipc_handle(vxlan_ctx_t *ctx, const char *req, size_t req_len);
#endif
