#ifndef EVPN_IPC_H
#define EVPN_IPC_H
#include "evpn.h"
#define EVPN_IPC_MAX_MSG 131072
int   evpn_ipc_init(evpn_ctx_t *ctx);
void  evpn_ipc_stop(evpn_ctx_t *ctx);
void *evpn_ipc_thread(void *arg);
char *evpn_ipc_handle(evpn_ctx_t *ctx, const char *req, size_t req_len);
#endif
