#ifndef VRF_IPC_H
#define VRF_IPC_H

#include "vrf.h"

#define VRF_IPC_MAX_MSG  131072

int   vrf_ipc_init(vrf_ctx_t *ctx);
void  vrf_ipc_stop(vrf_ctx_t *ctx);
void *vrf_ipc_thread(void *arg);
char *vrf_ipc_handle(vrf_ctx_t *ctx, const char *req, size_t req_len);

#endif /* VRF_IPC_H */
