#ifndef IP_IPC_H
#define IP_IPC_H

#include "ip.h"

#define IP_IPC_MAX_MSG  65536

int  ip_ipc_init(ip_ctx_t *ctx);
void ip_ipc_stop(ip_ctx_t *ctx);
void *ip_ipc_thread(void *arg);

/* Handlers (called from IPC thread) */
char *ip_ipc_handle(ip_ctx_t *ctx, const char *req, size_t req_len);

#endif /* IP_IPC_H */
