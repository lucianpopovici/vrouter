#ifndef VROUTER_IPC_SERVER_H
#define VROUTER_IPC_SERVER_H

#include <stddef.h>

/*
 * Generic Unix-domain socket server.
 *
 * Usage:
 *   1. Call vr_ipc_server_init() to create + bind + listen.
 *   2. Call vr_ipc_server_run() with a handler callback; it blocks until
 *      srv->running is set to 0 (e.g., from a signal handler).
 *   3. Call vr_ipc_server_destroy() on shutdown.
 *
 * Handler contract: write response into resp[0..resp_cap), return the
 * response length (bytes to send). Return <= 0 to send nothing.
 */
typedef int (*vr_ipc_handler_fn)(const char *req, size_t req_len,
                                  char *resp, size_t resp_cap,
                                  void *ctx);

typedef struct {
    int          fd;        /* listening socket fd (-1 if not open) */
    const char  *sock_path;
    volatile int running;
} vr_ipc_server_t;

/* Create, bind, and listen on sock_path. Returns 0 on success, -1 on error. */
int  vr_ipc_server_init(vr_ipc_server_t *srv, const char *sock_path, int backlog);

/* Blocking serve loop. Runs until srv->running becomes 0.
 * req_buf_sz / resp_buf_sz are the sizes of the per-call stack buffers. */
int  vr_ipc_server_run(vr_ipc_server_t *srv, vr_ipc_handler_fn handler, void *ctx,
                        size_t req_buf_sz, size_t resp_buf_sz);

/* Close the socket and unlink the path. */
void vr_ipc_server_destroy(vr_ipc_server_t *srv);

#endif /* VROUTER_IPC_SERVER_H */
