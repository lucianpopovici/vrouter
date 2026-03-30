#include <vrouter/ipc_server.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>

int vr_ipc_server_init(vr_ipc_server_t *srv, const char *sock_path, int backlog)
{
    srv->fd       = -1;
    srv->sock_path = sock_path;
    srv->running  = 1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("vr_ipc: socket"); return -1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    unlink(sock_path); /* remove stale socket if present */

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("vr_ipc: bind"); close(fd); return -1;
    }
    if (listen(fd, backlog > 0 ? backlog : 8) < 0) {
        perror("vr_ipc: listen"); close(fd); return -1;
    }

    srv->fd = fd;
    return 0;
}

int vr_ipc_server_run(vr_ipc_server_t *srv, vr_ipc_handler_fn handler, void *ctx,
                       size_t req_buf_sz, size_t resp_buf_sz)
{
    if (!srv || srv->fd < 0 || !handler) return -1;

    char *req  = malloc(req_buf_sz);
    char *resp = malloc(resp_buf_sz);
    if (!req || !resp) { free(req); free(resp); return -1; }

    while (srv->running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(srv->fd, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        if (select(srv->fd + 1, &rfds, NULL, NULL, &tv) <= 0) continue;

        int cli = accept(srv->fd, NULL, NULL);
        if (cli < 0) continue;

        ssize_t n = recv(cli, req, req_buf_sz - 1, 0);
        if (n > 0) {
            req[n] = '\0';
            int rlen = handler(req, (size_t)n, resp, resp_buf_sz, ctx);
            if (rlen > 0)
                send(cli, resp, (size_t)rlen, 0);
        }
        close(cli);
    }

    free(req);
    free(resp);
    return 0;
}

void vr_ipc_server_destroy(vr_ipc_server_t *srv)
{
    if (!srv) return;
    if (srv->fd >= 0) {
        close(srv->fd);
        srv->fd = -1;
    }
    if (srv->sock_path) unlink(srv->sock_path);
}
