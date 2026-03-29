/*
 * vxlan_daemon.c — VXLAN module daemon
 * Usage: vxlan_daemon [-s sock] [-c config] [-l local_ip] [-p port] [-i ifindex]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "vxlan.h"
#include "vxlan_ipc.h"

static void default_rx_cb(vxlan_pkt_t *pkt, void *user)
{
    (void)user;
    /* Default: just print a summary — real deployments replace this */
    fprintf(stderr, "[vxlan] rx vni=%u inner_len=%zu src_vtep=",
            pkt->vni, pkt->inner_len);
    char buf[INET6_ADDRSTRLEN];
    if (pkt->src_vtep.af == AF_INET)
        inet_ntop(AF_INET, &pkt->src_vtep.u.v4, buf, sizeof(buf));
    else if (pkt->src_vtep.af == AF_INET6)
        inet_ntop(AF_INET6, &pkt->src_vtep.u.v6, buf, sizeof(buf));
    else snprintf(buf, sizeof(buf), "?");
    fprintf(stderr, "%s\n", buf);
}

int main(int argc, char **argv)
{
    const char *sock_path   = getenv("VXLAN_SOCK_PATH");
    if (!sock_path) sock_path = "/var/run/vrouter/vxlan.sock";
    const char *config_path = getenv("VXLAN_CONFIG_PATH");
    const char *local_ip_s  = NULL;
    uint16_t    listen_port = VXLAN_PORT_DEFAULT;
    uint32_t    local_iidx  = 0;

    int opt;
    while ((opt = getopt(argc, argv, "s:c:l:p:i:h")) != -1) {
        switch (opt) {
        case 's': sock_path   = optarg; break;
        case 'c': config_path = optarg; break;
        case 'l': local_ip_s  = optarg; break;
        case 'p': listen_port = (uint16_t)atoi(optarg); break;
        case 'i': local_iidx  = (uint32_t)atoi(optarg); break;
        case 'h':
            printf("Usage: vxlan_daemon [-s sock] [-c config] "
                   "[-l local_ip] [-p port] [-i ifindex]\n");
            return 0;
        }
    }

    vxlan_ctx_t *ctx = vxlan_ctx_create();
    if (!ctx) { fprintf(stderr, "vxlan_ctx_create failed\n"); return 1; }

    vxlan_set_rx_cb(ctx, default_rx_cb, NULL);

    if (config_path) {
        printf("[vxlan] loading config from %s\n", config_path);
        vxlan_load_config(ctx, config_path);
    }

    vxlan_addr_t local_ip = {0};
    if (local_ip_s) vxlan_addr_parse(local_ip_s, &local_ip);

    if (vxlan_init(ctx, sock_path,
                   local_ip.af ? &local_ip : NULL,
                   local_iidx, listen_port) != VXLAN_OK) {
        fprintf(stderr, "vxlan_init failed (socket: %s)\n", sock_path);
        vxlan_ctx_destroy(ctx); return 1;
    }

    printf("[vxlan] listening on %s (UDP port %u, %u VNI(s))\n",
           sock_path, listen_port, ctx->vni_table.n_vnis);

    while (ctx->running) pause();

    vxlan_shutdown(ctx);
    vxlan_ctx_destroy(ctx);
    printf("[vxlan] shutdown complete\n");
    return 0;
}
