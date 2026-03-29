/*
 * vrf_daemon.c — VRF module daemon entry point.
 *
 * Usage:
 *   vrf_daemon [OPTIONS]
 *
 * Options:
 *   -s <sock>    Unix socket path  (default: /var/run/vrouter/vrf.sock,
 *                                   env: VRF_SOCK_PATH)
 *   -c <config>  Runtime config to load at startup
 *   -S <schema>  Schema output path  (default: vrf_schema.json)
 *   -h           Help
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#include "vrf.h"
#include "vrf_ipc.h"

static void write_schema(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror("schema open"); return; }
    fprintf(f,
        "{\n"
        "  \"module\": \"vrf\",\n"
        "  \"version\": \"1.0\",\n"
        "  \"keys\": {\n"
        "    \"ECMP_HASH_MODE\": {\n"
        "      \"type\": \"int\", \"description\": \"Global ECMP hash field bitmask for new VRF instances (1=src_ip 2=dst_ip 4=src_port 8=dst_port 16=proto)\",\n"
        "      \"default\": 3, \"min\": 0, \"max\": 31,\n"
        "      \"mandatory\": false, \"group\": \"ECMP\"\n"
        "    }\n"
        "  }\n"
        "}\n");
    fclose(f);
    printf("[vrf] schema written to %s\n", path);
}

int main(int argc, char **argv)
{
    const char *sock_path   = getenv("VRF_SOCK_PATH");
    if (!sock_path) sock_path = "/var/run/vrouter/vrf.sock";
    const char *config_path = getenv("VRF_CONFIG_PATH");
    const char *schema_path = "vrf_schema.json";

    int opt;
    while ((opt = getopt(argc, argv, "s:c:S:h")) != -1) {
        switch (opt) {
        case 's': sock_path   = optarg; break;
        case 'c': config_path = optarg; break;
        case 'S': schema_path = optarg; break;
        case 'h':
            printf("Usage: vrf_daemon [-s sock] [-c config] [-S schema]\n");
            return 0;
        }
    }

    write_schema(schema_path);

    vrf_ctx_t *ctx = vrf_ctx_create();
    if (!ctx) { fprintf(stderr, "vrf_ctx_create failed\n"); return 1; }

    if (config_path) {
        printf("[vrf] loading config from %s\n", config_path);
        vrf_load_config(ctx, config_path);
    }

    if (vrf_init(ctx, sock_path) != VRF_OK) {
        fprintf(stderr, "vrf_init failed (socket: %s)\n", sock_path);
        vrf_ctx_destroy(ctx);
        return 1;
    }

    printf("[vrf] listening on %s (%u VRF(s))\n",
           sock_path, ctx->vrf_table.n_vrfs);

    while (ctx->running) pause();

    vrf_shutdown(ctx);
    vrf_ctx_destroy(ctx);
    printf("[vrf] shutdown complete\n");
    return 0;
}
