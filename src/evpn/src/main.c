/*
 * evpn_daemon.c — BGP EVPN module daemon
 *
 * Usage: evpn_daemon [-s sock] [-c config] [-S schema]
 *                    [-v local_vtep_ip] [-a local_asn]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "evpn.h"
#include "evpn_ipc.h"

static void write_schema(const char *path)
{
    FILE *f = fopen(path, "w"); if (!f) return;
    fprintf(f,
        "{\n"
        "  \"module\": \"evpn\",\n"
        "  \"version\": \"1.0\",\n"
        "  \"keys\": {\n"
        "    \"LOCAL_ASN\": {\n"
        "      \"type\": \"int\", \"description\": \"Local BGP AS number (read-only, set via -a flag)\",\n"
        "      \"default\": 0, \"min\": 0, \"max\": 4294967295,\n"
        "      \"mandatory\": false, \"group\": \"BGP\"\n"
        "    },\n"
        "    \"LOCAL_VTEP\": {\n"
        "      \"type\": \"str\", \"description\": \"Local VTEP IP address (read-only, set via -l flag)\",\n"
        "      \"default\": \"\",\n"
        "      \"mandatory\": false, \"group\": \"BGP\"\n"
        "    }\n"
        "  }\n"
        "}\n");
    fclose(f);
    printf("[evpn] schema written to %s\n", path);
}

int main(int argc, char **argv)
{
    const char *sock_path   = getenv("EVPN_SOCK_PATH");
    if (!sock_path) sock_path = "/var/run/vrouter/evpn.sock";
    const char *config_path = getenv("EVPN_CONFIG_PATH");
    const char *schema_path = "evpn_schema.json";
    const char *vtep_str    = NULL;
    uint32_t    local_asn   = 65000;

    int opt;
    while ((opt = getopt(argc, argv, "s:c:S:v:a:h")) != -1) {
        switch (opt) {
        case 's': sock_path   = optarg; break;
        case 'c': config_path = optarg; break;
        case 'S': schema_path = optarg; break;
        case 'v': vtep_str    = optarg; break;
        case 'a': local_asn   = (uint32_t)atoi(optarg); break;
        case 'h':
            printf("Usage: evpn_daemon [-s sock] [-c config] [-S schema] "
                   "[-v local_vtep_ip] [-a local_asn]\n");
            return 0;
        }
    }

    write_schema(schema_path);

    evpn_ctx_t *ctx = evpn_ctx_create();
    if (!ctx) { fprintf(stderr, "evpn_ctx_create failed\n"); return 1; }

    evpn_addr_t vtep_ip = {0};
    if (vtep_str) evpn_addr_parse(vtep_str, &vtep_ip);

    if (config_path) {
        printf("[evpn] loading config from %s\n", config_path);
        evpn_load_config(ctx, config_path);
    }

    if (evpn_init(ctx, sock_path, vtep_ip.af ? &vtep_ip : NULL, local_asn) != EVPN_OK) {
        fprintf(stderr, "evpn_init failed (socket: %s)\n", sock_path);
        evpn_ctx_destroy(ctx); return 1;
    }

    printf("[evpn] listening on %s (ASN %u, %u EVI(s))\n",
           sock_path, local_asn, ctx->evi_table.n_evis);

    while (ctx->running) pause();

    evpn_shutdown(ctx);
    evpn_ctx_destroy(ctx);
    printf("[evpn] shutdown complete\n");
    return 0;
}
