/*
 * ip_daemon.c — entry point for the IP module daemon.
 *
 * Usage:
 *   ip_daemon [OPTIONS]
 *
 * Options:
 *   -s <sock>        Unix socket path  (default: /var/run/vrouter/ip.sock,
 *                                       env: IP_SOCK_PATH)
 *   -c <config>      Runtime config file to load at startup
 *   -S <schema>      Path to write schema.json   (default: ip_schema.json)
 *   --no-ipv4-fwd    Disable IPv4 forwarding at startup
 *   --no-ipv6-fwd    Disable IPv6 forwarding at startup
 *   -h               Help
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#include "ip.h"
#include "ip_ipc.h"

/* -----------------------------------------------------------------------
 * Schema export
 * --------------------------------------------------------------------- */
static void write_schema(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror("schema open"); return; }
    fprintf(f,
        "{\n"
        "  \"module\": \"ip\",\n"
        "  \"version\": \"1.0\",\n"
        "  \"keys\": {\n"
        "    \"IPV4_FWD\": {\n"
        "      \"type\": \"str\", \"description\": \"Enable global IPv4 packet forwarding\",\n"
        "      \"default\": \"true\", \"choices\": [\"true\", \"false\"],\n"
        "      \"mandatory\": false, \"group\": \"Forwarding\"\n"
        "    },\n"
        "    \"IPV6_FWD\": {\n"
        "      \"type\": \"str\", \"description\": \"Enable global IPv6 packet forwarding\",\n"
        "      \"default\": \"true\", \"choices\": [\"true\", \"false\"],\n"
        "      \"mandatory\": false, \"group\": \"Forwarding\"\n"
        "    },\n"
        "    \"ECMP_HASH_MODE\": {\n"
        "      \"type\": \"int\", \"description\": \"ECMP hash field bitmask (1=src_ip 2=dst_ip 4=src_port 8=dst_port 16=proto)\",\n"
        "      \"default\": 3, \"min\": 0, \"max\": 31,\n"
        "      \"mandatory\": false, \"group\": \"ECMP\"\n"
        "    },\n"
        "    \"DEFAULT_TTL\": {\n"
        "      \"type\": \"int\", \"description\": \"Default TTL for originated IPv4 packets\",\n"
        "      \"default\": 64, \"min\": 1, \"max\": 255,\n"
        "      \"mandatory\": false, \"group\": \"Forwarding\"\n"
        "    }\n"
        "  }\n"
        "}\n");
    fclose(f);
    printf("[ip] schema written to %s\n", path);
}

/* -----------------------------------------------------------------------
 * Main
 * --------------------------------------------------------------------- */
static const struct option long_opts[] = {
    {"no-ipv4-fwd", no_argument, NULL, '4'},
    {"no-ipv6-fwd", no_argument, NULL, '6'},
    {NULL, 0, NULL, 0}
};

int main(int argc, char **argv)
{
    const char *sock_path    = getenv("IP_SOCK_PATH");
    if (!sock_path) sock_path = "/var/run/vrouter/ip.sock";

    const char *config_path  = getenv("IP_CONFIG_PATH");
    const char *schema_path  = "ip_schema.json";
    bool no_ipv4_fwd = false, no_ipv6_fwd = false;

    int opt;
    while ((opt = getopt_long(argc, argv, "s:c:S:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 's': sock_path   = optarg; break;
        case 'c': config_path = optarg; break;
        case 'S': schema_path = optarg; break;
        case '4': no_ipv4_fwd = true;   break;
        case '6': no_ipv6_fwd = true;   break;
        case 'h':
            printf("Usage: ip_daemon [-s sock] [-c config] [-S schema]\n"
                   "                 [--no-ipv4-fwd] [--no-ipv6-fwd]\n");
            return 0;
        }
    }

    /* Write schema before any blocking init */
    write_schema(schema_path);

    ip_ctx_t *ctx = ip_ctx_create();
    if (!ctx) { fprintf(stderr, "ip_ctx_create failed\n"); return 1; }

    if (no_ipv4_fwd) ip_set_forwarding(ctx, AF_INET,  false);
    if (no_ipv6_fwd) ip_set_forwarding(ctx, AF_INET6, false);

    if (config_path) {
        printf("[ip] loading config from %s\n", config_path);
        ip_load_config(ctx, config_path);
    }

    if (ip_init(ctx, sock_path) != IP_OK) {
        fprintf(stderr, "ip_init failed (socket: %s)\n", sock_path);
        ip_ctx_destroy(ctx);
        return 1;
    }

    printf("[ip] listening on %s (ipv4_fwd=%s ipv6_fwd=%s)\n",
           sock_path,
           ip_get_forwarding(ctx, AF_INET)  ? "on" : "off",
           ip_get_forwarding(ctx, AF_INET6) ? "on" : "off");

    /* Main loop — daemon stays alive until SIGTERM/SIGINT */
    while (ctx->running) pause();

    ip_shutdown(ctx);
    ip_ctx_destroy(ctx);
    printf("[ip] shutdown complete\n");
    return 0;
}
