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
        "  \"commands\": [\n"
        "    {\"cmd\": \"%s\", \"args\": {\"ifindex\": \"int\", \"prefix\": \"str\", \"valid_lft\": \"int\", \"pref_lft\": \"int\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"ifindex\": \"int\", \"prefix\": \"str\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"ifindex\": \"int (optional, -1=all)\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"prefix\": \"str\", \"nexthop\": \"str\", \"ifindex\": \"int\", \"ad\": \"int\", \"metric\": \"int\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"prefix\": \"str\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"af\": \"ipv4|ipv6 (optional)\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"dst\": \"str\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"af\": \"ipv4|ipv6\", \"enable\": \"bool\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"ifindex\": \"int\", \"af\": \"ipv4|ipv6\", \"enable\": \"bool\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"af\": \"ipv4|ipv6\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"af\": \"ipv4|ipv6\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"path\": \"str (optional)\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"path\": \"str (optional)\"}}\n"
        "  ]\n"
        "}\n",
        IP_CMD_ADD_ADDR,
        IP_CMD_DEL_ADDR,
        IP_CMD_LIST_ADDRS,
        IP_CMD_LIST_IFS,
        IP_CMD_ADD_ROUTE,
        IP_CMD_DEL_ROUTE,
        IP_CMD_LIST_ROUTES,
        IP_CMD_LOOKUP,
        IP_CMD_SET_FWD,
        IP_CMD_GET_FWD,
        IP_CMD_SET_IF_FWD,
        IP_CMD_GET_STATS,
        IP_CMD_CLEAR_STATS,
        IP_CMD_DUMP_CONFIG,
        IP_CMD_LOAD_CONFIG);
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
