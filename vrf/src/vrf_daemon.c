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
        "  \"commands\": [\n"
        "    {\"cmd\": \"%s\", \"args\": {\"id\": \"int\", \"name\": \"str\", \"flags\": \"int\", \"table_id\": \"int\", \"rd\": \"int\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"id\": \"int\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"id\": \"int (or name: str)\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"vrf_id\": \"int\", \"ifindex\": \"int\", \"ifname\": \"str\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"ifindex\": \"int\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"vrf_id\": \"int (optional, -1=all)\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"ifindex\": \"int\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"vrf_id\": \"int\", \"prefix\": \"str\", \"nexthop\": \"str\", \"ifindex\": \"int\", \"ad\": \"int\", \"metric\": \"int\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"vrf_id\": \"int\", \"prefix\": \"str\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"vrf_id\": \"int (optional)\", \"af\": \"ipv4|ipv6 (optional)\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"vrf_id\": \"int\", \"dst\": \"str\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"src_vrf_id\": \"int\", \"dst_vrf_id\": \"int\", \"prefix\": \"str\", \"nexthop\": \"str\", \"ifindex\": \"int\", \"metric\": \"int\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"src_vrf_id\": \"int\", \"dst_vrf_id\": \"int\", \"prefix\": \"str\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"vrf_id\": \"int (optional)\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"vrf_id\": \"int\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"vrf_id\": \"int\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"path\": \"str (optional)\"}},\n"
        "    {\"cmd\": \"%s\", \"args\": {\"path\": \"str (optional)\"}}\n"
        "  ]\n"
        "}\n",
        VRF_CMD_CREATE, VRF_CMD_DELETE, VRF_CMD_LIST, VRF_CMD_GET,
        VRF_CMD_BIND_IF, VRF_CMD_UNBIND_IF, VRF_CMD_LIST_IFS, VRF_CMD_GET_IF_VRF,
        VRF_CMD_ADD_ROUTE, VRF_CMD_DEL_ROUTE, VRF_CMD_LIST_ROUTES, VRF_CMD_LOOKUP,
        VRF_CMD_LEAK_ROUTE, VRF_CMD_UNLEAK_ROUTE, VRF_CMD_LIST_LEAKS,
        VRF_CMD_GET_STATS, VRF_CMD_CLEAR_STATS,
        VRF_CMD_DUMP_CONFIG, VRF_CMD_LOAD_CONFIG);
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
