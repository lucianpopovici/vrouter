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
        "{\n  \"module\": \"evpn\",  \"version\": \"1.0\",\n"
        "  \"commands\": [\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\",\"l2_vni\":\"int\","
        "\"l3_vni\":\"int\",\"vrf_id\":\"int\",\"flags\":\"int\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\",\"rd\":\"str ASN:local\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\",\"rt\":\"str\","
        "\"export\":\"bool\",\"import\":\"bool\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\",\"rt\":\"str\","
        "\"export\":\"bool\",\"import\":\"bool\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\","
        "\"ip\":\"str\",\"mac\":\"str\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"ip\":\"str\",\"encap\":\"int\","
        "\"flags\":\"int\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"ip\":\"str\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\",\"mac\":\"str\","
        "\"ip\":\"str\",\"flags\":\"int\",\"vtep\":\"str\","
        "\"ifindex\":\"int\",\"rd\":\"str\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\","
        "\"mac\":\"str\",\"ip\":\"str\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\","
        "\"mac\":\"str\",\"ip\":\"str\",\"ifindex\":\"int\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\","
        "\"mac\":\"str\",\"ip\":\"str\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\","
        "\"vtep\":\"str (optional, NULL=all remote)\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\","
        "\"vtep\":\"str\",\"rd\":\"str\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\",\"vtep\":\"str\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\",\"prefix\":\"str\","
        "\"gw_ip\":\"str\",\"gw_mac\":\"str\",\"vtep\":\"str\","
        "\"local\":\"bool\",\"rd\":\"str\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\",\"prefix\":\"str\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int\",\"dst\":\"str\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"esi\":\"str\",\"es_type\":\"int\","
        "\"sys_mac\":\"str\",\"local_disc\":\"int\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"esi\":\"str\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int (optional)\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"evi_id\":\"int (optional)\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"path\":\"str (optional)\"}},\n"
        "    {\"cmd\":\"%s\",\"args\":{\"path\":\"str (optional)\"}}\n"
        "  ]\n}\n",
        EVPN_CMD_CREATE_EVI, EVPN_CMD_DELETE_EVI,
        EVPN_CMD_LIST_EVIS,  EVPN_CMD_GET_EVI,
        EVPN_CMD_SET_EVI_RD, EVPN_CMD_ADD_EVI_RT,
        EVPN_CMD_DEL_EVI_RT, EVPN_CMD_SET_IRB,
        EVPN_CMD_ADD_VTEP,   EVPN_CMD_DEL_VTEP,   EVPN_CMD_LIST_VTEPS,
        EVPN_CMD_ADD_MAC,    EVPN_CMD_DEL_MAC,
        EVPN_CMD_LEARN_MAC,  EVPN_CMD_LIST_MACS,
        EVPN_CMD_LOOKUP_MAC, EVPN_CMD_FLUSH_MAC,
        EVPN_CMD_ADD_IMET,   EVPN_CMD_DEL_IMET,   EVPN_CMD_LIST_IMET,
        EVPN_CMD_ADD_PREFIX, EVPN_CMD_DEL_PREFIX,
        EVPN_CMD_LIST_PREFIXES, EVPN_CMD_LOOKUP_PREFIX,
        EVPN_CMD_ADD_ES,     EVPN_CMD_DEL_ES,     EVPN_CMD_LIST_ES,
        EVPN_CMD_GET_STATS,  EVPN_CMD_CLEAR_STATS,
        EVPN_CMD_DUMP_CONFIG, EVPN_CMD_LOAD_CONFIG);
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
