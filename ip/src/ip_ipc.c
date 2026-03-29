/*
 * ip_ipc.c — Unix domain socket IPC server for the IP module.
 *
 * All commands arrive as newline-terminated JSON objects.
 * Responses are newline-terminated JSON objects.
 * Pattern mirrors every other module in the project.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "ip.h"
#include "ip_ipc.h"

/* -----------------------------------------------------------------------
 * Tiny JSON builder helpers
 * --------------------------------------------------------------------- */
static char *ok_json(void)
{
    char *r = strdup("{\"status\":\"ok\"}\n");
    return r;
}

static char *err_json(const char *msg)
{
    char buf[512];
    snprintf(buf, sizeof(buf), "{\"status\":\"error\",\"message\":\"%s\"}\n", msg);
    return strdup(buf);
}

/* Extract a JSON string field — same logic as ip.c */
static const char *jstr(const char *line, const char *key, char *out, size_t olen)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *p = strstr(line, search);
    if (!p) return NULL;
    p += strlen(search);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < olen) out[i++] = *p++;
    out[i] = '\0';
    return out;
}

static long jint(const char *line, const char *key)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(line, search);
    if (!p) return -1;
    p += strlen(search);
    if (*p == '"') p++;
    return strtol(p, NULL, 10);
}

static bool jbool(const char *line, const char *key)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":true", key);
    return strstr(line, search) != NULL;
}

/* -----------------------------------------------------------------------
 * Command handlers
 * --------------------------------------------------------------------- */

static char *handle_add_addr(ip_ctx_t *ctx, const char *req)
{
    char pfx_str[INET6_ADDRSTRLEN + 4] = {0};
    long ifindex = jint(req, "ifindex");
    if (ifindex < 0 || !jstr(req, "prefix", pfx_str, sizeof(pfx_str)))
        return err_json("missing ifindex or prefix");

    ip_prefix_t pfx;
    if (ip_prefix_parse(pfx_str, &pfx) != IP_OK)
        return err_json("invalid prefix");

    uint32_t valid_lft = (uint32_t)jint(req, "valid_lft");
    uint32_t pref_lft  = (uint32_t)jint(req, "pref_lft");

    int rc = ip_addr_add(ctx, (uint32_t)ifindex, &pfx, valid_lft, pref_lft);
    if (rc == IP_ERR_EXISTS)  return err_json("address already exists");
    if (rc == IP_ERR_NOTFOUND) return err_json("interface not found");
    if (rc != IP_OK)           return err_json("failed to add address");
    return ok_json();
}

static char *handle_del_addr(ip_ctx_t *ctx, const char *req)
{
    char pfx_str[INET6_ADDRSTRLEN + 4] = {0};
    long ifindex = jint(req, "ifindex");
    if (ifindex < 0 || !jstr(req, "prefix", pfx_str, sizeof(pfx_str)))
        return err_json("missing ifindex or prefix");

    ip_prefix_t pfx;
    if (ip_prefix_parse(pfx_str, &pfx) != IP_OK)
        return err_json("invalid prefix");

    int rc = ip_addr_del(ctx, (uint32_t)ifindex, &pfx);
    return rc == IP_OK ? ok_json() : err_json("address not found");
}

static char *handle_list_addrs(ip_ctx_t *ctx, const char *req)
{
    long ifindex_filter = jint(req, "ifindex"); /* -1 = all */

    char *buf = malloc(IP_IPC_MAX_MSG);
    if (!buf) return err_json("out of memory");
    size_t pos = 0, left = IP_IPC_MAX_MSG;

    pos += snprintf(buf + pos, left - pos,
                    "{\"status\":\"ok\",\"addresses\":[");

    pthread_rwlock_rdlock(&ctx->if_table.lock);
    bool first = true;
    for (uint32_t i = 0; i < ctx->if_table.n_buckets; i++) {
        for (ip_interface_t *ifc = ctx->if_table.buckets[i]; ifc; ifc = ifc->next) {
            if (ifindex_filter >= 0 && (uint32_t)ifindex_filter != ifc->ifindex)
                continue;
            pthread_rwlock_rdlock(&ifc->lock);
            for (ip_if_addr_t *a = ifc->addrs; a; a = a->next) {
                char pfxstr[INET6_ADDRSTRLEN + 4];
                ip_prefix_to_str(&a->prefix, pfxstr, sizeof(pfxstr));
                pos += snprintf(buf + pos, left - pos,
                                "%s{\"ifindex\":%u,\"ifname\":\"%s\","
                                "\"prefix\":\"%s\","
                                "\"af\":%d,\"state\":%u,"
                                "\"valid_lft\":%u,\"pref_lft\":%u}",
                                first ? "" : ",",
                                ifc->ifindex, ifc->name, pfxstr,
                                a->prefix.addr.af, a->state,
                                a->valid_lft, a->pref_lft);
                first = false;
                if (pos + 128 >= IP_IPC_MAX_MSG) break;
            }
            pthread_rwlock_unlock(&ifc->lock);
        }
    }
    pthread_rwlock_unlock(&ctx->if_table.lock);

    snprintf(buf + pos, left - pos, "]}\n");
    return buf;
}

static char *handle_list_interfaces(ip_ctx_t *ctx)
{
    char *buf = malloc(IP_IPC_MAX_MSG);
    if (!buf) return err_json("out of memory");
    size_t pos = 0, left = IP_IPC_MAX_MSG;

    pos += snprintf(buf + pos, left - pos,
                    "{\"status\":\"ok\",\"interfaces\":[");

    pthread_rwlock_rdlock(&ctx->if_table.lock);
    bool first = true;
    for (uint32_t i = 0; i < ctx->if_table.n_buckets; i++) {
        for (ip_interface_t *ifc = ctx->if_table.buckets[i]; ifc; ifc = ifc->next) {
            pthread_rwlock_rdlock(&ifc->lock);
            pos += snprintf(buf + pos, left - pos,
                            "%s{\"name\":\"%s\",\"ifindex\":%u,"
                            "\"flags\":%u,\"mtu\":%u,"
                            "\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
                            "\"ip4_fwd\":%s,\"ip6_fwd\":%s,"
                            "\"n_addrs\":%u,"
                            "\"rx_pkts\":%llu,\"tx_pkts\":%llu}",
                            first ? "" : ",",
                            ifc->name, ifc->ifindex,
                            ifc->flags, ifc->mtu,
                            ifc->mac[0], ifc->mac[1], ifc->mac[2],
                            ifc->mac[3], ifc->mac[4], ifc->mac[5],
                            ifc->ip4_fwd ? "true" : "false",
                            ifc->ip6_fwd ? "true" : "false",
                            ifc->n_addrs,
                            (unsigned long long)ifc->rx_pkts,
                            (unsigned long long)ifc->tx_pkts);
            first = false;
            pthread_rwlock_unlock(&ifc->lock);
        }
    }
    pthread_rwlock_unlock(&ctx->if_table.lock);

    snprintf(buf + pos, left - pos, "]}\n");
    return buf;
}

static char *handle_add_route(ip_ctx_t *ctx, const char *req)
{
    char pfx_str[INET6_ADDRSTRLEN + 4] = {0};
    char nh_str[INET6_ADDRSTRLEN]      = {0};
    if (!jstr(req, "prefix", pfx_str, sizeof(pfx_str)))
        return err_json("missing prefix");

    ip_prefix_t pfx;
    if (ip_prefix_parse(pfx_str, &pfx) != IP_OK)
        return err_json("invalid prefix");

    ip_addr_t nh = {0};
    if (jstr(req, "nexthop", nh_str, sizeof(nh_str)))
        ip_addr_parse(nh_str, &nh);
    else
        nh.af = pfx.addr.af;   /* on-link — nexthop == destination */

    uint32_t oif    = (uint32_t)jint(req, "ifindex");
    uint8_t  ad     = (uint8_t) jint(req, "ad");
    long     metric_l = jint(req, "metric");
    uint32_t metric = metric_l >= 0 ? (uint32_t)metric_l : 0;

    int rc = ip_fwd_add(ctx, &pfx, &nh, oif, ad, metric);
    return rc == IP_OK ? ok_json() : err_json("failed to add route");
}

static char *handle_del_route(ip_ctx_t *ctx, const char *req)
{
    char pfx_str[INET6_ADDRSTRLEN + 4] = {0};
    if (!jstr(req, "prefix", pfx_str, sizeof(pfx_str)))
        return err_json("missing prefix");
    ip_prefix_t pfx;
    if (ip_prefix_parse(pfx_str, &pfx) != IP_OK)
        return err_json("invalid prefix");
    int rc = ip_fwd_del(ctx, &pfx);
    return rc == IP_OK ? ok_json() : err_json("route not found");
}

static char *handle_list_routes(ip_ctx_t *ctx, const char *req)
{
    char af_str[8] = {0};
    jstr(req, "af", af_str, sizeof(af_str));
    sa_family_t af_filter = 0;
    if (strcmp(af_str, "ipv4") == 0) af_filter = AF_INET;
    if (strcmp(af_str, "ipv6") == 0) af_filter = AF_INET6;

    char *buf = malloc(IP_IPC_MAX_MSG);
    if (!buf) return err_json("out of memory");
    size_t pos = 0, left = IP_IPC_MAX_MSG;

    pos += snprintf(buf + pos, left - pos,
                    "{\"status\":\"ok\",\"routes\":[");

    bool first = true;
    for (int a = 0; a < 2; a++) {
        ip_fwd_table_t *t = a == 0 ? &ctx->fwd4 : &ctx->fwd6;
        sa_family_t taf   = a == 0 ? AF_INET : AF_INET6;
        if (af_filter && af_filter != taf) continue;

        pthread_rwlock_rdlock(&t->lock);
        for (uint32_t i = 0; i < t->n_buckets; i++) {
            for (ip_fwd_entry_t *e = t->buckets[i]; e; e = e->next) {
                char pfxstr[INET6_ADDRSTRLEN + 4];
                char nhstr[INET6_ADDRSTRLEN]  = "";
                ip_prefix_to_str(&e->prefix, pfxstr, sizeof(pfxstr));
                ip_addr_to_str(&e->nexthop, nhstr, sizeof(nhstr));
                pos += snprintf(buf + pos, left - pos,
                                "%s{\"prefix\":\"%s\",\"nexthop\":\"%s\","
                                "\"ifindex\":%u,\"ad\":%u,\"metric\":%u,"
                                "\"hits\":%llu}",
                                first ? "" : ",",
                                pfxstr, nhstr, e->out_ifindex,
                                e->ad, e->metric,
                                (unsigned long long)e->hit_count);
                first = false;
                if (pos + 256 >= IP_IPC_MAX_MSG) break;
            }
        }
        pthread_rwlock_unlock(&t->lock);
    }

    snprintf(buf + pos, left - pos, "]}\n");
    return buf;
}

static char *handle_lookup(ip_ctx_t *ctx, const char *req)
{
    char dst_str[INET6_ADDRSTRLEN] = {0};
    if (!jstr(req, "dst", dst_str, sizeof(dst_str)))
        return err_json("missing dst");
    ip_addr_t dst;
    if (ip_addr_parse(dst_str, &dst) != IP_OK)
        return err_json("invalid dst");

    ip_fwd_entry_t result;
    if (ip_fwd_lookup(ctx, &dst, &result) != IP_OK)
        return err_json("no route");

    char pfxstr[INET6_ADDRSTRLEN + 4];
    char nhstr[INET6_ADDRSTRLEN];
    ip_prefix_to_str(&result.prefix, pfxstr, sizeof(pfxstr));
    ip_addr_to_str(&result.nexthop, nhstr, sizeof(nhstr));

    char *buf = malloc(512);
    if (!buf) return err_json("out of memory");
    snprintf(buf, 512,
             "{\"status\":\"ok\",\"prefix\":\"%s\",\"nexthop\":\"%s\","
             "\"ifindex\":%u,\"ad\":%u,\"metric\":%u}\n",
             pfxstr, nhstr, result.out_ifindex, result.ad, result.metric);
    return buf;
}

static char *handle_set_forwarding(ip_ctx_t *ctx, const char *req)
{
    char af_str[8] = {0};
    jstr(req, "af", af_str, sizeof(af_str));
    sa_family_t af = strcmp(af_str, "ipv6") == 0 ? AF_INET6 : AF_INET;
    bool enable = jbool(req, "enable");
    ip_set_forwarding(ctx, af, enable);
    return ok_json();
}

static char *handle_get_forwarding(ip_ctx_t *ctx)
{
    bool v4 = ip_get_forwarding(ctx, AF_INET);
    bool v6 = ip_get_forwarding(ctx, AF_INET6);
    pthread_rwlock_rdlock(&ctx->cfg.lock);
    uint32_t flags = ctx->cfg.flags;
    uint8_t  ttl   = ctx->cfg.default_ttl;
    uint8_t  hl    = ctx->cfg.default_hop_limit;
    pthread_rwlock_unlock(&ctx->cfg.lock);

    char *buf = malloc(512);
    if (!buf) return err_json("out of memory");
    snprintf(buf, 512,
             "{\"status\":\"ok\","
             "\"ipv4_forwarding\":%s,"
             "\"ipv6_forwarding\":%s,"
             "\"flags\":%u,"
             "\"default_ttl\":%u,"
             "\"default_hop_limit\":%u}\n",
             v4 ? "true" : "false",
             v6 ? "true" : "false",
             flags, ttl, hl);
    return buf;
}

static char *handle_get_stats(ip_ctx_t *ctx, const char *req)
{
    char af_str[8] = {0};
    jstr(req, "af", af_str, sizeof(af_str));
    sa_family_t af = strcmp(af_str, "ipv6") == 0 ? AF_INET6 : AF_INET;
    ip_stats_t s;
    ip_stats_get(ctx, af, &s);

    char *buf = malloc(1024);
    if (!buf) return err_json("out of memory");
    snprintf(buf, 1024,
             "{\"status\":\"ok\",\"af\":\"%s\","
             "\"rx_pkts\":%llu,\"tx_pkts\":%llu,\"fwd_pkts\":%llu,"
             "\"rx_bytes\":%llu,\"tx_bytes\":%llu,"
             "\"rx_drop_ttl\":%llu,\"rx_drop_noroute\":%llu,"
             "\"rx_drop_martian\":%llu,\"rx_drop_rpf\":%llu,"
             "\"rx_errors\":%llu,\"tx_errors\":%llu,"
             "\"icmp_redirects_sent\":%llu,\"icmp_unreach_sent\":%llu}\n",
             af == AF_INET ? "ipv4" : "ipv6",
             (unsigned long long)s.rx_pkts,
             (unsigned long long)s.tx_pkts,
             (unsigned long long)s.fwd_pkts,
             (unsigned long long)s.rx_bytes,
             (unsigned long long)s.tx_bytes,
             (unsigned long long)s.rx_drop_ttl,
             (unsigned long long)s.rx_drop_noroute,
             (unsigned long long)s.rx_drop_martian,
             (unsigned long long)s.rx_drop_rpf,
             (unsigned long long)s.rx_errors,
             (unsigned long long)s.tx_errors,
             (unsigned long long)s.icmp_redirects_sent,
             (unsigned long long)s.icmp_unreach_sent);
    return buf;
}

static char *handle_set_if_fwd(ip_ctx_t *ctx, const char *req)
{
    long ifindex = jint(req, "ifindex");
    if (ifindex < 0) return err_json("missing ifindex");
    char af_str[8] = {0};
    jstr(req, "af", af_str, sizeof(af_str));
    sa_family_t af = strcmp(af_str, "ipv6") == 0 ? AF_INET6 : AF_INET;
    bool enable = jbool(req, "enable");
    int rc = ip_set_if_forwarding(ctx, (uint32_t)ifindex, af, enable);
    return rc == IP_OK ? ok_json() : err_json("interface not found");
}

static char *handle_dump_config(ip_ctx_t *ctx, const char *req)
{
    char path[256] = "ip_runtime_config.json";
    jstr(req, "path", path, sizeof(path));
    int rc = ip_save_config(ctx, path);
    if (rc != IP_OK) return err_json("failed to save config");
    char *buf = malloc(512);
    snprintf(buf, 512, "{\"status\":\"ok\",\"path\":\"%s\"}\n", path);
    return buf;
}

static char *handle_load_config(ip_ctx_t *ctx, const char *req)
{
    char path[256] = "ip_runtime_config.json";
    jstr(req, "path", path, sizeof(path));
    int rc = ip_load_config(ctx, path);
    return rc == IP_OK ? ok_json() : err_json("failed to load config");
}

/* -----------------------------------------------------------------------
 * Main dispatch
 * --------------------------------------------------------------------- */
char *ip_ipc_handle(ip_ctx_t *ctx, const char *req, size_t req_len)
{
    (void)req_len;
    char cmd[64] = {0};
    jstr(req, "cmd", cmd, sizeof(cmd));

    if (strcmp(cmd, IP_CMD_ADD_ADDR)    == 0) return handle_add_addr(ctx, req);
    if (strcmp(cmd, IP_CMD_DEL_ADDR)    == 0) return handle_del_addr(ctx, req);
    if (strcmp(cmd, IP_CMD_LIST_ADDRS)  == 0) return handle_list_addrs(ctx, req);
    if (strcmp(cmd, IP_CMD_LIST_IFS)    == 0) return handle_list_interfaces(ctx);
    if (strcmp(cmd, IP_CMD_ADD_ROUTE)   == 0) return handle_add_route(ctx, req);
    if (strcmp(cmd, IP_CMD_DEL_ROUTE)   == 0) return handle_del_route(ctx, req);
    if (strcmp(cmd, IP_CMD_LIST_ROUTES) == 0) return handle_list_routes(ctx, req);
    if (strcmp(cmd, IP_CMD_LOOKUP)      == 0) return handle_lookup(ctx, req);
    if (strcmp(cmd, IP_CMD_SET_FWD)     == 0) return handle_set_forwarding(ctx, req);
    if (strcmp(cmd, IP_CMD_GET_FWD)     == 0) return handle_get_forwarding(ctx);
    if (strcmp(cmd, IP_CMD_GET_STATS)   == 0) return handle_get_stats(ctx, req);
    if (strcmp(cmd, IP_CMD_CLEAR_STATS) == 0) {
        char af_str[8] = {0};
        jstr(req, "af", af_str, sizeof(af_str));
        sa_family_t af = strcmp(af_str, "ipv6") == 0 ? AF_INET6 : AF_INET;
        ip_stats_clear(ctx, af);
        return ok_json();
    }
    if (strcmp(cmd, IP_CMD_SET_IF_FWD)  == 0) return handle_set_if_fwd(ctx, req);
    if (strcmp(cmd, IP_CMD_DUMP_CONFIG) == 0) return handle_dump_config(ctx, req);
    if (strcmp(cmd, IP_CMD_LOAD_CONFIG) == 0) return handle_load_config(ctx, req);

    return err_json("unknown command");
}

/* -----------------------------------------------------------------------
 * IPC server thread
 * --------------------------------------------------------------------- */
int ip_ipc_init(ip_ctx_t *ctx)
{
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", ctx->sock_path);

    unlink(ctx->sock_path);
    ctx->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx->sock_fd < 0) return IP_ERR_INVAL;

    if (bind(ctx->sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(ctx->sock_fd, 16) < 0) {
        close(ctx->sock_fd);
        ctx->sock_fd = -1;
        return IP_ERR_INVAL;
    }
    return IP_OK;
}

void ip_ipc_stop(ip_ctx_t *ctx)
{
    if (ctx->sock_fd >= 0) {
        close(ctx->sock_fd);
        ctx->sock_fd = -1;
    }
    unlink(ctx->sock_path);
}

void *ip_ipc_thread(void *arg)
{
    ip_ctx_t *ctx = arg;
    char      buf[IP_IPC_MAX_MSG];

    while (ctx->running) {
        int client = accept(ctx->sock_fd, NULL, NULL);
        if (client < 0) {
            if (!ctx->running) break;
            continue;
        }

        ssize_t n = recv(client, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            char *resp = ip_ipc_handle(ctx, buf, (size_t)n);
            if (resp) {
                send(client, resp, strlen(resp), 0);
                free(resp);
            }
        }
        close(client);
    }
    return NULL;
}
