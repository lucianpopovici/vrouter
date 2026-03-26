#include "fib_ipc.h"
#include "fib.h"
#include "fib_cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <arpa/inet.h>

#define IPC_BUF_SZ   4096
#define IPC_RESP_SZ  8192

/* ─── Tiny JSON builder helpers ─────────────────────────────── */
static int jstr(char *b, size_t sz, size_t *pos,
                const char *k, const char *v)
{
    int n = snprintf(b + *pos, sz - *pos, "\"%s\": \"%s\"", k, v);
    if (n < 0 || (size_t)n >= sz - *pos) return -1;
    *pos += (size_t)n;
    return 0;
}
static void jcomma(char *b, size_t sz, size_t *pos)
{
    if (*pos < sz - 2) { b[(*pos)++] = ','; b[(*pos)++] = ' '; }
}

/* ─── Simple JSON field extractor (reuse from fib_cli.c) ───── */
static int jget(const char *json, const char *key, char *buf, size_t sz)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < sz - 1) buf[i++] = *p++;
        buf[i] = '\0';
    } else {
        size_t i = 0;
        while (*p && *p != ',' && *p != '\n' && *p != '}' && i < sz - 1)
            buf[i++] = *p++;
        buf[i] = '\0';
        while (i > 0 && (buf[i-1]==' '||buf[i-1]=='\r')) buf[--i]='\0';
    }
    return 0;
}

/* ─── Handle one JSON command, write JSON response ──────────── */
static void handle_cmd(fib_table_t *fib, const char *req,
                       char *resp, size_t rsz)
{
    char cmd[32] = {0};
    jget(req, "cmd", cmd, sizeof(cmd));

    /* ── route add ──────────────────────────────────────────── */
    if (strcmp(cmd, "add") == 0) {
        char prefix[32]={0}, nexthop[16]={0}, iface[16]={0}, metric_s[16]={0};
        jget(req, "prefix",  prefix,  sizeof(prefix));
        jget(req, "nexthop", nexthop, sizeof(nexthop));
        jget(req, "iface",   iface,   sizeof(iface));
        jget(req, "metric",  metric_s,sizeof(metric_s));
        uint32_t metric = metric_s[0] ? (uint32_t)atoi(metric_s)
                                      : FIB_DEFAULT_METRIC;
        if (!iface[0]) strncpy(iface, "unknown", sizeof(iface)-1);

        int rc = fib_add(fib, prefix, nexthop, iface, metric, FIB_FLAG_STATIC);
        if (rc == 0)
            snprintf(resp, rsz,
                "{\"status\": \"ok\", \"msg\": \"route %s added\"}", prefix);
        else
            snprintf(resp, rsz,
                "{\"status\": \"error\", \"msg\": \"fib_add failed: %d\"}", rc);

    /* ── route del ──────────────────────────────────────────── */
    } else if (strcmp(cmd, "del") == 0) {
        char prefix[32] = {0};
        jget(req, "prefix", prefix, sizeof(prefix));
        int rc = fib_del(fib, prefix);
        if (rc == 0)
            snprintf(resp, rsz,
                "{\"status\": \"ok\", \"msg\": \"route %s deleted\"}", prefix);
        else
            snprintf(resp, rsz,
                "{\"status\": \"error\", \"msg\": \"route not found\"}");

    /* ── lookup ─────────────────────────────────────────────── */
    } else if (strcmp(cmd, "lookup") == 0) {
        char addr[16] = {0};
        jget(req, "addr", addr, sizeof(addr));
        const fib_entry_t *e = fib_lookup(fib, addr);
        if (e) {
            struct in_addr nh = { htonl(e->nexthop) };
            char nh_s[INET_ADDRSTRLEN];
            struct in_addr pfx = { htonl(e->prefix) };
            char pfx_s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &nh,  nh_s,  sizeof(nh_s));
            inet_ntop(AF_INET, &pfx, pfx_s, sizeof(pfx_s));
            snprintf(resp, rsz,
                "{\"status\": \"ok\", \"addr\": \"%s\","
                " \"prefix\": \"%s/%u\", \"nexthop\": \"%s\","
                " \"iface\": \"%s\", \"metric\": %u}",
                addr, pfx_s, e->prefix_len, nh_s, e->iface, e->metric);
        } else {
            snprintf(resp, rsz,
                "{\"status\": \"miss\", \"addr\": \"%s\"}", addr);
        }

    /* ── show ───────────────────────────────────────────────── */
    } else if (strcmp(cmd, "show") == 0) {
        size_t pos = 0;
        pos += (size_t)snprintf(resp + pos, rsz - pos,
            "{\"status\": \"ok\", \"count\": %d, \"routes\": [", fib->count);
        for (int i = 0; i < fib->count && pos < rsz - 256; i++) {
            const fib_entry_t *e = &fib->entries[i];
            struct in_addr pfx_in = { htonl(e->prefix) };
            struct in_addr nh_in  = { htonl(e->nexthop) };
            char ps[INET_ADDRSTRLEN], ns[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &pfx_in, ps, sizeof(ps));
            inet_ntop(AF_INET, &nh_in,  ns, sizeof(ns));
            if (i > 0 && pos < rsz - 2) resp[pos++] = ',';
            pos += (size_t)snprintf(resp + pos, rsz - pos,
                "{\"prefix\": \"%s/%u\", \"nexthop\": \"%s\","
                " \"iface\": \"%s\", \"metric\": %u, \"hits\": %llu}",
                ps, e->prefix_len, ns, e->iface, e->metric,
                (unsigned long long)e->hit_count);
        }
        if (pos < rsz - 4) { resp[pos++]=']'; resp[pos++]='}'; resp[pos]='\0'; }

    /* ── flush ──────────────────────────────────────────────── */
    } else if (strcmp(cmd, "flush") == 0) {
        fib_flush(fib);
        snprintf(resp, rsz, "{\"status\": \"ok\", \"msg\": \"fib flushed\"}");

    /* ── stats ──────────────────────────────────────────────── */
    } else if (strcmp(cmd, "stats") == 0) {
        snprintf(resp, rsz,
            "{\"status\": \"ok\","
            " \"routes\": %d, \"max_routes\": %u,"
            " \"total_lookups\": %llu, \"total_hits\": %llu}",
            fib->count, fib->max_routes,
            (unsigned long long)fib->total_lookups,
            (unsigned long long)fib->total_hits);

    /* ── get <key> ──────────────────────────────────────────── */
    } else if (strcmp(cmd, "get") == 0) {
        char key[64] = {0};
        jget(req, "key", key, sizeof(key));
        char val[64] = {0};
        if (strcmp(key, "MAX_ROUTES") == 0)
            snprintf(val, sizeof(val), "%u", fib->max_routes);
        else if (strcmp(key, "DEFAULT_METRIC") == 0)
            snprintf(val, sizeof(val), "%d", FIB_DEFAULT_METRIC);
        else {
            snprintf(resp, rsz,
                "{\"status\": \"error\", \"msg\": \"unknown key %s\"}", key);
            return;
        }
        size_t p = 0;
        p += (size_t)snprintf(resp+p, rsz-p, "{");
        jstr(resp, rsz, &p, "status", "ok");  jcomma(resp, rsz, &p);
        jstr(resp, rsz, &p, "key", key);      jcomma(resp, rsz, &p);
        jstr(resp, rsz, &p, "value", val);
        if (p < rsz - 2) { resp[p++]='}'; resp[p]='\0'; }

    /* ── set <key> <value> ──────────────────────────────────── */
    } else if (strcmp(cmd, "set") == 0) {
        char key[64]={0}, value[64]={0};
        jget(req, "key",   key,   sizeof(key));
        jget(req, "value", value, sizeof(value));
        if (strcmp(key, "MAX_ROUTES") == 0) {
            int v = atoi(value);
            if (v < 10 || v > 100000) {
                snprintf(resp, rsz,
                    "{\"status\": \"error\", \"msg\": \"MAX_ROUTES out of range\"}");
                return;
            }
            fib->max_routes = (uint32_t)v;
            cli_save_runtime_key(key, value);
        } else {
            snprintf(resp, rsz,
                "{\"status\": \"error\", \"msg\": \"unknown key %s\"}", key);
            return;
        }
        snprintf(resp, rsz,
            "{\"status\": \"ok\", \"msg\": \"%s set to %s\"}", key, value);

    /* ── ping ───────────────────────────────────────────────── */
    } else if (strcmp(cmd, "ping") == 0) {
        snprintf(resp, rsz,
            "{\"status\": \"ok\", \"msg\": \"pong\", \"module\": \"fib\"}");

    } else {
        snprintf(resp, rsz,
            "{\"status\": \"error\", \"msg\": \"unknown command: %s\"}", cmd);
    }
}

/* ─── IPC server (blocking, single-threaded) ────────────────── */
int ipc_serve(fib_table_t *fib, const char *sock_path, volatile int *running)
{
    /* remove stale socket */
    unlink(sock_path);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return -1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(srv); return -1;
    }
    if (listen(srv, 8) < 0) {
        perror("listen"); close(srv); return -1;
    }

    fprintf(stderr, "[fibd] IPC socket listening on %s\n", sock_path);

    char req[IPC_BUF_SZ];
    char resp[IPC_RESP_SZ];

    while (*running) {
        /* use select so we can check *running periodically */
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(srv, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        if (select(srv + 1, &rfds, NULL, NULL, &tv) <= 0) continue;

        int cli = accept(srv, NULL, NULL);
        if (cli < 0) continue;

        ssize_t n = recv(cli, req, sizeof(req) - 1, 0);
        if (n > 0) {
            req[n] = '\0';
            handle_cmd(fib, req, resp, sizeof(resp));
            send(cli, resp, strlen(resp), 0);
        }
        close(cli);
    }

    close(srv);
    unlink(sock_path);
    return 0;
}
