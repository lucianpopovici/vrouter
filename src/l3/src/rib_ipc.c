#include "rib_ipc.h"
#include "rib.h"
#include "fib.h"
#include "fib_cli.h"
#include <vrouter/json.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <arpa/inet.h>

#define IPC_BUF_SZ     4096
#define IPC_RESP_SZ   16384


/* ─── FIB push callback ─────────────────────────────────────── *
 * Called by rib_add/rib_del when the best route changes.        *
 * Pushes the winner (or withdrawal) directly into the FIB.      */
static void push_to_fib(const rib_entry_t *entry,
                        const rib_candidate_t *best,
                        int install, void *ctx)
{
    fib_table_t *fib = (fib_table_t *)ctx;

    /* build prefix CIDR string */
    struct in_addr pfx_in = { htonl(entry->prefix) };
    char pfx_s[INET_ADDRSTRLEN + 4];
    char addr_s[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pfx_in, addr_s, sizeof(addr_s));
    snprintf(pfx_s, sizeof(pfx_s), "%s/%u", addr_s, entry->prefix_len);

    struct in_addr nh_in = { htonl(best->nexthop) };
    char nh_s[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &nh_in, nh_s, sizeof(nh_s));

    if (install) {
        uint32_t flags = FIB_FLAG_STATIC;
        if (best->source == RIB_SRC_CONNECTED) flags = FIB_FLAG_CONNECTED;
        fib_add(fib, pfx_s, nh_s, best->iface, best->metric, flags);
        fprintf(stderr, "[ribd] → FIB install %s via %s (%s ad=%u)\n",
                pfx_s, nh_s, RIB_SRC_NAME[best->source], best->admin_dist);
    } else {
        fib_del(fib, pfx_s);
        fprintf(stderr, "[ribd] → FIB withdraw %s\n", pfx_s);
    }
}

/* ─── Handle one JSON command ───────────────────────────────── */
static void handle_cmd(rib_table_t *rib, fib_table_t *fib,
                       const char *req, char *resp, size_t rsz)
{
    char cmd[32] = {0};
    vr_json_get_str(req, "cmd", cmd, sizeof(cmd));

    /* ── route add ──────────────────────────────────────────── */
    if (strcmp(cmd, "add") == 0) {
        char prefix[32]={0}, nexthop[16]={0}, iface[16]={0};
        char metric_s[16]={0}, source_s[16]={0}, ad_s[8]={0};
        vr_json_get_str(req, "prefix",  prefix,  sizeof(prefix));
        vr_json_get_str(req, "nexthop", nexthop, sizeof(nexthop));
        vr_json_get_str(req, "iface",   iface,   sizeof(iface));
        vr_json_get_str(req, "metric",  metric_s,sizeof(metric_s));
        vr_json_get_str(req, "source",  source_s,sizeof(source_s));
        vr_json_get_str(req, "ad",      ad_s,    sizeof(ad_s));

        uint32_t     metric = metric_s[0] ? (uint32_t)atoi(metric_s) : 1;
        rib_source_t src    = (rib_source_t)rib_source_from_str(source_s);
        uint8_t      ad     = ad_s[0] ? (uint8_t)atoi(ad_s) : 0;
        if (!iface[0]) strncpy(iface, "unknown", sizeof(iface)-1);

        int rc = rib_add(rib, prefix, nexthop, iface, metric, src, ad,
                         push_to_fib, fib);
        if (rc == 0)
            snprintf(resp, rsz,
                "{\"status\": \"ok\","
                " \"msg\": \"rib route %s (%s) added\"}", prefix, source_s);
        else
            snprintf(resp, rsz,
                "{\"status\": \"error\", \"msg\": \"rib_add failed: %d\"}", rc);

    /* ── route del ──────────────────────────────────────────── */
    } else if (strcmp(cmd, "del") == 0) {
        char prefix[32]={0}, nexthop[16]={0}, source_s[16]={0};
        vr_json_get_str(req, "prefix",  prefix,  sizeof(prefix));
        vr_json_get_str(req, "nexthop", nexthop, sizeof(nexthop));
        vr_json_get_str(req, "source",  source_s,sizeof(source_s));

        rib_source_t src = (rib_source_t)rib_source_from_str(source_s);
        int rc = rib_del(rib, prefix, nexthop[0] ? nexthop : NULL,
                         src, push_to_fib, fib);
        if (rc == 0)
            snprintf(resp, rsz,
                "{\"status\": \"ok\","
                " \"msg\": \"rib route %s (%s) deleted\"}", prefix, source_s);
        else
            snprintf(resp, rsz,
                "{\"status\": \"error\", \"msg\": \"route not found\"}");

    /* ── show all RIB entries (walk hash buckets) ───────────── */
    } else if (strcmp(cmd, "show") == 0) {
        char source_filter[16] = {0};
        vr_json_get_str(req, "source", source_filter, sizeof(source_filter));
        rib_source_t src_f = RIB_SRC_UNKNOWN;
        if (source_filter[0])
            src_f = (rib_source_t)rib_source_from_str(source_filter);

        size_t pos = 0;
        int need_comma = 0;
        pos += (size_t)snprintf(resp+pos, rsz-pos,
            "{\"status\": \"ok\", \"count\": %d, \"routes\": [", rib->count);

        for (uint32_t _b = 0; _b < rib->n_buckets && pos < rsz-512; _b++) {
            const rib_entry_t *e = rib->buckets[_b];
            while (e && pos < rsz-512) {
                struct in_addr pi = { htonl(e->prefix) };
                char ps[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &pi, ps, sizeof(ps));

                if (need_comma && pos < rsz-2) resp[pos++] = ',';
                need_comma = 1;
                pos += (size_t)snprintf(resp+pos, rsz-pos,
                    "{\"prefix\": \"%s/%u\", \"candidates\": [",
                    ps, e->prefix_len);

                int first = 1;
                for (int j = 0; j < e->n_candidates && pos < rsz-256; j++) {
                    const rib_candidate_t *c = &e->candidates[j];
                    if (src_f != RIB_SRC_UNKNOWN && c->source != src_f) continue;
                    struct in_addr ni = { htonl(c->nexthop) };
                    char ns[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ni, ns, sizeof(ns));
                    if (!first && pos < rsz-2) resp[pos++] = ',';
                    pos += (size_t)snprintf(resp+pos, rsz-pos,
                        "{\"nexthop\": \"%s\"," " \"iface\": \"%s\"," " \"source\": \"%s\"," " \"ad\": %u," " \"metric\": %u," " \"best\": %s}",
                        ns, c->iface, RIB_SRC_NAME[c->source],
                        c->admin_dist, c->metric,
                        c->active ? "true" : "false");
                    first = 0;
                }
                if (pos < rsz-4) { resp[pos++]=']'; resp[pos++]='}'; }
                e = e->next;
            }
        }
        if (pos < rsz-4) { resp[pos++]=']'; resp[pos++]='}'; resp[pos]='\0'; }

    /* ── show single prefix ─────────────────────────────────── */
    } else if (strcmp(cmd, "get") == 0) {
        char prefix[32] = {0};
        vr_json_get_str(req, "prefix", prefix, sizeof(prefix));
        rib_entry_t entry;
        if (rib_find(rib, prefix, &entry) != 0) {
            snprintf(resp, rsz,
                "{\"status\": \"miss\", \"prefix\": \"%s\"}", prefix);
            return;
        }
        struct in_addr pi = { htonl(entry.prefix) };
        char ps[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &pi, ps, sizeof(ps));
        size_t pos = 0;
        pos += (size_t)snprintf(resp+pos, rsz-pos,
            "{\"status\": \"ok\","
            " \"prefix\": \"%s/%u\","
            " \"candidates\": [", ps, entry.prefix_len);
        for (int j = 0; j < entry.n_candidates && pos < rsz - 256; j++) {
            const rib_candidate_t *c = &entry.candidates[j];
            struct in_addr ni = { htonl(c->nexthop) };
            char ns[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ni, ns, sizeof(ns));
            if (j > 0 && pos < rsz-2) resp[pos++] = ',';
            pos += (size_t)snprintf(resp+pos, rsz-pos,
                "{\"nexthop\": \"%s\","
                " \"iface\": \"%s\","
                " \"source\": \"%s\","
                " \"ad\": %u, \"metric\": %u, \"best\": %s}",
                ns, c->iface, RIB_SRC_NAME[c->source],
                c->admin_dist, c->metric,
                c->active ? "true" : "false");
        }
        if (pos < rsz - 3) { resp[pos++]=']'; resp[pos++]='}'; resp[pos]='\0'; }

    /* ── stats ──────────────────────────────────────────────── */
    } else if (strcmp(cmd, "stats") == 0) {
        snprintf(resp, rsz,
            "{\"status\": \"ok\","
            " \"prefixes\": %d,"
            " \"pool_used\": %u,"
            " \"pool_size\": %u,"
            " \"load_factor\": %.3f,"
            " \"collisions\": %llu,"
            " \"added\": %llu,"
            " \"deleted\": %llu,"
            " \"fib_updates\": %llu}",
            rib->count,
            rib->pool_used, rib->pool_size,
            rib_load_factor(rib),
            (unsigned long long)rib->n_collisions,
            (unsigned long long)rib->n_added,
            (unsigned long long)rib->n_deleted,
            (unsigned long long)rib->n_fib_updates);

    /* ── flush ──────────────────────────────────────────────── */
    } else if (strcmp(cmd, "flush") == 0) {
        pthread_rwlock_wrlock(&rib->lock);
        /* withdraw all active routes from FIB first */
        for (uint32_t _b = 0; _b < rib->n_buckets; _b++) {
            rib_entry_t *e = rib->buckets[_b];
            while (e) {
                const rib_candidate_t *b = rib_best(e);
                if (b) push_to_fib(e, b, 0, fib);
                e = e->next;
            }
            rib->buckets[_b] = NULL;
        }
        memset(rib->pool, 0, rib->pool_used * sizeof(rib_entry_t));
        rib->pool_used = 0;
        rib->count = 0;
        rib->free_list = NULL;
        pthread_rwlock_unlock(&rib->lock);
        snprintf(resp, rsz,
            "{\"status\": \"ok\", \"msg\": \"rib flushed\"}");

    /* ── ping ───────────────────────────────────────────────── */
    } else if (strcmp(cmd, "ping") == 0) {
        snprintf(resp, rsz,
            "{\"status\": \"ok\", \"msg\": \"pong\", \"module\": \"rib\"}");

    } else {
        snprintf(resp, rsz,
            "{\"status\": \"error\", \"msg\": \"unknown command: %s\"}", cmd);
    }
}

/* ─── IPC server ────────────────────────────────────────────── */
int rib_ipc_serve(rib_table_t *rib, fib_table_t *fib,
                  const char *sock_path, volatile int *running)
{
    unlink(sock_path);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("rib socket"); return -1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("rib bind"); close(srv); return -1;
    }
    if (listen(srv, 8) < 0) {
        perror("rib listen"); close(srv); return -1;
    }

    fprintf(stderr, "[ribd] IPC socket listening on %s\n", sock_path);

    char req[IPC_BUF_SZ];
    char resp[IPC_RESP_SZ];

    while (*running) {
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
            handle_cmd(rib, fib, req, resp, sizeof(resp));
            send(cli, resp, strlen(resp), 0);
        }
        close(cli);
    }

    close(srv);
    unlink(sock_path);
    return 0;
}
