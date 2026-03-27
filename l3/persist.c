#include "persist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

/* ── tiny JSON field extractor (same pattern as ipc files) ──── */
static int jget(const char *json, const char *key, char *buf, size_t sz)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p == '"') {
        p++; size_t i = 0;
        while (*p && *p != '"' && i < sz-1) buf[i++] = *p++;
        buf[i] = '\0';
    } else {
        size_t i = 0;
        while (*p && *p != ',' && *p != '\n' && *p != '}' && i < sz-1)
            buf[i++] = *p++;
        buf[i] = '\0';
        while (i > 0 && (buf[i-1]==' '||buf[i-1]=='\r')) buf[--i]='\0';
    }
    return 0;
}

/* ── dump ────────────────────────────────────────────────────── */
int persist_dump(const rib_table_t *rib, const char *path)
{
    if (!path) path = L3_DUMP_FILE;

    /* write to a tmp file then rename for atomicity */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    FILE *f = fopen(tmp, "w");
    if (!f) return -errno;

    int written = 0;

    /* walk all RIB buckets */
    /* Best-effort snapshot: acquire read lock so dump is consistent
     * with concurrent rib_add/rib_del. The RIB IPC thread will block
     * on write operations while we read, which is acceptable for an
     * infrequent checkpoint triggered by SIGHUP or shutdown.         */
    pthread_rwlock_rdlock(&((rib_table_t*)rib)->lock);

    for (uint32_t b = 0; b < rib->n_buckets; b++) {
        const rib_entry_t *e = rib->buckets[b];
        while (e) {
            struct in_addr pfx_in = { htonl(e->prefix) };
            char pfx_s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &pfx_in, pfx_s, sizeof(pfx_s));

            for (int i = 0; i < e->n_candidates; i++) {
                const rib_candidate_t *c = &e->candidates[i];
                struct in_addr nh_in = { htonl(c->nexthop) };
                char nh_s[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &nh_in, nh_s, sizeof(nh_s));

                fprintf(f,
                    "{\"prefix\":\"%s/%u\","
                    "\"nexthop\":\"%s\","
                    "\"iface\":\"%s\","
                    "\"metric\":%u,"
                    "\"source\":\"%s\","
                    "\"ad\":%u}\n",
                    pfx_s, e->prefix_len,
                    nh_s, c->iface, c->metric,
                    RIB_SRC_NAME[c->source],
                    c->admin_dist);
                written++;
            }
            e = e->next;
        }
    }

    fclose(f);
    pthread_rwlock_unlock(&((rib_table_t*)rib)->lock);

    if (rename(tmp, path) != 0) {
        int err = errno;
        remove(tmp);
        return -err;
    }

    fprintf(stderr, "[persist] dumped %d candidates to %s\n", written, path);
    return written;
}

/* ── restore ─────────────────────────────────────────────────── */
int persist_restore(rib_table_t *rib, rib_fib_cb cb, void *cb_ctx,
                    const char *path)
{
    if (!path) path = L3_DUMP_FILE;

    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 0;  /* no dump yet, that's fine */
        return -errno;
    }

    char line[512];
    int  restored = 0;

    while (fgets(line, sizeof(line), f)) {
        /* strip newline */
        size_t ln = strlen(line);
        while (ln > 0 && (line[ln-1]=='\n'||line[ln-1]=='\r'))
            line[--ln] = '\0';
        if (!ln || line[0] != '{') continue;

        char prefix[48]={0}, nexthop[20]={0}, iface[16]={0};
        char metric_s[16]={0}, source_s[16]={0}, ad_s[8]={0};

        jget(line, "prefix",  prefix,  sizeof(prefix));
        jget(line, "nexthop", nexthop, sizeof(nexthop));
        jget(line, "iface",   iface,   sizeof(iface));
        jget(line, "metric",  metric_s,sizeof(metric_s));
        jget(line, "source",  source_s,sizeof(source_s));
        jget(line, "ad",      ad_s,    sizeof(ad_s));

        if (!prefix[0] || !nexthop[0]) continue;

        uint32_t     metric = metric_s[0] ? (uint32_t)atoi(metric_s) : 1;
        rib_source_t src    = (rib_source_t)rib_source_from_str(source_s);
        uint8_t      ad     = ad_s[0] ? (uint8_t)atoi(ad_s) : 0;
        if (!iface[0]) strncpy(iface, "unknown", sizeof(iface)-1);

        int rc = rib_add(rib, prefix, nexthop, iface, metric, src, ad,
                         cb, cb_ctx);
        if (rc == 0) restored++;
    }

    fclose(f);
    fprintf(stderr, "[persist] restored %d candidates from %s\n",
            restored, path);
    return restored;
}
