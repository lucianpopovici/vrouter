#include "fib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

/* ─── Init ──────────────────────────────────────────────────── */
void fib_init(fib_table_t *fib)
{
    memset(fib, 0, sizeof(*fib));
    fib->max_routes = FIB_MAX_ROUTES;
}

/* ─── Parse CIDR ("192.168.1.0/24") ────────────────────────── */
int fib_parse_cidr(const char *cidr, uint32_t *prefix, uint8_t *len)
{
    char buf[32];
    char *slash;

    if (!cidr || strlen(cidr) >= sizeof(buf)) return -1;
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf)-1] = '\0';

    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        int l = atoi(slash + 1);
        if (l < 0 || l > 32) return -1;
        *len = (uint8_t)l;
    } else {
        *len = 32;
    }

    struct in_addr in;
    if (inet_pton(AF_INET, buf, &in) != 1) return -1;
    *prefix = ntohl(in.s_addr);

    /* normalise: mask host bits */
    if (*len < 32)
        *prefix &= (0xFFFFFFFF << (32 - *len));

    return 0;
}

/* ─── Add / Update ──────────────────────────────────────────── */
int fib_add(fib_table_t *fib, const char *prefix_cidr,
            const char *nexthop_str, const char *iface,
            uint32_t metric, uint32_t flags)
{
    uint32_t pfx;  uint8_t len;
    if (fib_parse_cidr(prefix_cidr, &pfx, &len) != 0) return -EINVAL;

    struct in_addr nh_in;
    if (inet_pton(AF_INET, nexthop_str, &nh_in) != 1) return -EINVAL;
    uint32_t nh = ntohl(nh_in.s_addr);

    /* update existing entry? */
    for (int i = 0; i < fib->count; i++) {
        fib_entry_t *e = &fib->entries[i];
        if (e->prefix == pfx && e->prefix_len == len) {
            e->nexthop = nh;
            strncpy(e->iface, iface, FIB_IFACE_LEN - 1);
            e->metric  = metric;
            e->flags   = flags | FIB_FLAG_ACTIVE;
            return 0;
        }
    }

    if (fib->count >= (int)fib->max_routes) return -ENOMEM;

    fib_entry_t *e = &fib->entries[fib->count++];
    e->prefix     = pfx;
    e->prefix_len = len;
    e->nexthop    = nh;
    strncpy(e->iface, iface, FIB_IFACE_LEN - 1);
    e->metric     = metric;
    e->flags      = flags | FIB_FLAG_ACTIVE;
    e->hit_count  = 0;

    return 0;
}

/* ─── Delete ────────────────────────────────────────────────── */
int fib_del(fib_table_t *fib, const char *prefix_cidr)
{
    uint32_t pfx;  uint8_t len;
    if (fib_parse_cidr(prefix_cidr, &pfx, &len) != 0) return -EINVAL;

    for (int i = 0; i < fib->count; i++) {
        fib_entry_t *e = &fib->entries[i];
        if (e->prefix == pfx && e->prefix_len == len) {
            /* swap with last */
            if (i != fib->count - 1)
                fib->entries[i] = fib->entries[fib->count - 1];
            fib->count--;
            return 0;
        }
    }
    return -ENOENT;
}

/* ─── Longest-Prefix Match lookup ───────────────────────────── */
const fib_entry_t *fib_lookup(fib_table_t *fib, const char *addr_str)
{
    struct in_addr in;
    if (inet_pton(AF_INET, addr_str, &in) != 1) return NULL;
    uint32_t addr = ntohl(in.s_addr);

    fib->total_lookups++;

    fib_entry_t *best = NULL;
    for (int i = 0; i < fib->count; i++) {
        fib_entry_t *e = &fib->entries[i];
        if (!(e->flags & FIB_FLAG_ACTIVE)) continue;

        uint32_t mask = (e->prefix_len == 0) ? 0
                      : (0xFFFFFFFF << (32 - e->prefix_len));
        if ((addr & mask) == e->prefix) {
            if (!best || e->prefix_len > best->prefix_len ||
                (e->prefix_len == best->prefix_len &&
                 e->metric < best->metric))
                best = e;
        }
    }

    if (best) {
        best->hit_count++;
        fib->total_hits++;
    }
    return best;
}

/* ─── Flush ─────────────────────────────────────────────────── */
void fib_flush(fib_table_t *fib)
{
    fib->count = 0;
    fib->total_lookups = 0;
    fib->total_hits    = 0;
}

/* ─── Count ─────────────────────────────────────────────────── */
int fib_count(const fib_table_t *fib) { return fib->count; }

/* ─── Entry → readable string ───────────────────────────────── */
void fib_entry_to_str(const fib_entry_t *e, char *buf, size_t bufsz)
{
    struct in_addr pfx_in = { htonl(e->prefix) };
    struct in_addr nh_in  = { htonl(e->nexthop) };
    char pfx_s[INET_ADDRSTRLEN], nh_s[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pfx_in, pfx_s, sizeof(pfx_s));
    inet_ntop(AF_INET, &nh_in,  nh_s,  sizeof(nh_s));

    snprintf(buf, bufsz, "%s/%u via %s dev %s metric %u hits %llu",
             pfx_s, e->prefix_len, nh_s, e->iface, e->metric,
             (unsigned long long)e->hit_count);
}
