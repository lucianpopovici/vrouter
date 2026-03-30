/*
 * evpn.c — BGP EVPN module core (RFC 7432 / RFC 8365)
 *
 * Implements:
 *   RT-2  MAC/IP advertisement table (per-EVI, FNV-1a hash on MAC+IP)
 *   RT-3  IMET flood list (per-EVI linked list of remote VTEPs)
 *   RT-4  Ethernet Segment table (global)
 *   RT-5  IP-prefix table (per-EVI, FNV-1a hash on prefix, LPM lookup)
 *
 * RT-1 (EAD) is represented implicitly by VTEP + ES state; generating
 * actual BGP UPDATE PDUs is outside this module's scope (that belongs
 * to a BGP speaker that calls these APIs).
 *
 * Locking:
 *   evpn_evi_table.lock  — global EVI hash table
 *   evpn_vtep_table.lock — global VTEP hash table
 *   evpn_ctx.es_lock     — global ES list
 *   evpn_evi.lock        — per-EVI IMET list + stats
 *   evpn_mac_table.lock  — per-EVI MAC-IP table
 *   evpn_prefix_table.lock — per-EVI prefix table
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "evpn.h"
#include "evpn_ipc.h"
#include <vrouter/json.h>

/* -----------------------------------------------------------------------
 * FNV-1a (using shared vr_fnv1a from <vrouter/hash.h>)
 * --------------------------------------------------------------------- */
#include <vrouter/hash.h>

uint32_t evpn_fnv1a_mac(const evpn_mac_t *mac, uint32_t n)
{ return vr_fnv1a_mod(mac->b, 6, n); }

uint32_t evpn_fnv1a_addr(const evpn_addr_t *a, uint32_t n)
{
    if (a->af == AF_INET)  return vr_fnv1a_mod((const uint8_t *)&a->u.v4,  4, n);
    if (a->af == AF_INET6) return vr_fnv1a_mod((const uint8_t *)&a->u.v6, 16, n);
    return 0;
}

uint32_t evpn_fnv1a_prefix(const evpn_prefix_t *p, uint32_t n)
{
    uint8_t buf[17]; size_t al = p->addr.af == AF_INET ? 4 : 16;
    if (p->addr.af == AF_INET) memcpy(buf, &p->addr.u.v4, 4);
    else                       memcpy(buf, &p->addr.u.v6, 16);
    buf[al] = p->plen;
    return vr_fnv1a_mod(buf, al + 1, n);
}

/* Hash key for MAC-IP entries: MAC + IP (zero IP = pure-MAC) */
static uint32_t mac_ip_hash(const evpn_mac_t *mac, const evpn_addr_t *ip,
                            uint32_t n)
{
    uint8_t buf[22]; /* 6 + 16 max */
    memcpy(buf, mac->b, 6);
    size_t iplen = 0;
    if (ip && ip->af == AF_INET)  { memcpy(buf + 6, &ip->u.v4,  4); iplen = 4; }
    if (ip && ip->af == AF_INET6) { memcpy(buf + 6, &ip->u.v6, 16); iplen = 16; }
    return vr_fnv1a_mod(buf, 6 + iplen, n);
}

/* -----------------------------------------------------------------------
 * Address helpers
 * --------------------------------------------------------------------- */
int evpn_addr_parse(const char *s, evpn_addr_t *out)
{
    if (!s || !out) return EVPN_ERR_INVAL;
    if (inet_pton(AF_INET,  s, &out->u.v4) == 1) { out->af = AF_INET;  return EVPN_OK; }
    if (inet_pton(AF_INET6, s, &out->u.v6) == 1) { out->af = AF_INET6; return EVPN_OK; }
    return EVPN_ERR_INVAL;
}

int evpn_prefix_parse(const char *s, evpn_prefix_t *out)
{
    if (!s || !out) return EVPN_ERR_INVAL;
    char buf[INET6_ADDRSTRLEN + 4];
    strncpy(buf, s, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0';
    char *sl = strchr(buf, '/'); int plen = -1;
    if (sl) { *sl = '\0'; plen = atoi(sl + 1); }
    if (evpn_addr_parse(buf, &out->addr) != EVPN_OK) return EVPN_ERR_INVAL;
    uint8_t maxp = out->addr.af == AF_INET ? 32 : 128;
    out->plen = (uint8_t)(plen >= 0 && plen <= maxp ? plen : maxp);
    return EVPN_OK;
}

void evpn_addr_to_str(const evpn_addr_t *a, char *buf, size_t len)
{
    if (a->af == AF_INET) inet_ntop(AF_INET,  &a->u.v4, buf, len);
    else                  inet_ntop(AF_INET6, &a->u.v6, buf, len);
}

void evpn_prefix_to_str(const evpn_prefix_t *p, char *buf, size_t len)
{
    char ab[INET6_ADDRSTRLEN]; evpn_addr_to_str(&p->addr, ab, sizeof(ab));
    snprintf(buf, len, "%s/%u", ab, p->plen);
}

bool evpn_prefix_contains(const evpn_prefix_t *pfx, const evpn_addr_t *addr)
{
    if (pfx->addr.af != addr->af) return false;
    uint8_t pl = pfx->plen;
    if (addr->af == AF_INET) {
        uint32_t mask = pl ? htonl(~0u << (32 - pl)) : 0;
        return (addr->u.v4.s_addr & mask) == (pfx->addr.u.v4.s_addr & mask);
    }
    uint8_t full = pl / 8, rem = pl % 8;
    const uint8_t *a = addr->u.v6.s6_addr, *p = pfx->addr.u.v6.s6_addr;
    if (memcmp(a, p, full) != 0) return false;
    if (!rem) return true;
    uint8_t m = (uint8_t)(0xffu << (8 - rem));
    return (a[full] & m) == (p[full] & m);
}

int evpn_mac_parse(const char *str, evpn_mac_t *out)
{
    if (!str || !out) return EVPN_ERR_INVAL;
    if (sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out->b[0],&out->b[1],&out->b[2],
               &out->b[3],&out->b[4],&out->b[5]) == 6)
        return EVPN_OK;
    return EVPN_ERR_INVAL;
}

void evpn_mac_to_str(const evpn_mac_t *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->b[0],mac->b[1],mac->b[2],mac->b[3],mac->b[4],mac->b[5]);
}

int evpn_esi_parse(const char *str, evpn_esi_t *out)
{
    if (!str || !out) return EVPN_ERR_INVAL;
    /* Format: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx */
    if (sscanf(str,
               "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out->b[0],&out->b[1],&out->b[2],&out->b[3],&out->b[4],
               &out->b[5],&out->b[6],&out->b[7],&out->b[8],&out->b[9]) == 10)
        return EVPN_OK;
    return EVPN_ERR_INVAL;
}

void evpn_esi_to_str(const evpn_esi_t *esi, char *buf, size_t len)
{
    snprintf(buf, len,
             "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             esi->b[0],esi->b[1],esi->b[2],esi->b[3],esi->b[4],
             esi->b[5],esi->b[6],esi->b[7],esi->b[8],esi->b[9]);
}

uint64_t evpn_rd_make(uint32_t asn, uint16_t local)
{ return ((uint64_t)asn << 16) | local; }

uint64_t evpn_rt_make(uint32_t asn, uint16_t local)
{ return ((uint64_t)asn << 16) | local; }

void evpn_rd_to_str(uint64_t rd, char *buf, size_t len)
{ snprintf(buf, len, "%u:%u", (uint32_t)(rd >> 16), (uint32_t)(rd & 0xffffu)); }

static bool addr_eq(const evpn_addr_t *a, const evpn_addr_t *b)
{
    if (a->af != b->af) return false;
    if (a->af == AF_INET)  return a->u.v4.s_addr == b->u.v4.s_addr;
    if (a->af == AF_INET6) return memcmp(&a->u.v6, &b->u.v6, 16) == 0;
    return a->af == b->af; /* both AF_UNSPEC */
}

static bool mac_eq(const evpn_mac_t *a, const evpn_mac_t *b)
{ return memcmp(a->b, b->b, 6) == 0; }

/* -----------------------------------------------------------------------
 * MAC table
 * --------------------------------------------------------------------- */
static int mac_table_init(evpn_mac_table_t *t)
{
    t->n_buckets = EVPN_MAC_BUCKETS;
    t->buckets   = calloc(t->n_buckets, sizeof(*t->buckets));
    if (!t->buckets) return EVPN_ERR_NOMEM;
    t->n_entries = 0;
    return pthread_rwlock_init(&t->lock, NULL) ? EVPN_ERR_NOMEM : EVPN_OK;
}

static void mac_table_destroy(evpn_mac_table_t *t)
{
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        evpn_mac_ip_t *c = t->buckets[i];
        while (c) { evpn_mac_ip_t *n = c->next; free(c); c = n; }
    }
    free(t->buckets); pthread_rwlock_destroy(&t->lock);
}

/* -----------------------------------------------------------------------
 * Prefix table
 * --------------------------------------------------------------------- */
static int pfx_table_init(evpn_prefix_table_t *t)
{
    t->n_buckets = EVPN_PFX_BUCKETS;
    t->buckets   = calloc(t->n_buckets, sizeof(*t->buckets));
    if (!t->buckets) return EVPN_ERR_NOMEM;
    t->n_entries = 0;
    return pthread_rwlock_init(&t->lock, NULL) ? EVPN_ERR_NOMEM : EVPN_OK;
}

static void pfx_table_destroy(evpn_prefix_table_t *t)
{
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        evpn_ip_prefix_t *c = t->buckets[i];
        while (c) { evpn_ip_prefix_t *n = c->next; free(c); c = n; }
    }
    free(t->buckets); pthread_rwlock_destroy(&t->lock);
}

static evpn_ip_prefix_t *pfx_find_locked(evpn_prefix_table_t *t,
                                         const evpn_prefix_t *pfx)
{
    uint32_t b = evpn_fnv1a_prefix(pfx, t->n_buckets);
    for (evpn_ip_prefix_t *e = t->buckets[b]; e; e = e->next) {
        if (e->prefix.plen == pfx->plen &&
            e->prefix.addr.af == pfx->addr.af &&
            addr_eq(&e->prefix.addr, &pfx->addr))
            return e;
    }
    return NULL;
}

/* -----------------------------------------------------------------------
 * VTEP table
 * --------------------------------------------------------------------- */
static int vtep_table_init(evpn_vtep_table_t *t)
{
    t->n_buckets = EVPN_VTEP_BUCKETS;
    t->buckets   = calloc(t->n_buckets, sizeof(*t->buckets));
    if (!t->buckets) return EVPN_ERR_NOMEM;
    t->n_vteps = 0;
    return pthread_rwlock_init(&t->lock, NULL) ? EVPN_ERR_NOMEM : EVPN_OK;
}

static void vtep_table_destroy(evpn_vtep_table_t *t)
{
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        evpn_vtep_t *c = t->buckets[i];
        while (c) { evpn_vtep_t *n = c->next; free(c); c = n; }
    }
    free(t->buckets); pthread_rwlock_destroy(&t->lock);
}

/* -----------------------------------------------------------------------
 * EVI table
 * --------------------------------------------------------------------- */
static int evi_table_init(evpn_evi_table_t *t)
{
    t->n_buckets = EVPN_EVI_BUCKETS;
    t->buckets   = calloc(t->n_buckets, sizeof(*t->buckets));
    if (!t->buckets) return EVPN_ERR_NOMEM;
    t->n_evis = 0;
    return pthread_rwlock_init(&t->lock, NULL) ? EVPN_ERR_NOMEM : EVPN_OK;
}

static void evi_table_destroy(evpn_evi_table_t *t)
{
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        evpn_evi_t *c = t->buckets[i];
        while (c) {
            evpn_evi_t *n = c->next;
            mac_table_destroy(&c->mac_table);
            pfx_table_destroy(&c->pfx_table);
            evpn_imet_t *im = c->imet_list;
            while (im) { evpn_imet_t *ni = im->next; free(im); im = ni; }
            pthread_rwlock_destroy(&c->lock);
            free(c); c = n;
        }
    }
    free(t->buckets); pthread_rwlock_destroy(&t->lock);
}

static uint32_t evi_bucket(const evpn_evi_table_t *t, uint32_t id)
{
    return vr_fnv1a_mod((const uint8_t *)&id, sizeof(id), t->n_buckets);
}

/* -----------------------------------------------------------------------
 * EVI API
 * --------------------------------------------------------------------- */
int evpn_evi_create(evpn_ctx_t *ctx, uint32_t evi_id,
                    uint32_t l2_vni, uint32_t l3_vni,
                    uint32_t vrf_id, uint32_t flags)
{
    if (!ctx || evi_id == 0) return EVPN_ERR_INVAL;
    if (l2_vni < EVPN_VNI_MIN || l2_vni > EVPN_VNI_MAX) return EVPN_ERR_INVAL;

    evpn_evi_table_t *t = &ctx->evi_table;
    uint32_t b = evi_bucket(t, evi_id);
    int rc = EVPN_OK;

    pthread_rwlock_wrlock(&t->lock);
    for (evpn_evi_t *c = t->buckets[b]; c; c = c->next)
        if (c->evi_id == evi_id) { rc = EVPN_ERR_EXISTS; goto out; }

    if (t->n_evis >= EVPN_MAX_EVI) { rc = EVPN_ERR_FULL; goto out; }

    evpn_evi_t *e = calloc(1, sizeof(*e));
    if (!e) { rc = EVPN_ERR_NOMEM; goto out; }

    e->evi_id = evi_id; e->l2_vni = l2_vni; e->l3_vni = l3_vni;
    e->vrf_id = vrf_id; e->flags  = flags | EVPN_EVI_ACTIVE;
    e->encap  = EVPN_ENCAP_VXLAN;
    e->local_vtep_ip = ctx->local_vtep_ip;
    e->created_at = time(NULL);

    /* Auto-RD: ASN:evi_id */
    e->rd = evpn_rd_make(ctx->local_asn, (uint16_t)evi_id);
    /* Auto-RT for both export and import */
    uint64_t auto_rt = evpn_rt_make(ctx->local_asn, (uint16_t)l2_vni);
    e->rt_export[0] = auto_rt; e->n_rt_export = 1;
    e->rt_import[0] = auto_rt; e->n_rt_import = 1;

    if (mac_table_init(&e->mac_table) != EVPN_OK ||
        pfx_table_init(&e->pfx_table) != EVPN_OK ||
        pthread_rwlock_init(&e->lock, NULL)) {
        mac_table_destroy(&e->mac_table);
        pfx_table_destroy(&e->pfx_table);
        free(e); rc = EVPN_ERR_NOMEM; goto out;
    }

    e->next = t->buckets[b]; t->buckets[b] = e; t->n_evis++;

out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int evpn_evi_delete(evpn_ctx_t *ctx, uint32_t evi_id)
{
    if (!ctx) return EVPN_ERR_INVAL;
    evpn_evi_table_t *t = &ctx->evi_table;
    uint32_t b = evi_bucket(t, evi_id);
    int rc = EVPN_ERR_NOTFOUND;

    pthread_rwlock_wrlock(&t->lock);
    evpn_evi_t **pp = &t->buckets[b];
    while (*pp) {
        if ((*pp)->evi_id == evi_id) {
            evpn_evi_t *del = *pp; *pp = del->next;
            mac_table_destroy(&del->mac_table);
            pfx_table_destroy(&del->pfx_table);
            evpn_imet_t *im = del->imet_list;
            while (im) { evpn_imet_t *ni = im->next; free(im); im = ni; }
            pthread_rwlock_destroy(&del->lock);
            free(del); t->n_evis--; rc = EVPN_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

evpn_evi_t *evpn_evi_find(evpn_ctx_t *ctx, uint32_t evi_id)
{
    if (!ctx) return NULL;
    evpn_evi_table_t *t = &ctx->evi_table;
    uint32_t b = evi_bucket(t, evi_id);
    evpn_evi_t *found = NULL;
    pthread_rwlock_rdlock(&t->lock);
    for (evpn_evi_t *c = t->buckets[b]; c; c = c->next)
        if (c->evi_id == evi_id) { found = c; break; }
    pthread_rwlock_unlock(&t->lock);
    return found;
}

evpn_evi_t *evpn_evi_find_by_vni(evpn_ctx_t *ctx, uint32_t vni)
{
    if (!ctx || !vni) return NULL;
    evpn_evi_table_t *t = &ctx->evi_table;
    evpn_evi_t *found = NULL;
    pthread_rwlock_rdlock(&t->lock);
    for (uint32_t i = 0; i < t->n_buckets && !found; i++)
        for (evpn_evi_t *c = t->buckets[i]; c; c = c->next)
            if (c->l2_vni == vni || c->l3_vni == vni) { found = c; break; }
    pthread_rwlock_unlock(&t->lock);
    return found;
}

int evpn_evi_set_rd(evpn_ctx_t *ctx, uint32_t evi_id, uint64_t rd)
{
    evpn_evi_t *e = evpn_evi_find(ctx, evi_id);
    if (!e) return EVPN_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&e->lock); e->rd = rd; pthread_rwlock_unlock(&e->lock);
    return EVPN_OK;
}

int evpn_evi_add_rt(evpn_ctx_t *ctx, uint32_t evi_id,
                    uint64_t rt, bool is_export)
{
    evpn_evi_t *e = evpn_evi_find(ctx, evi_id);
    if (!e) return EVPN_ERR_NOTFOUND;
    int rc = EVPN_OK;
    pthread_rwlock_wrlock(&e->lock);
    uint64_t *list = is_export ? e->rt_export : e->rt_import;
    uint8_t  *n    = is_export ? &e->n_rt_export : &e->n_rt_import;
    for (uint8_t i = 0; i < *n; i++)
        if (list[i] == rt) goto out;
    if (*n >= EVPN_RT_MAX_PER_EVI) { rc = EVPN_ERR_FULL; goto out; }
    list[(*n)++] = rt;
out:
    pthread_rwlock_unlock(&e->lock);
    return rc;
}

int evpn_evi_del_rt(evpn_ctx_t *ctx, uint32_t evi_id,
                    uint64_t rt, bool is_export)
{
    evpn_evi_t *e = evpn_evi_find(ctx, evi_id);
    if (!e) return EVPN_ERR_NOTFOUND;
    int rc = EVPN_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&e->lock);
    uint64_t *list = is_export ? e->rt_export : e->rt_import;
    uint8_t  *n    = is_export ? &e->n_rt_export : &e->n_rt_import;
    for (uint8_t i = 0; i < *n; i++) {
        if (list[i] == rt) {
            memmove(&list[i], &list[i+1], (*n - i - 1) * sizeof(uint64_t));
            (*n)--; rc = EVPN_OK; break;
        }
    }
    pthread_rwlock_unlock(&e->lock);
    return rc;
}

int evpn_evi_set_irb(evpn_ctx_t *ctx, uint32_t evi_id,
                     const evpn_addr_t *ip, const evpn_mac_t *mac)
{
    if (!ip || !mac) return EVPN_ERR_INVAL;
    evpn_evi_t *e = evpn_evi_find(ctx, evi_id);
    if (!e) return EVPN_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&e->lock);
    e->irb_ip  = *ip; e->irb_mac = *mac; e->irb_configured = true;
    e->flags  |= EVPN_EVI_IRB;
    pthread_rwlock_unlock(&e->lock);
    return EVPN_OK;
}

/* -----------------------------------------------------------------------
 * VTEP API
 * --------------------------------------------------------------------- */
int evpn_vtep_add(evpn_ctx_t *ctx, const evpn_addr_t *ip,
                  uint8_t encap, uint32_t flags)
{
    if (!ctx || !ip) return EVPN_ERR_INVAL;
    evpn_vtep_table_t *t = &ctx->vtep_table;
    uint32_t b = evpn_fnv1a_addr(ip, t->n_buckets);
    int rc = EVPN_OK;

    pthread_rwlock_wrlock(&t->lock);
    for (evpn_vtep_t *c = t->buckets[b]; c; c = c->next)
        if (addr_eq(&c->ip, ip)) { rc = EVPN_ERR_EXISTS; goto out; }

    if (t->n_vteps >= EVPN_MAX_VTEP) { rc = EVPN_ERR_FULL; goto out; }

    evpn_vtep_t *v = calloc(1, sizeof(*v));
    if (!v) { rc = EVPN_ERR_NOMEM; goto out; }
    v->ip = *ip; v->encap = encap; v->flags = flags | EVPN_VTEP_ACTIVE;
    v->udp_port = EVPN_VXLAN_PORT; v->first_seen = v->last_seen = time(NULL);
    v->next = t->buckets[b]; t->buckets[b] = v; t->n_vteps++;

out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int evpn_vtep_del(evpn_ctx_t *ctx, const evpn_addr_t *ip)
{
    if (!ctx || !ip) return EVPN_ERR_INVAL;
    evpn_vtep_table_t *t = &ctx->vtep_table;
    uint32_t b = evpn_fnv1a_addr(ip, t->n_buckets);
    int rc = EVPN_ERR_NOTFOUND;

    pthread_rwlock_wrlock(&t->lock);
    evpn_vtep_t **pp = &t->buckets[b];
    while (*pp) {
        if (addr_eq(&(*pp)->ip, ip)) {
            evpn_vtep_t *d = *pp; *pp = d->next; free(d);
            t->n_vteps--; rc = EVPN_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

evpn_vtep_t *evpn_vtep_find(evpn_ctx_t *ctx, const evpn_addr_t *ip)
{
    if (!ctx || !ip) return NULL;
    evpn_vtep_table_t *t = &ctx->vtep_table;
    uint32_t b = evpn_fnv1a_addr(ip, t->n_buckets);
    evpn_vtep_t *found = NULL;
    pthread_rwlock_rdlock(&t->lock);
    for (evpn_vtep_t *c = t->buckets[b]; c; c = c->next)
        if (addr_eq(&c->ip, ip)) { found = c; break; }
    pthread_rwlock_unlock(&t->lock);
    return found;
}

/* -----------------------------------------------------------------------
 * MAC-IP table (RT-2)
 * --------------------------------------------------------------------- */
int evpn_mac_add(evpn_ctx_t *ctx, uint32_t evi_id,
                 const evpn_mac_t *mac, const evpn_addr_t *ip,
                 uint32_t flags, const evpn_addr_t *vtep_ip,
                 uint32_t out_ifindex, uint64_t rd)
{
    if (!ctx || !mac) return EVPN_ERR_INVAL;
    evpn_evi_t *evi = evpn_evi_find(ctx, evi_id);
    if (!evi) return EVPN_ERR_NOTFOUND;

    evpn_mac_table_t *t = &evi->mac_table;
    static const evpn_addr_t zero_ip = {0};
    const evpn_addr_t *key_ip = ip ? ip : &zero_ip;
    uint32_t b = mac_ip_hash(mac, key_ip, t->n_buckets);
    int rc = EVPN_OK;

    pthread_rwlock_wrlock(&t->lock);

    /* Update if exists */
    for (evpn_mac_ip_t *e = t->buckets[b]; e; e = e->next) {
        if (mac_eq(&e->mac, mac) && addr_eq(&e->ip, key_ip)) {
            e->flags = flags; e->rd = rd; e->out_ifindex = out_ifindex;
            e->last_update = time(NULL);
            /* update VTEP pointer */
            if (vtep_ip && vtep_ip->af != 0)
                e->vtep = evpn_vtep_find(ctx, vtep_ip);
            else
                e->vtep = NULL;
            goto out;
        }
    }

    if (t->n_entries >= EVPN_MAX_MAC_PER_EVI) { rc = EVPN_ERR_FULL; goto out; }

    evpn_mac_ip_t *e = calloc(1, sizeof(*e));
    if (!e) { rc = EVPN_ERR_NOMEM; goto out; }
    e->mac = *mac;
    if (ip) e->ip = *ip;
    e->vni = evi->l2_vni; e->flags = flags; e->rd = rd;
    e->out_ifindex = out_ifindex;
    e->installed_at = e->last_update = time(NULL);
    if (vtep_ip && vtep_ip->af != 0)
        e->vtep = evpn_vtep_find(ctx, vtep_ip);
    e->next = t->buckets[b]; t->buckets[b] = e; t->n_entries++;

    if (flags & EVPN_MAC_REMOTE) {
        pthread_rwlock_wrlock(&evi->lock); evi->rx_mac_routes++;
        pthread_rwlock_unlock(&evi->lock);
    } else {
        pthread_rwlock_wrlock(&evi->lock); evi->tx_mac_routes++;
        pthread_rwlock_unlock(&evi->lock);
    }

out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int evpn_mac_del(evpn_ctx_t *ctx, uint32_t evi_id,
                 const evpn_mac_t *mac, const evpn_addr_t *ip)
{
    if (!ctx || !mac) return EVPN_ERR_INVAL;
    evpn_evi_t *evi = evpn_evi_find(ctx, evi_id);
    if (!evi) return EVPN_ERR_NOTFOUND;

    static const evpn_addr_t zero_ip = {0};
    const evpn_addr_t *key_ip = ip ? ip : &zero_ip;
    evpn_mac_table_t *t = &evi->mac_table;
    uint32_t b = mac_ip_hash(mac, key_ip, t->n_buckets);
    int rc = EVPN_ERR_NOTFOUND;

    pthread_rwlock_wrlock(&t->lock);
    evpn_mac_ip_t **pp = &t->buckets[b];
    while (*pp) {
        if (mac_eq(&(*pp)->mac, mac) && addr_eq(&(*pp)->ip, key_ip)) {
            evpn_mac_ip_t *d = *pp; *pp = d->next; free(d);
            t->n_entries--; rc = EVPN_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

evpn_mac_ip_t *evpn_mac_lookup(evpn_ctx_t *ctx, uint32_t evi_id,
                                const evpn_mac_t *mac, const evpn_addr_t *ip)
{
    if (!ctx || !mac) return NULL;
    evpn_evi_t *evi = evpn_evi_find(ctx, evi_id);
    if (!evi) return NULL;
    static const evpn_addr_t zero_ip = {0};
    const evpn_addr_t *key_ip = ip ? ip : &zero_ip;
    evpn_mac_table_t *t = &evi->mac_table;
    evpn_mac_ip_t *found = NULL;
    pthread_rwlock_rdlock(&t->lock);
    uint32_t b = mac_ip_hash(mac, key_ip, t->n_buckets);
    for (evpn_mac_ip_t *e = t->buckets[b]; e; e = e->next)
        if (mac_eq(&e->mac, mac) && addr_eq(&e->ip, key_ip))
            { e->hit_count++; found = e; break; }
    pthread_rwlock_unlock(&t->lock);
    return found;
}

int evpn_mac_learn(evpn_ctx_t *ctx, uint32_t evi_id,
                   const evpn_mac_t *mac, const evpn_addr_t *ip,
                   uint32_t in_ifindex)
{
    return evpn_mac_add(ctx, evi_id, mac, ip,
                        EVPN_MAC_LOCAL, NULL, in_ifindex, 0);
}

int evpn_mac_flush(evpn_ctx_t *ctx, uint32_t evi_id,
                   const evpn_addr_t *vtep_ip)
{
    if (!ctx) return EVPN_ERR_INVAL;
    evpn_evi_t *evi = evpn_evi_find(ctx, evi_id);
    if (!evi) return EVPN_ERR_NOTFOUND;

    evpn_vtep_t *target = vtep_ip && vtep_ip->af
                          ? evpn_vtep_find(ctx, vtep_ip) : NULL;
    evpn_mac_table_t *t = &evi->mac_table;
    pthread_rwlock_wrlock(&t->lock);
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        evpn_mac_ip_t **pp = &t->buckets[i];
        while (*pp) {
            bool remove = (vtep_ip && vtep_ip->af)
                          ? ((*pp)->vtep == target)
                          : ((*pp)->vtep != NULL); /* flush all remote */
            if (remove) {
                evpn_mac_ip_t *d = *pp; *pp = d->next; free(d); t->n_entries--;
            } else {
                pp = &(*pp)->next;
            }
        }
    }
    pthread_rwlock_unlock(&t->lock);
    return EVPN_OK;
}

/* -----------------------------------------------------------------------
 * IMET (RT-3)
 * --------------------------------------------------------------------- */
int evpn_imet_add(evpn_ctx_t *ctx, uint32_t evi_id,
                  const evpn_addr_t *vtep_ip, uint64_t rd)
{
    if (!ctx || !vtep_ip) return EVPN_ERR_INVAL;
    evpn_evi_t *evi = evpn_evi_find(ctx, evi_id);
    if (!evi) return EVPN_ERR_NOTFOUND;

    int rc = EVPN_OK;
    pthread_rwlock_wrlock(&evi->lock);
    /* check duplicate */
    for (evpn_imet_t *c = evi->imet_list; c; c = c->next)
        if (addr_eq(&c->vtep_ip, vtep_ip)) {
            c->rd = rd; c->received_at = time(NULL); goto out;
        }
    evpn_imet_t *im = calloc(1, sizeof(*im));
    if (!im) { rc = EVPN_ERR_NOMEM; goto out; }
    im->vtep_ip = *vtep_ip; im->vni = evi->l2_vni;
    im->rd = rd; im->received_at = time(NULL);
    im->next = evi->imet_list; evi->imet_list = im; evi->n_imet++;
out:
    pthread_rwlock_unlock(&evi->lock);
    return rc;
}

int evpn_imet_del(evpn_ctx_t *ctx, uint32_t evi_id,
                  const evpn_addr_t *vtep_ip)
{
    if (!ctx || !vtep_ip) return EVPN_ERR_INVAL;
    evpn_evi_t *evi = evpn_evi_find(ctx, evi_id);
    if (!evi) return EVPN_ERR_NOTFOUND;

    int rc = EVPN_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&evi->lock);
    evpn_imet_t **pp = &evi->imet_list;
    while (*pp) {
        if (addr_eq(&(*pp)->vtep_ip, vtep_ip)) {
            evpn_imet_t *d = *pp; *pp = d->next; free(d);
            evi->n_imet--; rc = EVPN_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&evi->lock);
    return rc;
}

/* -----------------------------------------------------------------------
 * IP-prefix table (RT-5)
 * --------------------------------------------------------------------- */
int evpn_prefix_add(evpn_ctx_t *ctx, uint32_t evi_id,
                    const evpn_prefix_t *pfx,
                    const evpn_addr_t *gw_ip, const evpn_mac_t *gw_mac,
                    const evpn_addr_t *vtep_ip, uint64_t rd, bool local)
{
    if (!ctx || !pfx) return EVPN_ERR_INVAL;
    evpn_evi_t *evi = evpn_evi_find(ctx, evi_id);
    if (!evi) return EVPN_ERR_NOTFOUND;

    evpn_prefix_table_t *t = &evi->pfx_table;
    uint32_t b = evpn_fnv1a_prefix(pfx, t->n_buckets);
    int rc = EVPN_OK;

    pthread_rwlock_wrlock(&t->lock);
    evpn_ip_prefix_t *e = pfx_find_locked(t, pfx);
    if (e) {
        /* update */
        if (gw_ip)  e->gw_ip  = *gw_ip;
        if (gw_mac) e->gw_mac = *gw_mac;
        e->rd = rd; e->local = local; e->last_update = time(NULL);
        e->vtep = vtep_ip && vtep_ip->af ? evpn_vtep_find(ctx, vtep_ip) : NULL;
        goto out;
    }

    if (t->n_entries >= EVPN_MAX_PREFIX_PER_EVI) { rc = EVPN_ERR_FULL; goto out; }

    e = calloc(1, sizeof(*e));
    if (!e) { rc = EVPN_ERR_NOMEM; goto out; }
    e->prefix = *pfx; e->vni = evi->l3_vni ? evi->l3_vni : evi->l2_vni;
    if (gw_ip)  e->gw_ip  = *gw_ip;
    if (gw_mac) e->gw_mac = *gw_mac;
    e->rd = rd; e->local = local;
    e->installed_at = e->last_update = time(NULL);
    e->vtep = vtep_ip && vtep_ip->af ? evpn_vtep_find(ctx, vtep_ip) : NULL;
    e->next = t->buckets[b]; t->buckets[b] = e; t->n_entries++;

    pthread_rwlock_wrlock(&evi->lock);
    if (local) evi->tx_pfx_routes++; else evi->rx_pfx_routes++;
    pthread_rwlock_unlock(&evi->lock);

out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int evpn_prefix_del(evpn_ctx_t *ctx, uint32_t evi_id,
                    const evpn_prefix_t *pfx)
{
    if (!ctx || !pfx) return EVPN_ERR_INVAL;
    evpn_evi_t *evi = evpn_evi_find(ctx, evi_id);
    if (!evi) return EVPN_ERR_NOTFOUND;

    evpn_prefix_table_t *t = &evi->pfx_table;
    uint32_t b = evpn_fnv1a_prefix(pfx, t->n_buckets);
    int rc = EVPN_ERR_NOTFOUND;

    pthread_rwlock_wrlock(&t->lock);
    evpn_ip_prefix_t **pp = &t->buckets[b];
    while (*pp) {
        evpn_ip_prefix_t *e = *pp;
        if (e->prefix.plen == pfx->plen && e->prefix.addr.af == pfx->addr.af &&
            addr_eq(&e->prefix.addr, &pfx->addr)) {
            *pp = e->next; free(e); t->n_entries--; rc = EVPN_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

/* LPM lookup in the RT-5 table */
evpn_ip_prefix_t *evpn_prefix_lookup(evpn_ctx_t *ctx, uint32_t evi_id,
                                     const evpn_addr_t *dst)
{
    if (!ctx || !dst) return NULL;
    evpn_evi_t *evi = evpn_evi_find(ctx, evi_id);
    if (!evi) return NULL;

    evpn_prefix_table_t *t = &evi->pfx_table;
    evpn_ip_prefix_t *best = NULL;
    pthread_rwlock_rdlock(&t->lock);
    for (uint32_t i = 0; i < t->n_buckets; i++)
        for (evpn_ip_prefix_t *e = t->buckets[i]; e; e = e->next)
            if (evpn_prefix_contains(&e->prefix, dst))
                if (!best || e->prefix.plen > best->prefix.plen)
                    best = e;
    if (best) best->hit_count++;
    pthread_rwlock_unlock(&t->lock);
    return best;
}

/* -----------------------------------------------------------------------
 * Ethernet Segment (RT-4)
 * --------------------------------------------------------------------- */
int evpn_es_add(evpn_ctx_t *ctx, const evpn_esi_t *esi, uint8_t type,
                const evpn_mac_t *sys_mac, uint32_t local_disc)
{
    if (!ctx || !esi) return EVPN_ERR_INVAL;
    int rc = EVPN_OK;
    pthread_rwlock_wrlock(&ctx->es_lock);
    for (evpn_es_t *c = ctx->es_list; c; c = c->next)
        if (memcmp(c->esi.b, esi->b, 10) == 0) { rc = EVPN_ERR_EXISTS; goto out; }
    if (ctx->n_es >= EVPN_MAX_ES) { rc = EVPN_ERR_FULL; goto out; }
    evpn_es_t *es = calloc(1, sizeof(*es));
    if (!es) { rc = EVPN_ERR_NOMEM; goto out; }
    es->esi = *esi; es->type = type; es->local_disc = local_disc;
    if (sys_mac) es->sys_mac = *sys_mac;
    es->created_at = time(NULL);
    es->next = ctx->es_list; ctx->es_list = es; ctx->n_es++;
out:
    pthread_rwlock_unlock(&ctx->es_lock);
    return rc;
}

int evpn_es_del(evpn_ctx_t *ctx, const evpn_esi_t *esi)
{
    if (!ctx || !esi) return EVPN_ERR_INVAL;
    int rc = EVPN_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&ctx->es_lock);
    evpn_es_t **pp = &ctx->es_list;
    while (*pp) {
        if (memcmp((*pp)->esi.b, esi->b, 10) == 0) {
            evpn_es_t *d = *pp; *pp = d->next; free(d);
            ctx->n_es--; rc = EVPN_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&ctx->es_lock);
    return rc;
}

evpn_es_t *evpn_es_find(evpn_ctx_t *ctx, const evpn_esi_t *esi)
{
    if (!ctx || !esi) return NULL;
    evpn_es_t *found = NULL;
    pthread_rwlock_rdlock(&ctx->es_lock);
    for (evpn_es_t *c = ctx->es_list; c; c = c->next)
        if (memcmp(c->esi.b, esi->b, 10) == 0) { found = c; break; }
    pthread_rwlock_unlock(&ctx->es_lock);
    return found;
}

/* -----------------------------------------------------------------------
 * Persistence
 * --------------------------------------------------------------------- */
int evpn_save_config(evpn_ctx_t *ctx, const char *path)
{
    if (!ctx || !path) return EVPN_ERR_INVAL;
    char tmp[512]; snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w"); if (!f) return EVPN_ERR_INVAL;

    /* Global state */
    char vtep_str[INET6_ADDRSTRLEN] = "0.0.0.0";
    evpn_addr_to_str(&ctx->local_vtep_ip, vtep_str, sizeof(vtep_str));
    fprintf(f, "{\"type\":\"global\",\"local_vtep\":\"%s\","
               "\"local_asn\":%u}\n",
            vtep_str, ctx->local_asn);

    /* VTEPs */
    pthread_rwlock_rdlock(&ctx->vtep_table.lock);
    for (uint32_t i = 0; i < ctx->vtep_table.n_buckets; i++)
        for (evpn_vtep_t *v = ctx->vtep_table.buckets[i]; v; v = v->next) {
            char ip[INET6_ADDRSTRLEN];
            evpn_addr_to_str(&v->ip, ip, sizeof(ip));
            fprintf(f, "{\"type\":\"vtep\",\"ip\":\"%s\","
                       "\"encap\":%u,\"flags\":%u}\n",
                    ip, v->encap, v->flags);
        }
    pthread_rwlock_unlock(&ctx->vtep_table.lock);

    /* Ethernet Segments */
    pthread_rwlock_rdlock(&ctx->es_lock);
    for (evpn_es_t *es = ctx->es_list; es; es = es->next) {
        char esi_s[40], mac_s[20];
        evpn_esi_to_str(&es->esi, esi_s, sizeof(esi_s));
        evpn_mac_to_str(&es->sys_mac, mac_s, sizeof(mac_s));
        fprintf(f, "{\"type\":\"es\",\"esi\":\"%s\",\"es_type\":%u,"
                   "\"sys_mac\":\"%s\",\"local_disc\":%u}\n",
                esi_s, es->type, mac_s, es->local_disc);
    }
    pthread_rwlock_unlock(&ctx->es_lock);

    /* EVIs */
    pthread_rwlock_rdlock(&ctx->evi_table.lock);
    for (uint32_t i = 0; i < ctx->evi_table.n_buckets; i++) {
        for (evpn_evi_t *e = ctx->evi_table.buckets[i]; e; e = e->next) {
            pthread_rwlock_rdlock(&e->lock);

            char rd_s[32]; evpn_rd_to_str(e->rd, rd_s, sizeof(rd_s));
            char irb_ip[INET6_ADDRSTRLEN]="", irb_mac[20]="";
            if (e->irb_configured) {
                evpn_addr_to_str(&e->irb_ip, irb_ip, sizeof(irb_ip));
                evpn_mac_to_str(&e->irb_mac, irb_mac, sizeof(irb_mac));
            }
            fprintf(f, "{\"type\":\"evi\",\"evi_id\":%u,\"l2_vni\":%u,"
                       "\"l3_vni\":%u,\"vrf_id\":%u,\"flags\":%u,"
                       "\"rd\":\"%s\",\"encap\":%u,"
                       "\"irb_ip\":\"%s\",\"irb_mac\":\"%s\"}\n",
                    e->evi_id, e->l2_vni, e->l3_vni, e->vrf_id,
                    e->flags, rd_s, e->encap, irb_ip, irb_mac);

            /* RT lists */
            for (uint8_t r = 0; r < e->n_rt_export; r++) {
                char rt_s[32]; evpn_rd_to_str(e->rt_export[r], rt_s, sizeof(rt_s));
                fprintf(f, "{\"type\":\"evi_rt\",\"evi_id\":%u,"
                           "\"rt\":\"%s\",\"dir\":\"export\"}\n",
                        e->evi_id, rt_s);
            }
            for (uint8_t r = 0; r < e->n_rt_import; r++) {
                char rt_s[32]; evpn_rd_to_str(e->rt_import[r], rt_s, sizeof(rt_s));
                fprintf(f, "{\"type\":\"evi_rt\",\"evi_id\":%u,"
                           "\"rt\":\"%s\",\"dir\":\"import\"}\n",
                        e->evi_id, rt_s);
            }

            /* IMET flood list */
            for (evpn_imet_t *im = e->imet_list; im; im = im->next) {
                char ip[INET6_ADDRSTRLEN]; evpn_addr_to_str(&im->vtep_ip,ip,sizeof(ip));
                char rd_s2[32]; evpn_rd_to_str(im->rd, rd_s2, sizeof(rd_s2));
                fprintf(f, "{\"type\":\"imet\",\"evi_id\":%u,"
                           "\"vtep\":\"%s\",\"rd\":\"%s\"}\n",
                        e->evi_id, ip, rd_s2);
            }
            pthread_rwlock_unlock(&e->lock);

            /* MAC-IP table */
            pthread_rwlock_rdlock(&e->mac_table.lock);
            for (uint32_t bi = 0; bi < e->mac_table.n_buckets; bi++)
                for (evpn_mac_ip_t *m = e->mac_table.buckets[bi]; m; m = m->next) {
                    char mac_s[20], ip_s[INET6_ADDRSTRLEN]="";
                    evpn_mac_to_str(&m->mac, mac_s, sizeof(mac_s));
                    if (m->ip.af) evpn_addr_to_str(&m->ip, ip_s, sizeof(ip_s));
                    char vtep_s[INET6_ADDRSTRLEN]="";
                    if (m->vtep) evpn_addr_to_str(&m->vtep->ip,vtep_s,sizeof(vtep_s));
                    fprintf(f, "{\"type\":\"mac\",\"evi_id\":%u,"
                               "\"mac\":\"%s\",\"ip\":\"%s\","
                               "\"flags\":%u,\"vtep\":\"%s\","
                               "\"ifindex\":%u,\"rd\":%llu}\n",
                            e->evi_id, mac_s, ip_s, m->flags,
                            vtep_s, m->out_ifindex,
                            (unsigned long long)m->rd);
                }
            pthread_rwlock_unlock(&e->mac_table.lock);

            /* IP-prefix table */
            pthread_rwlock_rdlock(&e->pfx_table.lock);
            for (uint32_t bi = 0; bi < e->pfx_table.n_buckets; bi++)
                for (evpn_ip_prefix_t *p = e->pfx_table.buckets[bi]; p; p = p->next) {
                    char pfx_s[INET6_ADDRSTRLEN+4], gw_s[INET6_ADDRSTRLEN]="";
                    char gw_mac_s[20]="", vtep_s[INET6_ADDRSTRLEN]="";
                    evpn_prefix_to_str(&p->prefix, pfx_s, sizeof(pfx_s));
                    if (p->gw_ip.af) evpn_addr_to_str(&p->gw_ip,gw_s,sizeof(gw_s));
                    evpn_mac_to_str(&p->gw_mac, gw_mac_s, sizeof(gw_mac_s));
                    if (p->vtep) evpn_addr_to_str(&p->vtep->ip,vtep_s,sizeof(vtep_s));
                    fprintf(f, "{\"type\":\"prefix\",\"evi_id\":%u,"
                               "\"prefix\":\"%s\",\"gw_ip\":\"%s\","
                               "\"gw_mac\":\"%s\",\"vtep\":\"%s\","
                               "\"local\":%s,\"rd\":%llu}\n",
                            e->evi_id, pfx_s, gw_s, gw_mac_s, vtep_s,
                            p->local?"true":"false",
                            (unsigned long long)p->rd);
                }
            pthread_rwlock_unlock(&e->pfx_table.lock);
        }
    }
    pthread_rwlock_unlock(&ctx->evi_table.lock);

    fflush(f); fclose(f); rename(tmp, path);
    return EVPN_OK;
}

/* Tiny JSON field extractors */
static long long jll(const char *l, const char *k)
{
    char s[128]; snprintf(s, sizeof(s), "\"%s\":", k);
    const char *p = strstr(l, s); if (!p) return -1;
    p += strlen(s); if (*p == '"') p++;
    return strtoll(p, NULL, 10);
}

static uint64_t parse_rd_str(const char *s)
{
    /* "asn:local" */
    unsigned long asn = 0, local = 0;
    if (sscanf(s, "%lu:%lu", &asn, &local) == 2)
        return evpn_rd_make((uint32_t)asn, (uint16_t)local);
    return 0;
}

int evpn_load_config(evpn_ctx_t *ctx, const char *path)
{
    if (!ctx || !path) return EVPN_ERR_INVAL;
    FILE *f = fopen(path, "r"); if (!f) return EVPN_ERR_INVAL;
    char line[2048], type_buf[32];

    while (fgets(line, sizeof(line), f)) {
        if (vr_json_get_str(line, "type", type_buf, sizeof(type_buf)) != 0) continue;

        if (strcmp(type_buf, "global") == 0) {
            char vtep_s[INET6_ADDRSTRLEN] = {0};
            vr_json_get_str(line, "local_vtep", vtep_s, sizeof(vtep_s));
            evpn_addr_parse(vtep_s, &ctx->local_vtep_ip);
            long long asn = jll(line, "local_asn");
            if (asn > 0) ctx->local_asn = (uint32_t)asn;

        } else if (strcmp(type_buf, "vtep") == 0) {
            char ip_s[INET6_ADDRSTRLEN] = {0};
            vr_json_get_str(line, "ip", ip_s, sizeof(ip_s));
            evpn_addr_t ip; if (evpn_addr_parse(ip_s, &ip) != EVPN_OK) continue;
            uint8_t  enc  = (uint8_t) jll(line, "encap");
            uint32_t flgs = (uint32_t)jll(line, "flags");
            evpn_vtep_add(ctx, &ip, enc ? enc : EVPN_ENCAP_VXLAN, flgs);

        } else if (strcmp(type_buf, "es") == 0) {
            char esi_s[40]={0}, mac_s[20]={0};
            vr_json_get_str(line,"esi",esi_s,sizeof(esi_s));
            vr_json_get_str(line,"sys_mac",mac_s,sizeof(mac_s));
            evpn_esi_t esi; evpn_mac_t mac;
            if (evpn_esi_parse(esi_s,&esi)==EVPN_OK) {
                evpn_mac_parse(mac_s,&mac);
                uint8_t  t   = (uint8_t) jll(line,"es_type");
                uint32_t ld  = (uint32_t)jll(line,"local_disc");
                evpn_es_add(ctx,&esi,t,&mac,ld);
            }

        } else if (strcmp(type_buf, "evi") == 0) {
            long long eid = jll(line,"evi_id");
            if (eid <= 0) continue;
            uint32_t l2  = (uint32_t)jll(line,"l2_vni");
            uint32_t l3  = (uint32_t)jll(line,"l3_vni");
            uint32_t vrf = (uint32_t)jll(line,"vrf_id");
            uint32_t flg = (uint32_t)jll(line,"flags");
            evpn_evi_create(ctx,(uint32_t)eid,l2,l3,vrf,
                            flg&~EVPN_EVI_ACTIVE);
            /* restore RD */
            char rd_s[32]={0}; vr_json_get_str(line,"rd",rd_s,sizeof(rd_s));
            uint64_t rd = parse_rd_str(rd_s);
            if (rd) evpn_evi_set_rd(ctx,(uint32_t)eid,rd);
            /* restore IRB */
            char irb_ip_s[INET6_ADDRSTRLEN]={0}, irb_mac_s[20]={0};
            vr_json_get_str(line,"irb_ip",irb_ip_s,sizeof(irb_ip_s));
            vr_json_get_str(line,"irb_mac",irb_mac_s,sizeof(irb_mac_s));
            if (irb_ip_s[0]) {
                evpn_addr_t irb_ip; evpn_mac_t irb_mac;
                if (evpn_addr_parse(irb_ip_s,&irb_ip)==EVPN_OK &&
                    evpn_mac_parse(irb_mac_s,&irb_mac)==EVPN_OK)
                    evpn_evi_set_irb(ctx,(uint32_t)eid,&irb_ip,&irb_mac);
            }

        } else if (strcmp(type_buf, "evi_rt") == 0) {
            long long eid = jll(line,"evi_id"); if (eid<=0) continue;
            char rt_s[32]={0},dir[16]={0};
            vr_json_get_str(line,"rt",rt_s,sizeof(rt_s));
            vr_json_get_str(line,"dir",dir,sizeof(dir));
            uint64_t rt = parse_rd_str(rt_s);
            if (rt) evpn_evi_add_rt(ctx,(uint32_t)eid,rt,
                                    strcmp(dir,"export")==0);

        } else if (strcmp(type_buf, "imet") == 0) {
            long long eid = jll(line,"evi_id"); if (eid<=0) continue;
            char vtep_s[INET6_ADDRSTRLEN]={0}, rd_s[32]={0};
            vr_json_get_str(line,"vtep",vtep_s,sizeof(vtep_s));
            vr_json_get_str(line,"rd",rd_s,sizeof(rd_s));
            evpn_addr_t vtep_ip;
            if (evpn_addr_parse(vtep_s,&vtep_ip)==EVPN_OK)
                evpn_imet_add(ctx,(uint32_t)eid,&vtep_ip,parse_rd_str(rd_s));

        } else if (strcmp(type_buf, "mac") == 0) {
            long long eid = jll(line,"evi_id"); if (eid<=0) continue;
            char mac_s[20]={0},ip_s[INET6_ADDRSTRLEN]={0};
            char vtep_s[INET6_ADDRSTRLEN]={0};
            vr_json_get_str(line,"mac",mac_s,sizeof(mac_s));
            vr_json_get_str(line,"ip",ip_s,sizeof(ip_s));
            vr_json_get_str(line,"vtep",vtep_s,sizeof(vtep_s));
            evpn_mac_t mac; if (evpn_mac_parse(mac_s,&mac)!=EVPN_OK) continue;
            evpn_addr_t ip={0}; if (ip_s[0]) evpn_addr_parse(ip_s,&ip);
            evpn_addr_t vtep_ip={0}; if (vtep_s[0]) evpn_addr_parse(vtep_s,&vtep_ip);
            uint32_t flg = (uint32_t)jll(line,"flags");
            uint32_t oif = (uint32_t)jll(line,"ifindex");
            long long rdl = jll(line,"rd");
            evpn_mac_add(ctx,(uint32_t)eid,&mac,ip.af?&ip:NULL,
                         flg,vtep_ip.af?&vtep_ip:NULL,oif,
                         rdl>=0?(uint64_t)rdl:0);

        } else if (strcmp(type_buf, "prefix") == 0) {
            long long eid = jll(line,"evi_id"); if (eid<=0) continue;
            char pfx_s[INET6_ADDRSTRLEN+4]={0};
            char gw_ip_s[INET6_ADDRSTRLEN]={0},gw_mac_s[20]={0};
            char vtep_s[INET6_ADDRSTRLEN]={0};
            vr_json_get_str(line,"prefix",pfx_s,sizeof(pfx_s));
            vr_json_get_str(line,"gw_ip",gw_ip_s,sizeof(gw_ip_s));
            vr_json_get_str(line,"gw_mac",gw_mac_s,sizeof(gw_mac_s));
            vr_json_get_str(line,"vtep",vtep_s,sizeof(vtep_s));
            evpn_prefix_t pfx; if (evpn_prefix_parse(pfx_s,&pfx)!=EVPN_OK) continue;
            evpn_addr_t gw_ip={0}; if (gw_ip_s[0]) evpn_addr_parse(gw_ip_s,&gw_ip);
            evpn_mac_t gw_mac={0}; evpn_mac_parse(gw_mac_s,&gw_mac);
            evpn_addr_t vtep_ip={0}; if (vtep_s[0]) evpn_addr_parse(vtep_s,&vtep_ip);
            long long rdl = jll(line,"rd");
            bool local = vr_json_get_bool(line,"local");
            evpn_prefix_add(ctx,(uint32_t)eid,&pfx,
                            gw_ip.af?&gw_ip:NULL,&gw_mac,
                            vtep_ip.af?&vtep_ip:NULL,
                            rdl>=0?(uint64_t)rdl:0,local);
        }
    }
    fclose(f);
    return EVPN_OK;
}

/* -----------------------------------------------------------------------
 * Lifecycle
 * --------------------------------------------------------------------- */
static evpn_ctx_t *g_ctx = NULL;

static void sig_handler(int sig)
{
    if (!g_ctx) return;
    if (sig == SIGHUP) evpn_save_config(g_ctx, "evpn_runtime_config.json");
    else if (sig == SIGTERM || sig == SIGINT) g_ctx->running = false;
}

evpn_ctx_t *evpn_ctx_create(void)
{
    evpn_ctx_t *ctx = calloc(1, sizeof(*ctx)); if (!ctx) return NULL;
    if (evi_table_init(&ctx->evi_table)   != EVPN_OK ||
        vtep_table_init(&ctx->vtep_table) != EVPN_OK ||
        pthread_rwlock_init(&ctx->es_lock, NULL)) {
        evpn_ctx_destroy(ctx); return NULL;
    }
    ctx->sock_fd = -1;
    return ctx;
}

void evpn_ctx_destroy(evpn_ctx_t *ctx)
{
    if (!ctx) return;
    evi_table_destroy(&ctx->evi_table);
    vtep_table_destroy(&ctx->vtep_table);
    evpn_es_t *es = ctx->es_list;
    while (es) { evpn_es_t *n = es->next; free(es); es = n; }
    pthread_rwlock_destroy(&ctx->es_lock);
    free(ctx);
}

int evpn_init(evpn_ctx_t *ctx, const char *sock_path,
              const evpn_addr_t *local_vtep, uint32_t local_asn)
{
    if (!ctx || !sock_path) return EVPN_ERR_INVAL;
    strncpy(ctx->sock_path, sock_path, sizeof(ctx->sock_path) - 1);
    if (local_vtep) ctx->local_vtep_ip = *local_vtep;
    ctx->local_asn = local_asn;

    g_ctx = ctx;
    struct sigaction sa = { .sa_handler = sig_handler };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    /* Register local VTEP */
    if (local_vtep && local_vtep->af)
        evpn_vtep_add(ctx, local_vtep, EVPN_ENCAP_VXLAN,
                      EVPN_VTEP_LOCAL | EVPN_VTEP_ACTIVE);

    ctx->running = true;
    if (evpn_ipc_init(ctx) != EVPN_OK) return EVPN_ERR_INVAL;
    if (pthread_create(&ctx->ipc_thread, NULL, evpn_ipc_thread, ctx))
        return EVPN_ERR_NOMEM;
    return EVPN_OK;
}

void evpn_shutdown(evpn_ctx_t *ctx)
{
    if (!ctx) return;
    ctx->running = false;
    evpn_save_config(ctx, "evpn_runtime_config.json");
    evpn_ipc_stop(ctx);
    pthread_join(ctx->ipc_thread, NULL);
}
