/*
 * vxlan.c — VXLAN data-plane module (RFC 7348 / RFC 8365)
 *
 * Wire-format (each field network byte order on the wire):
 *
 *   Outer UDP src-port = entropy hash of inner frame headers
 *   Outer UDP dst-port = 4789 (IANA VXLAN)
 *
 *   VXLAN header (8 bytes):
 *     byte 0:    flags  — bit 3 (0x08) = I-flag (VNI valid), rest 0
 *     bytes 1-3: reserved (0)
 *     bytes 4-6: VNI (24 bits, big-endian)
 *     byte 7:    reserved (0)
 *
 * The module sends frames via SOCK_DGRAM (kernel fills IP/UDP headers
 * from the socket's connected address, so no raw-socket CAP_NET_RAW is
 * required for the basic send path).  The receive path binds a
 * SOCK_DGRAM socket to port 4789 and receives UDP payloads, then runs
 * vxlan_decap() to strip the VXLAN header and dispatch to the callback.
 *
 * For unit-testing without root, the send/receive sockets are opened
 * with SO_REUSEPORT and the tests inject frames directly through
 * vxlan_encap_send / vxlan_decap without needing a kernel network stack.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "vxlan.h"
#include "vxlan_ipc.h"
#include <vrouter/json.h>
#include <vrouter/hash.h>

/* Entropy source port for ECMP-aware outer UDP hashing (RFC 7348 §5.1) */
static uint16_t entropy_port(const uint8_t *inner, size_t inner_len)
{
    if (inner_len < 12) return 49152;
    uint32_t h = vr_fnv1a(inner, inner_len < 32 ? inner_len : 32);
    uint16_t port = (uint16_t)((h & 0x7fff) | 0x8000); /* 32768-65535 */
    return port;
}

/* -----------------------------------------------------------------------
 * Address helpers
 * --------------------------------------------------------------------- */
int vxlan_addr_parse(const char *s, vxlan_addr_t *out)
{
    if (!s || !out) return VXLAN_ERR_INVAL;
    if (inet_pton(AF_INET,  s, &out->u.v4) == 1) { out->af = AF_INET;  return VXLAN_OK; }
    if (inet_pton(AF_INET6, s, &out->u.v6) == 1) { out->af = AF_INET6; return VXLAN_OK; }
    return VXLAN_ERR_INVAL;
}

void vxlan_addr_to_str(const vxlan_addr_t *a, char *buf, size_t len)
{
    if (a->af == AF_INET)  inet_ntop(AF_INET,  &a->u.v4, buf, len);
    else if (a->af == AF_INET6) inet_ntop(AF_INET6, &a->u.v6, buf, len);
    else if (len) buf[0] = '\0';
}

bool vxlan_addr_eq(const vxlan_addr_t *a, const vxlan_addr_t *b)
{
    if (a->af != b->af) return false;
    if (a->af == AF_INET)  return a->u.v4.s_addr == b->u.v4.s_addr;
    if (a->af == AF_INET6) return memcmp(&a->u.v6, &b->u.v6, 16) == 0;
    return true; /* both AF_UNSPEC */
}

int vxlan_mac_parse(const char *s, vxlan_mac_t *out)
{
    if (!s || !out) return VXLAN_ERR_INVAL;
    if (sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out->b[0],&out->b[1],&out->b[2],
               &out->b[3],&out->b[4],&out->b[5]) == 6)
        return VXLAN_OK;
    return VXLAN_ERR_INVAL;
}

void vxlan_mac_to_str(const vxlan_mac_t *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->b[0],mac->b[1],mac->b[2],
             mac->b[3],mac->b[4],mac->b[5]);
}

/* -----------------------------------------------------------------------
 * VXLAN header encode / decode
 * --------------------------------------------------------------------- */
void vxlan_hdr_encode(vxlan_hdr_t *hdr, uint32_t vni)
{
    /* I-flag = bit 3 of first byte = 0x08000000 in network byte order */
    hdr->flags_reserved = htonl(0x08000000u);
    /* VNI in top 24 bits of second word, bottom byte = 0 */
    hdr->vni_reserved   = htonl((vni & 0x00ffffffu) << 8);
}

int vxlan_hdr_decode(const vxlan_hdr_t *hdr, uint32_t *vni_out)
{
    if (!hdr || !vni_out) return VXLAN_ERR_INVAL;
    uint32_t flags = ntohl(hdr->flags_reserved);
    if (!(flags & 0x08000000u)) return VXLAN_ERR_DECAP; /* I-flag not set */
    *vni_out = (ntohl(hdr->vni_reserved) >> 8) & 0x00ffffffu;
    return VXLAN_OK;
}

/* -----------------------------------------------------------------------
 * Decapsulation (pure function — no sockets)
 * --------------------------------------------------------------------- */
int vxlan_decap(const uint8_t *udp_payload, size_t udp_len,
                const vxlan_addr_t *src_ip, const vxlan_addr_t *dst_ip,
                uint16_t src_port, uint16_t dst_port,
                vxlan_pkt_t *out)
{
    if (!udp_payload || !out) return VXLAN_ERR_INVAL;
    if (udp_len < (size_t)(VXLAN_HDR_LEN + VXLAN_ETH_HDR_LEN))
        return VXLAN_ERR_DECAP;

    const vxlan_hdr_t *hdr = (const vxlan_hdr_t *)udp_payload;
    uint32_t vni = 0;
    if (vxlan_hdr_decode(hdr, &vni) != VXLAN_OK) return VXLAN_ERR_DECAP;

    out->buf       = (uint8_t *)udp_payload;
    out->len       = udp_len;
    out->vni       = vni;
    out->inner     = (uint8_t *)udp_payload + VXLAN_HDR_LEN;
    out->inner_len = udp_len - VXLAN_HDR_LEN;
    out->src_port  = src_port;
    out->dst_port  = dst_port;
    if (src_ip) out->src_vtep = *src_ip;
    if (dst_ip) out->dst_vtep = *dst_ip;

    return VXLAN_OK;
}

/* -----------------------------------------------------------------------
 * Table helpers — FNV hash keys
 * --------------------------------------------------------------------- */
static uint32_t tunnel_hash(const vxlan_addr_t *remote, uint32_t vni,
                            uint32_t n)
{
    uint8_t buf[20];
    size_t  al = remote->af == AF_INET ? 4 : 16;
    if (remote->af == AF_INET)  memcpy(buf, &remote->u.v4, 4);
    else                        memcpy(buf, &remote->u.v6, 16);
    buf[al]   = (vni >> 16) & 0xff;
    buf[al+1] = (vni >>  8) & 0xff;
    buf[al+2] =  vni        & 0xff;
    return vr_fnv1a_mod(buf, al + 3, n);
}

static uint32_t mac_vni_hash(const vxlan_mac_t *mac, uint32_t vni,
                             uint32_t n)
{
    uint8_t buf[9];
    memcpy(buf, mac->b, 6);
    buf[6] = (vni >> 16) & 0xff;
    buf[7] = (vni >>  8) & 0xff;
    buf[8] =  vni        & 0xff;
    return vr_fnv1a_mod(buf, 9, n);
}

static uint32_t vni_hash(uint32_t vni, uint32_t n)
{
    return vr_fnv1a_mod((const uint8_t *)&vni, 4, n);
}

/* -----------------------------------------------------------------------
 * Tunnel table
 * --------------------------------------------------------------------- */
static int tunnel_table_init(vxlan_tunnel_table_t *t)
{
    t->n_buckets = VXLAN_TUNNEL_BUCKETS;
    t->buckets   = calloc(t->n_buckets, sizeof(*t->buckets));
    if (!t->buckets) return VXLAN_ERR_NOMEM;
    t->n_tunnels = 0;
    return pthread_rwlock_init(&t->lock, NULL) ? VXLAN_ERR_NOMEM : VXLAN_OK;
}

static void tunnel_table_destroy(vxlan_tunnel_table_t *t)
{
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        vxlan_tunnel_t *c = t->buckets[i];
        while (c) { vxlan_tunnel_t *n = c->next; free(c); c = n; }
    }
    free(t->buckets); pthread_rwlock_destroy(&t->lock);
}

static vxlan_tunnel_t *tunnel_find_locked(vxlan_tunnel_table_t *t,
                                          const vxlan_addr_t *remote,
                                          uint32_t vni)
{
    uint32_t b = tunnel_hash(remote, vni, t->n_buckets);
    for (vxlan_tunnel_t *c = t->buckets[b]; c; c = c->next)
        if (c->vni == vni && vxlan_addr_eq(&c->remote_ip, remote))
            return c;
    return NULL;
}

int vxlan_tunnel_add(vxlan_ctx_t *ctx, const vxlan_addr_t *remote_ip,
                     uint32_t vni, uint32_t flags,
                     uint16_t dst_port, uint8_t ttl)
{
    if (!ctx || !remote_ip || vni < VXLAN_VNI_MIN || vni > VXLAN_VNI_MAX)
        return VXLAN_ERR_INVAL;

    vxlan_tunnel_table_t *t = &ctx->tunnel_table;
    uint32_t b = tunnel_hash(remote_ip, vni, t->n_buckets);
    int rc = VXLAN_OK;

    pthread_rwlock_wrlock(&t->lock);
    if (tunnel_find_locked(t, remote_ip, vni)) { rc = VXLAN_ERR_EXISTS; goto out; }
    if (t->n_tunnels >= VXLAN_MAX_TUNNELS) { rc = VXLAN_ERR_FULL; goto out; }

    vxlan_tunnel_t *tun = calloc(1, sizeof(*tun));
    if (!tun) { rc = VXLAN_ERR_NOMEM; goto out; }
    tun->local_ip    = ctx->local_ip;
    tun->remote_ip   = *remote_ip;
    tun->vni         = vni;
    tun->flags       = flags | VXLAN_TUNNEL_UP;
    tun->dst_port    = dst_port ? dst_port : VXLAN_PORT_DEFAULT;
    tun->ttl         = ttl ? ttl : 64;
    tun->created_at  = time(NULL);
    tun->next = t->buckets[b]; t->buckets[b] = tun; t->n_tunnels++;

out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int vxlan_tunnel_del(vxlan_ctx_t *ctx, const vxlan_addr_t *remote_ip,
                     uint32_t vni)
{
    if (!ctx || !remote_ip) return VXLAN_ERR_INVAL;
    vxlan_tunnel_table_t *t = &ctx->tunnel_table;
    uint32_t b = tunnel_hash(remote_ip, vni, t->n_buckets);
    int rc = VXLAN_ERR_NOTFOUND;

    pthread_rwlock_wrlock(&t->lock);
    vxlan_tunnel_t **pp = &t->buckets[b];
    while (*pp) {
        if ((*pp)->vni == vni && vxlan_addr_eq(&(*pp)->remote_ip, remote_ip)) {
            vxlan_tunnel_t *d = *pp; *pp = d->next; free(d);
            t->n_tunnels--; rc = VXLAN_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

vxlan_tunnel_t *vxlan_tunnel_find(vxlan_ctx_t *ctx,
                                  const vxlan_addr_t *remote_ip,
                                  uint32_t vni)
{
    if (!ctx || !remote_ip) return NULL;
    vxlan_tunnel_table_t *t = &ctx->tunnel_table;
    vxlan_tunnel_t *found = NULL;
    pthread_rwlock_rdlock(&t->lock);
    found = tunnel_find_locked(t, remote_ip, vni);
    pthread_rwlock_unlock(&t->lock);
    return found;
}

/* -----------------------------------------------------------------------
 * FDB
 * --------------------------------------------------------------------- */
static int fdb_init(vxlan_fdb_table_t *t)
{
    t->n_buckets = VXLAN_FDB_BUCKETS;
    t->buckets   = calloc(t->n_buckets, sizeof(*t->buckets));
    if (!t->buckets) return VXLAN_ERR_NOMEM;
    t->n_entries = 0;
    return pthread_rwlock_init(&t->lock, NULL) ? VXLAN_ERR_NOMEM : VXLAN_OK;
}

static void fdb_destroy(vxlan_fdb_table_t *t)
{
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        vxlan_fdb_entry_t *c = t->buckets[i];
        while (c) { vxlan_fdb_entry_t *n = c->next; free(c); c = n; }
    }
    free(t->buckets); pthread_rwlock_destroy(&t->lock);
}

static vxlan_fdb_entry_t *fdb_find_locked(vxlan_fdb_table_t *t,
                                          const vxlan_mac_t *mac,
                                          uint32_t vni)
{
    uint32_t b = mac_vni_hash(mac, vni, t->n_buckets);
    for (vxlan_fdb_entry_t *e = t->buckets[b]; e; e = e->next)
        if (e->vni == vni && memcmp(e->mac.b, mac->b, 6) == 0)
            return e;
    return NULL;
}

/* Add to the VNI's FDB — also called by vxlan_fdb_add for global table */
static int fdb_table_add(vxlan_fdb_table_t *t, uint32_t vni,
                         const vxlan_mac_t *mac,
                         const vxlan_addr_t *remote_ip,
                         uint32_t out_ifindex, uint32_t flags)
{
    uint32_t b = mac_vni_hash(mac, vni, t->n_buckets);
    int rc = VXLAN_OK;
    pthread_rwlock_wrlock(&t->lock);

    /* Update if exists */
    for (vxlan_fdb_entry_t *e = t->buckets[b]; e; e = e->next) {
        if (e->vni == vni && memcmp(e->mac.b, mac->b, 6) == 0) {
            if (remote_ip) e->remote_ip = *remote_ip;
            e->out_ifindex = out_ifindex; e->flags = flags;
            e->last_seen = time(NULL); goto out;
        }
    }

    if (t->n_entries >= VXLAN_MAX_FDB_ENTRIES) { rc = VXLAN_ERR_FULL; goto out; }

    vxlan_fdb_entry_t *e = calloc(1, sizeof(*e));
    if (!e) { rc = VXLAN_ERR_NOMEM; goto out; }
    e->mac = *mac; e->vni = vni; e->flags = flags;
    e->out_ifindex = out_ifindex;
    if (remote_ip) e->remote_ip = *remote_ip;
    e->dst_port = VXLAN_PORT_DEFAULT;
    e->installed_at = e->last_seen = time(NULL);
    e->next = t->buckets[b]; t->buckets[b] = e; t->n_entries++;

out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int vxlan_fdb_add(vxlan_ctx_t *ctx, uint32_t vni,
                  const vxlan_mac_t *mac,
                  const vxlan_addr_t *remote_ip,
                  uint32_t out_ifindex, uint32_t flags)
{
    if (!ctx || !mac) return VXLAN_ERR_INVAL;
    vxlan_vni_t *v = vxlan_vni_find(ctx, vni);
    if (!v) return VXLAN_ERR_NOTFOUND;
    return fdb_table_add(&v->fdb, vni, mac, remote_ip, out_ifindex, flags);
}

int vxlan_fdb_del(vxlan_ctx_t *ctx, uint32_t vni, const vxlan_mac_t *mac)
{
    if (!ctx || !mac) return VXLAN_ERR_INVAL;
    vxlan_vni_t *v = vxlan_vni_find(ctx, vni);
    if (!v) return VXLAN_ERR_NOTFOUND;

    vxlan_fdb_table_t *t = &v->fdb;
    uint32_t b = mac_vni_hash(mac, vni, t->n_buckets);
    int rc = VXLAN_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&t->lock);
    vxlan_fdb_entry_t **pp = &t->buckets[b];
    while (*pp) {
        if ((*pp)->vni == vni && memcmp((*pp)->mac.b, mac->b, 6) == 0) {
            vxlan_fdb_entry_t *d = *pp; *pp = d->next; free(d);
            t->n_entries--; rc = VXLAN_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

vxlan_fdb_entry_t *vxlan_fdb_lookup(vxlan_ctx_t *ctx, uint32_t vni,
                                    const vxlan_mac_t *mac)
{
    if (!ctx || !mac) return NULL;
    vxlan_vni_t *v = vxlan_vni_find(ctx, vni);
    if (!v) return NULL;
    vxlan_fdb_table_t *t = &v->fdb;
    vxlan_fdb_entry_t *found = NULL;
    pthread_rwlock_rdlock(&t->lock);
    found = fdb_find_locked(t, mac, vni);
    if (found) { found->hit_count++; found->last_seen = time(NULL); }
    pthread_rwlock_unlock(&t->lock);
    return found;
}

int vxlan_fdb_learn(vxlan_ctx_t *ctx, uint32_t vni,
                    const vxlan_mac_t *mac,
                    const vxlan_addr_t *remote_ip,
                    uint32_t in_ifindex)
{
    uint32_t flags = remote_ip && remote_ip->af
                     ? VXLAN_FDB_REMOTE : VXLAN_FDB_LOCAL;
    return vxlan_fdb_add(ctx, vni, mac, remote_ip, in_ifindex, flags);
}

int vxlan_fdb_flush(vxlan_ctx_t *ctx, uint32_t vni,
                    const vxlan_addr_t *remote_ip)
{
    if (!ctx) return VXLAN_ERR_INVAL;
    vxlan_vni_t *v = vxlan_vni_find(ctx, vni);
    if (!v) return VXLAN_ERR_NOTFOUND;

    vxlan_fdb_table_t *t = &v->fdb;
    pthread_rwlock_wrlock(&t->lock);
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        vxlan_fdb_entry_t **pp = &t->buckets[i];
        while (*pp) {
            bool remove = !remote_ip || !remote_ip->af
                          ? ((*pp)->flags & VXLAN_FDB_REMOTE) != 0
                          : vxlan_addr_eq(&(*pp)->remote_ip, remote_ip);
            if (remove) {
                vxlan_fdb_entry_t *d = *pp; *pp = d->next; free(d); t->n_entries--;
            } else {
                pp = &(*pp)->next;
            }
        }
    }
    pthread_rwlock_unlock(&t->lock);
    return VXLAN_OK;
}

/* -----------------------------------------------------------------------
 * VNI table
 * --------------------------------------------------------------------- */
static int vni_table_init(vxlan_vni_table_t *t)
{
    t->n_buckets = VXLAN_VNI_BUCKETS;
    t->buckets   = calloc(t->n_buckets, sizeof(*t->buckets));
    if (!t->buckets) return VXLAN_ERR_NOMEM;
    t->n_vnis = 0;
    return pthread_rwlock_init(&t->lock, NULL) ? VXLAN_ERR_NOMEM : VXLAN_OK;
}

static void vni_table_destroy(vxlan_vni_table_t *t)
{
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        vxlan_vni_t *c = t->buckets[i];
        while (c) {
            vxlan_vni_t *n = c->next;
            fdb_destroy(&c->fdb);
            free(c->flood_list);
            pthread_rwlock_destroy(&c->lock);
            free(c); c = n;
        }
    }
    free(t->buckets); pthread_rwlock_destroy(&t->lock);
}

int vxlan_vni_add(vxlan_ctx_t *ctx, uint32_t vni,
                  uint32_t bd_ifindex, uint32_t flags, uint16_t mtu)
{
    if (!ctx || vni < VXLAN_VNI_MIN || vni > VXLAN_VNI_MAX) return VXLAN_ERR_INVAL;
    vxlan_vni_table_t *t = &ctx->vni_table;
    uint32_t b = vni_hash(vni, t->n_buckets);
    int rc = VXLAN_OK;

    pthread_rwlock_wrlock(&t->lock);
    for (vxlan_vni_t *c = t->buckets[b]; c; c = c->next)
        if (c->vni == vni) { rc = VXLAN_ERR_EXISTS; goto out; }

    if (t->n_vnis >= VXLAN_MAX_VNIS) { rc = VXLAN_ERR_FULL; goto out; }

    vxlan_vni_t *v = calloc(1, sizeof(*v));
    if (!v) { rc = VXLAN_ERR_NOMEM; goto out; }
    v->vni = vni; v->bd_ifindex = bd_ifindex;
    v->flags = flags | VXLAN_VNI_ACTIVE;
    v->mtu = mtu ? mtu : VXLAN_MTU_DEFAULT;
    v->created_at = time(NULL);
    if (fdb_init(&v->fdb) != VXLAN_OK ||
        pthread_rwlock_init(&v->lock, NULL)) {
        fdb_destroy(&v->fdb); free(v); rc = VXLAN_ERR_NOMEM; goto out;
    }
    v->next = t->buckets[b]; t->buckets[b] = v; t->n_vnis++;

out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int vxlan_vni_del(vxlan_ctx_t *ctx, uint32_t vni)
{
    if (!ctx) return VXLAN_ERR_INVAL;
    vxlan_vni_table_t *t = &ctx->vni_table;
    uint32_t b = vni_hash(vni, t->n_buckets);
    int rc = VXLAN_ERR_NOTFOUND;

    pthread_rwlock_wrlock(&t->lock);
    vxlan_vni_t **pp = &t->buckets[b];
    while (*pp) {
        if ((*pp)->vni == vni) {
            vxlan_vni_t *d = *pp; *pp = d->next;
            fdb_destroy(&d->fdb);
            free(d->flood_list);
            pthread_rwlock_destroy(&d->lock);
            free(d); t->n_vnis--; rc = VXLAN_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

vxlan_vni_t *vxlan_vni_find(vxlan_ctx_t *ctx, uint32_t vni)
{
    if (!ctx) return NULL;
    vxlan_vni_table_t *t = &ctx->vni_table;
    uint32_t b = vni_hash(vni, t->n_buckets);
    vxlan_vni_t *found = NULL;
    pthread_rwlock_rdlock(&t->lock);
    for (vxlan_vni_t *c = t->buckets[b]; c; c = c->next)
        if (c->vni == vni) { found = c; break; }
    pthread_rwlock_unlock(&t->lock);
    return found;
}

int vxlan_vni_set_mcast(vxlan_ctx_t *ctx, uint32_t vni,
                        const vxlan_addr_t *mcast_group,
                        uint32_t mcast_ifindex)
{
    if (!mcast_group) return VXLAN_ERR_INVAL;
    vxlan_vni_t *v = vxlan_vni_find(ctx, vni);
    if (!v) return VXLAN_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&v->lock);
    v->mcast_group   = *mcast_group;
    v->mcast_ifindex = mcast_ifindex;
    v->flags |= VXLAN_VNI_MCAST;
    pthread_rwlock_unlock(&v->lock);
    return VXLAN_OK;
}

/* -----------------------------------------------------------------------
 * Flood list (head-end replication)
 * --------------------------------------------------------------------- */
int vxlan_flood_add(vxlan_ctx_t *ctx, uint32_t vni,
                    const vxlan_addr_t *remote_ip)
{
    if (!ctx || !remote_ip) return VXLAN_ERR_INVAL;
    vxlan_vni_t *v = vxlan_vni_find(ctx, vni);
    if (!v) return VXLAN_ERR_NOTFOUND;

    int rc = VXLAN_OK;
    pthread_rwlock_wrlock(&v->lock);
    /* Check duplicate */
    for (uint32_t i = 0; i < v->n_flood; i++)
        if (vxlan_addr_eq(&v->flood_list[i], remote_ip)) goto out;

    vxlan_addr_t *nl = realloc(v->flood_list,
                               (v->n_flood + 1) * sizeof(vxlan_addr_t));
    if (!nl) { rc = VXLAN_ERR_NOMEM; goto out; }
    nl[v->n_flood++] = *remote_ip;
    v->flood_list = nl;
    v->flags |= VXLAN_VNI_FLOOD;

out:
    pthread_rwlock_unlock(&v->lock);
    return rc;
}

int vxlan_flood_del(vxlan_ctx_t *ctx, uint32_t vni,
                    const vxlan_addr_t *remote_ip)
{
    if (!ctx || !remote_ip) return VXLAN_ERR_INVAL;
    vxlan_vni_t *v = vxlan_vni_find(ctx, vni);
    if (!v) return VXLAN_ERR_NOTFOUND;

    int rc = VXLAN_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&v->lock);
    for (uint32_t i = 0; i < v->n_flood; i++) {
        if (!vxlan_addr_eq(&v->flood_list[i], remote_ip)) continue;
        memmove(&v->flood_list[i], &v->flood_list[i+1],
                (v->n_flood - i - 1) * sizeof(vxlan_addr_t));
        v->n_flood--;
        if (v->n_flood == 0) { free(v->flood_list); v->flood_list = NULL;
                               v->flags &= ~VXLAN_VNI_FLOOD; }
        rc = VXLAN_OK; break;
    }
    pthread_rwlock_unlock(&v->lock);
    return rc;
}

/* -----------------------------------------------------------------------
 * Data-plane: encapsulate and transmit
 * --------------------------------------------------------------------- */
int vxlan_encap_send(vxlan_ctx_t *ctx, uint32_t vni,
                     const vxlan_addr_t *remote_ip,
                     const uint8_t *inner_frame, size_t inner_len)
{
    if (!ctx || !remote_ip || !inner_frame || !inner_len) return VXLAN_ERR_INVAL;
    if (inner_len > VXLAN_MAX_FRAME) return VXLAN_ERR_INVAL;

    /* Assemble UDP payload: VXLAN header + inner frame */
    size_t payload_len = VXLAN_HDR_LEN + inner_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        pthread_rwlock_wrlock(&ctx->stats.lock);
        ctx->stats.tx_encap_err++;
        pthread_rwlock_unlock(&ctx->stats.lock);
        return VXLAN_ERR_NOMEM;
    }

    vxlan_hdr_t *hdr = (vxlan_hdr_t *)payload;
    vxlan_hdr_encode(hdr, vni);
    memcpy(payload + VXLAN_HDR_LEN, inner_frame, inner_len);

    /* Choose tx socket and build dest address */
    uint16_t src_port = entropy_port(inner_frame, inner_len);
    int rc = VXLAN_OK;
    ssize_t sent = -1;

    /* Find tunnel for stats update */
    vxlan_tunnel_t *tun = vxlan_tunnel_find(ctx, remote_ip, vni);

    if (remote_ip->af == AF_INET) {
        if (ctx->tx_sock_v4 < 0) { rc = VXLAN_ERR_SOCKET; goto done; }
        struct sockaddr_in dst = {0};
        dst.sin_family = AF_INET;
        dst.sin_addr   = remote_ip->u.v4;
        dst.sin_port   = htons(tun ? tun->dst_port : VXLAN_PORT_DEFAULT);
        /* Set source port via ancillary data or rely on OS assignment;
         * for user-space simulation we just connect+send */
        (void)src_port; /* used only for entropy — kernel picks src port */
        sent = sendto(ctx->tx_sock_v4, payload, payload_len, 0,
                      (struct sockaddr *)&dst, sizeof(dst));
    } else if (remote_ip->af == AF_INET6) {
        if (ctx->tx_sock_v6 < 0) { rc = VXLAN_ERR_SOCKET; goto done; }
        struct sockaddr_in6 dst = {0};
        dst.sin6_family = AF_INET6;
        dst.sin6_addr   = remote_ip->u.v6;
        dst.sin6_port   = htons(tun ? tun->dst_port : VXLAN_PORT_DEFAULT);
        sent = sendto(ctx->tx_sock_v6, payload, payload_len, 0,
                      (struct sockaddr *)&dst, sizeof(dst));
    } else {
        rc = VXLAN_ERR_INVAL; goto done;
    }

    if (sent < 0) { rc = VXLAN_ERR_ENCAP; }

done:
    free(payload);

    pthread_rwlock_wrlock(&ctx->stats.lock);
    if (rc == VXLAN_OK && sent > 0) {
        ctx->stats.tx_pkts++;
        ctx->stats.tx_bytes += (uint64_t)sent;
        ctx->stats.tx_encap_ok++;
    } else {
        ctx->stats.tx_encap_err++;
    }
    pthread_rwlock_unlock(&ctx->stats.lock);

    if (tun && rc == VXLAN_OK && sent > 0) {
        tun->tx_pkts++; tun->tx_bytes += (uint64_t)sent; tun->last_tx = time(NULL);
    } else if (tun) {
        tun->tx_errors++;
    }

    /* Update VNI stats */
    vxlan_vni_t *v = vxlan_vni_find(ctx, vni);
    if (v) {
        pthread_rwlock_wrlock(&v->lock);
        if (rc == VXLAN_OK && sent > 0) {
            v->tx_pkts++; v->tx_bytes += (uint64_t)payload_len;
        }
        pthread_rwlock_unlock(&v->lock);
    }

    return rc;
}

/* -----------------------------------------------------------------------
 * Flood
 * --------------------------------------------------------------------- */
int vxlan_flood(vxlan_ctx_t *ctx, uint32_t vni,
                const uint8_t *inner_frame, size_t inner_len,
                const vxlan_addr_t *exclude_vtep)
{
    if (!ctx || !inner_frame) return VXLAN_ERR_INVAL;
    vxlan_vni_t *v = vxlan_vni_find(ctx, vni);
    if (!v) return VXLAN_ERR_NOTFOUND;

    pthread_rwlock_rdlock(&v->lock);
    uint32_t n = v->n_flood;
    /* Copy flood list to avoid holding the lock during sends */
    vxlan_addr_t *flood_copy = NULL;
    if (n > 0) {
        flood_copy = malloc(n * sizeof(vxlan_addr_t));
        if (flood_copy) memcpy(flood_copy, v->flood_list,
                               n * sizeof(vxlan_addr_t));
    }
    pthread_rwlock_unlock(&v->lock);

    if (!flood_copy && n > 0) return VXLAN_ERR_NOMEM;

    int errors = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (exclude_vtep && vxlan_addr_eq(&flood_copy[i], exclude_vtep)) continue;
        if (vxlan_encap_send(ctx, vni, &flood_copy[i], inner_frame, inner_len) != VXLAN_OK)
            errors++;
    }
    free(flood_copy);

    pthread_rwlock_wrlock(&v->lock);
    v->tx_flood_pkts += n;
    pthread_rwlock_unlock(&v->lock);

    return errors ? VXLAN_ERR_ENCAP : VXLAN_OK;
}

/* -----------------------------------------------------------------------
 * Receive thread
 * --------------------------------------------------------------------- */
#define RX_BUF_SIZE (VXLAN_MAX_FRAME + VXLAN_OUTER_V4_OVERHEAD + 64)

static void rx_process(vxlan_ctx_t *ctx, const uint8_t *buf, ssize_t n,
                       const vxlan_addr_t *src_ip, uint16_t src_port)
{
    pthread_rwlock_wrlock(&ctx->stats.lock);
    ctx->stats.rx_pkts++;
    ctx->stats.rx_bytes += (uint64_t)n;
    pthread_rwlock_unlock(&ctx->stats.lock);

    if ((size_t)n < VXLAN_HDR_LEN + VXLAN_ETH_HDR_LEN) {
        pthread_rwlock_wrlock(&ctx->stats.lock);
        ctx->stats.rx_drop_short++;
        pthread_rwlock_unlock(&ctx->stats.lock);
        return;
    }

    vxlan_pkt_t pkt;
    if (vxlan_decap(buf, (size_t)n, src_ip, &ctx->local_ip,
                    src_port, ctx->listen_port, &pkt) != VXLAN_OK) {
        pthread_rwlock_wrlock(&ctx->stats.lock);
        ctx->stats.rx_decap_err++;
        pthread_rwlock_unlock(&ctx->stats.lock);
        return;
    }

    pthread_rwlock_wrlock(&ctx->stats.lock);
    ctx->stats.rx_decap_ok++;
    pthread_rwlock_unlock(&ctx->stats.lock);

    /* Update VNI stats */
    vxlan_vni_t *v = vxlan_vni_find(ctx, pkt.vni);
    if (v) {
        pthread_rwlock_wrlock(&v->lock);
        v->rx_pkts++; v->rx_bytes += (uint64_t)n;
        pthread_rwlock_unlock(&v->lock);
    } else {
        pthread_rwlock_wrlock(&ctx->stats.lock);
        ctx->stats.rx_drop_vni++;
        pthread_rwlock_unlock(&ctx->stats.lock);
    }

    /* Learn source MAC from inner Ethernet header if inner_len >= 14 */
    if (pkt.inner_len >= 14) {
        vxlan_mac_t src_mac;
        memcpy(src_mac.b, pkt.inner + 6, 6); /* src MAC at offset 6 */
        vxlan_fdb_learn(ctx, pkt.vni, &src_mac, src_ip, 0);
    }

    /* Invoke application callback */
    if (ctx->rx_cb) ctx->rx_cb(&pkt, ctx->rx_cb_user);
}

static void *rx_thread_v4(void *arg)
{
    vxlan_ctx_t *ctx = arg;
    uint8_t buf[RX_BUF_SIZE];
    struct sockaddr_in src;
    socklen_t sl = sizeof(src);

    while (ctx->rx_running) {
        ssize_t n = recvfrom(ctx->sock_v4, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &sl);
        if (n < 0) { if (ctx->rx_running) continue; break; }
        vxlan_addr_t src_ip = { .af = AF_INET, .u.v4 = src.sin_addr };
        rx_process(ctx, buf, n, &src_ip, ntohs(src.sin_port));
    }
    return NULL;
}

/* -----------------------------------------------------------------------
 * Stats
 * --------------------------------------------------------------------- */
void vxlan_stats_get(vxlan_ctx_t *ctx, vxlan_stats_t *out)
{
    if (!ctx || !out) return;
    pthread_rwlock_rdlock(&ctx->stats.lock);
    *out = ctx->stats;
    pthread_rwlock_unlock(&ctx->stats.lock);
}

void vxlan_stats_clear(vxlan_ctx_t *ctx)
{
    if (!ctx) return;
    pthread_rwlock_wrlock(&ctx->stats.lock);
    pthread_rwlock_t saved = ctx->stats.lock;
    memset(&ctx->stats, 0, sizeof(ctx->stats));
    ctx->stats.lock = saved;
    pthread_rwlock_unlock(&ctx->stats.lock);
}

/* -----------------------------------------------------------------------
 * Persistence
 * --------------------------------------------------------------------- */
int vxlan_save_config(vxlan_ctx_t *ctx, const char *path)
{
    if (!ctx || !path) return VXLAN_ERR_INVAL;
    char tmp[512]; snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w"); if (!f) return VXLAN_ERR_INVAL;

    /* Global */
    char local_ip_s[INET6_ADDRSTRLEN] = "0.0.0.0";
    vxlan_addr_to_str(&ctx->local_ip, local_ip_s, sizeof(local_ip_s));
    fprintf(f, "{\"type\":\"global\",\"local_ip\":\"%s\","
               "\"local_ifindex\":%u,\"listen_port\":%u}\n",
            local_ip_s, ctx->local_ifindex, ctx->listen_port);

    /* VNIs */
    pthread_rwlock_rdlock(&ctx->vni_table.lock);
    for (uint32_t i = 0; i < ctx->vni_table.n_buckets; i++) {
        for (vxlan_vni_t *v = ctx->vni_table.buckets[i]; v; v = v->next) {
            pthread_rwlock_rdlock(&v->lock);
            char mcast_s[INET6_ADDRSTRLEN] = "";
            if (v->flags & VXLAN_VNI_MCAST)
                vxlan_addr_to_str(&v->mcast_group, mcast_s, sizeof(mcast_s));
            fprintf(f, "{\"type\":\"vni\",\"vni\":%u,\"bd_ifindex\":%u,"
                       "\"flags\":%u,\"mtu\":%u,\"mcast_group\":\"%s\","
                       "\"mcast_ifindex\":%u}\n",
                    v->vni, v->bd_ifindex, v->flags, v->mtu,
                    mcast_s, v->mcast_ifindex);

            /* Flood list */
            for (uint32_t fi = 0; fi < v->n_flood; fi++) {
                char fip[INET6_ADDRSTRLEN];
                vxlan_addr_to_str(&v->flood_list[fi], fip, sizeof(fip));
                fprintf(f, "{\"type\":\"flood\",\"vni\":%u,\"remote\":\"%s\"}\n",
                        v->vni, fip);
            }

            /* FDB entries */
            pthread_rwlock_rdlock(&v->fdb.lock);
            for (uint32_t bi = 0; bi < v->fdb.n_buckets; bi++) {
                for (vxlan_fdb_entry_t *e = v->fdb.buckets[bi]; e; e = e->next) {
                    char mac_s[20], rip_s[INET6_ADDRSTRLEN] = "";
                    vxlan_mac_to_str(&e->mac, mac_s, sizeof(mac_s));
                    if (e->remote_ip.af)
                        vxlan_addr_to_str(&e->remote_ip, rip_s, sizeof(rip_s));
                    fprintf(f, "{\"type\":\"fdb\",\"vni\":%u,"
                               "\"mac\":\"%s\",\"remote_ip\":\"%s\","
                               "\"ifindex\":%u,\"flags\":%u}\n",
                            v->vni, mac_s, rip_s,
                            e->out_ifindex, e->flags);
                }
            }
            pthread_rwlock_unlock(&v->fdb.lock);
            pthread_rwlock_unlock(&v->lock);
        }
    }
    pthread_rwlock_unlock(&ctx->vni_table.lock);

    /* Tunnels */
    pthread_rwlock_rdlock(&ctx->tunnel_table.lock);
    for (uint32_t i = 0; i < ctx->tunnel_table.n_buckets; i++) {
        for (vxlan_tunnel_t *t = ctx->tunnel_table.buckets[i]; t; t = t->next) {
            char rip_s[INET6_ADDRSTRLEN];
            vxlan_addr_to_str(&t->remote_ip, rip_s, sizeof(rip_s));
            fprintf(f, "{\"type\":\"tunnel\",\"remote_ip\":\"%s\","
                       "\"vni\":%u,\"flags\":%u,\"dst_port\":%u,\"ttl\":%u}\n",
                    rip_s, t->vni, t->flags, t->dst_port, t->ttl);
        }
    }
    pthread_rwlock_unlock(&ctx->tunnel_table.lock);

    fflush(f); fclose(f); rename(tmp, path);
    return VXLAN_OK;
}

/* jll: read a 64-bit integer field from a flat JSON line.
 * vr_json_get_int returns long (64-bit on LP64), cast to long long. */
static long long jll(const char *l, const char *k)
{
    return (long long)vr_json_get_int(l, k, -1);
}

int vxlan_load_config(vxlan_ctx_t *ctx, const char *path)
{
    if (!ctx || !path) return VXLAN_ERR_INVAL;
    FILE *f = fopen(path, "r"); if (!f) return VXLAN_ERR_INVAL;
    char line[2048], type_buf[32];

    while (fgets(line, sizeof(line), f)) {
        if (vr_json_get_str(line, "type", type_buf, sizeof(type_buf)) != 0) continue;

        if (!strcmp(type_buf, "global")) {
            char ip_s[INET6_ADDRSTRLEN] = {0};
            vr_json_get_str(line, "local_ip", ip_s, sizeof(ip_s));
            vxlan_addr_parse(ip_s, &ctx->local_ip);
            long long iidx = jll(line, "local_ifindex");
            if (iidx >= 0) ctx->local_ifindex = (uint32_t)iidx;
            long long lp = jll(line, "listen_port");
            if (lp > 0) ctx->listen_port = (uint16_t)lp;

        } else if (!strcmp(type_buf, "vni")) {
            long long vni_l = jll(line, "vni"); if (vni_l <= 0) continue;
            uint32_t vni    = (uint32_t)vni_l;
            uint32_t bd     = (uint32_t)jll(line, "bd_ifindex");
            uint32_t flg    = (uint32_t)jll(line, "flags");
            long long mtu_l = jll(line, "mtu");
            uint16_t mtu    = mtu_l > 0 ? (uint16_t)mtu_l : VXLAN_MTU_DEFAULT;
            vxlan_vni_add(ctx, vni, bd, flg & ~VXLAN_VNI_ACTIVE, mtu);
            char mcast_s[INET6_ADDRSTRLEN] = {0};
            vr_json_get_str(line, "mcast_group", mcast_s, sizeof(mcast_s));
            if (mcast_s[0]) {
                vxlan_addr_t mg; long long mi = jll(line, "mcast_ifindex");
                if (vxlan_addr_parse(mcast_s, &mg) == VXLAN_OK)
                    vxlan_vni_set_mcast(ctx, vni, &mg,
                                        mi >= 0 ? (uint32_t)mi : 0);
            }

        } else if (!strcmp(type_buf, "flood")) {
            long long vni_l = jll(line, "vni"); if (vni_l <= 0) continue;
            char rip_s[INET6_ADDRSTRLEN] = {0};
            vr_json_get_str(line, "remote", rip_s, sizeof(rip_s));
            vxlan_addr_t rip;
            if (vxlan_addr_parse(rip_s, &rip) == VXLAN_OK)
                vxlan_flood_add(ctx, (uint32_t)vni_l, &rip);

        } else if (!strcmp(type_buf, "fdb")) {
            long long vni_l = jll(line, "vni"); if (vni_l <= 0) continue;
            char mac_s[20] = {0}, rip_s[INET6_ADDRSTRLEN] = {0};
            vr_json_get_str(line, "mac",       mac_s, sizeof(mac_s));
            vr_json_get_str(line, "remote_ip", rip_s, sizeof(rip_s));
            vxlan_mac_t mac; if (vxlan_mac_parse(mac_s, &mac) != VXLAN_OK) continue;
            vxlan_addr_t rip = {0};
            if (rip_s[0]) vxlan_addr_parse(rip_s, &rip);
            uint32_t oif  = (uint32_t)jll(line, "ifindex");
            uint32_t flg  = (uint32_t)jll(line, "flags");
            /* Skip dynamically learned entries on reload — only static */
            if (flg & VXLAN_FDB_STATIC)
                vxlan_fdb_add(ctx, (uint32_t)vni_l, &mac,
                              rip.af ? &rip : NULL, oif, flg);

        } else if (!strcmp(type_buf, "tunnel")) {
            char rip_s[INET6_ADDRSTRLEN] = {0};
            vr_json_get_str(line, "remote_ip", rip_s, sizeof(rip_s));
            vxlan_addr_t rip; if (vxlan_addr_parse(rip_s, &rip) != VXLAN_OK) continue;
            long long vni_l = jll(line, "vni");    if (vni_l <= 0) continue;
            uint32_t flg  = (uint32_t)jll(line, "flags");
            long long dp  = jll(line, "dst_port");
            long long ttl = jll(line, "ttl");
            vxlan_tunnel_add(ctx, &rip, (uint32_t)vni_l,
                             flg & ~VXLAN_TUNNEL_UP,
                             dp  > 0 ? (uint16_t)dp  : 0,
                             ttl > 0 ? (uint8_t)ttl  : 0);
        }
    }
    fclose(f);
    return VXLAN_OK;
}

/* -----------------------------------------------------------------------
 * Lifecycle
 * --------------------------------------------------------------------- */
static vxlan_ctx_t *g_ctx = NULL;

static void sig_handler(int sig)
{
    if (!g_ctx) return;
    if (sig == SIGHUP)             vxlan_save_config(g_ctx, "vxlan_runtime.json");
    else if (sig == SIGTERM ||
             sig == SIGINT)        g_ctx->running = false;
}

void vxlan_set_rx_cb(vxlan_ctx_t *ctx, vxlan_rx_cb_t cb, void *user)
{
    if (!ctx) return;
    ctx->rx_cb = cb; ctx->rx_cb_user = user;
}

vxlan_ctx_t *vxlan_ctx_create(void)
{
    vxlan_ctx_t *ctx = calloc(1, sizeof(*ctx)); if (!ctx) return NULL;
    if (tunnel_table_init(&ctx->tunnel_table) != VXLAN_OK ||
        vni_table_init(&ctx->vni_table)       != VXLAN_OK ||
        pthread_rwlock_init(&ctx->stats.lock, NULL)) {
        vxlan_ctx_destroy(ctx); return NULL;
    }
    ctx->sock_v4 = ctx->sock_v6 = ctx->tx_sock_v4 = ctx->tx_sock_v6 = -1;
    ctx->ipc_fd  = -1;
    ctx->listen_port = VXLAN_PORT_DEFAULT;
    return ctx;
}

void vxlan_ctx_destroy(vxlan_ctx_t *ctx)
{
    if (!ctx) return;
    tunnel_table_destroy(&ctx->tunnel_table);
    vni_table_destroy(&ctx->vni_table);
    pthread_rwlock_destroy(&ctx->stats.lock);
    free(ctx);
}

static int open_udp_socket(sa_family_t af, uint16_t port, bool reuse)
{
    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    if (reuse) {
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    }
    if (af == AF_INET) {
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET; a.sin_port = htons(port);
        a.sin_addr.s_addr = INADDR_ANY;
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0)
            { close(fd); return -1; }
    } else {
        int v6only = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        struct sockaddr_in6 a = {0};
        a.sin6_family = AF_INET6; a.sin6_port = htons(port);
        a.sin6_addr = in6addr_any;
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0)
            { close(fd); return -1; }
    }
    return fd;
}

int vxlan_init(vxlan_ctx_t *ctx, const char *sock_path,
               const vxlan_addr_t *local_ip,
               uint32_t local_ifindex, uint16_t listen_port)
{
    if (!ctx || !sock_path) return VXLAN_ERR_INVAL;
    strncpy(ctx->sock_path, sock_path, sizeof(ctx->sock_path) - 1);
    if (local_ip)  ctx->local_ip       = *local_ip;
    if (local_ifindex) ctx->local_ifindex = local_ifindex;
    if (listen_port)   ctx->listen_port   = listen_port;

    g_ctx = ctx;
    struct sigaction sa = { .sa_handler = sig_handler };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    /* Open tx sockets (no bind needed for sending) */
    ctx->tx_sock_v4 = socket(AF_INET,  SOCK_DGRAM, 0);
    ctx->tx_sock_v6 = socket(AF_INET6, SOCK_DGRAM, 0);

    /* Open rx socket on listen_port */
    ctx->sock_v4 = open_udp_socket(AF_INET, ctx->listen_port, true);
    /* IPv6 rx optional — don't fail if it can't bind */
    ctx->sock_v6 = open_udp_socket(AF_INET6, ctx->listen_port, true);

    ctx->running = true;
    if (vxlan_ipc_init(ctx) != VXLAN_OK) return VXLAN_ERR_SOCKET;
    if (pthread_create(&ctx->ipc_thread, NULL, vxlan_ipc_thread, ctx))
        return VXLAN_ERR_NOMEM;

    /* Start rx thread (requires a working rx socket) */
    if (ctx->sock_v4 >= 0) {
        ctx->rx_running = true;
        if (pthread_create(&ctx->rx_thread, NULL, rx_thread_v4, ctx))
            ctx->rx_running = false;
    }

    return VXLAN_OK;
}

void vxlan_shutdown(vxlan_ctx_t *ctx)
{
    if (!ctx) return;
    ctx->running    = false;
    ctx->rx_running = false;
    vxlan_save_config(ctx, "vxlan_runtime.json");
    vxlan_ipc_stop(ctx);
    pthread_join(ctx->ipc_thread, NULL);
    if (ctx->sock_v4 >= 0) { shutdown(ctx->sock_v4, SHUT_RDWR); close(ctx->sock_v4); ctx->sock_v4 = -1; }
    if (ctx->sock_v6 >= 0) { close(ctx->sock_v6); ctx->sock_v6 = -1; }
    if (ctx->tx_sock_v4 >= 0) { close(ctx->tx_sock_v4); ctx->tx_sock_v4 = -1; }
    if (ctx->tx_sock_v6 >= 0) { close(ctx->tx_sock_v6); ctx->tx_sock_v6 = -1; }
    if (ctx->rx_running)
        pthread_join(ctx->rx_thread, NULL);
}
