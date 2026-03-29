/*
 * evpn_ipc.c — Unix socket IPC for the EVPN module.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "evpn.h"
#include "evpn_ipc.h"

/* -----------------------------------------------------------------------
 * JSON micro-helpers
 * --------------------------------------------------------------------- */
static char *ok(void) { return strdup("{\"status\":\"ok\"}\n"); }
static char *err(const char *m)
{
    char b[512]; snprintf(b, sizeof(b),
        "{\"status\":\"error\",\"message\":\"%s\"}\n", m);
    return strdup(b);
}

static const char *jstr(const char *l, const char *k, char *o, size_t ol)
{
    char s[128]; snprintf(s, sizeof(s), "\"%s\":\"", k);
    const char *p = strstr(l, s); if (!p) return NULL;
    p += strlen(s); size_t i = 0;
    while (*p && *p != '"' && i + 1 < ol) o[i++] = *p++;
    o[i] = '\0'; return o;
}
static long long jll(const char *l, const char *k)
{
    char s[128]; snprintf(s, sizeof(s), "\"%s\":", k);
    const char *p = strstr(l, s); if (!p) return -1;
    p += strlen(s); if (*p == '"') p++;
    return strtoll(p, NULL, 10);
}
static bool jbool(const char *l, const char *k)
{
    char s[128]; snprintf(s, sizeof(s), "\"%s\":true", k);
    return strstr(l, s) != NULL;
}

static uint64_t parse_rd_str(const char *s)
{
    unsigned long a = 0, b = 0;
    if (sscanf(s, "%lu:%lu", &a, &b) == 2)
        return evpn_rd_make((uint32_t)a, (uint16_t)b);
    return 0;
}

static bool parse_addr(const char *req, const char *key, evpn_addr_t *out)
{
    char s[INET6_ADDRSTRLEN] = {0};
    if (!jstr(req, key, s, sizeof(s))) return false;
    return evpn_addr_parse(s, out) == EVPN_OK;
}

static bool parse_mac_field(const char *req, const char *key, evpn_mac_t *out)
{
    char s[20] = {0};
    if (!jstr(req, key, s, sizeof(s))) return false;
    return evpn_mac_parse(s, out) == EVPN_OK;
}

/* -----------------------------------------------------------------------
 * EVI handlers
 * --------------------------------------------------------------------- */
static char *h_create_evi(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    long long l2  = jll(req, "l2_vni"); if (l2 <= 0) return err("missing l2_vni");
    long long l3  = jll(req, "l3_vni"); /* optional */
    long long vrf = jll(req, "vrf_id");
    long long flg = jll(req, "flags");
    int rc = evpn_evi_create(ctx, (uint32_t)eid, (uint32_t)l2,
                             l3 > 0 ? (uint32_t)l3 : 0,
                             vrf > 0 ? (uint32_t)vrf : 0,
                             flg > 0 ? (uint32_t)flg : 0);
    if (rc == EVPN_ERR_EXISTS) return err("EVI already exists");
    if (rc == EVPN_ERR_FULL)   return err("EVI table full");
    if (rc == EVPN_ERR_INVAL)  return err("invalid VNI");
    return rc == EVPN_OK ? ok() : err("failed");
}

static char *h_delete_evi(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    int rc = evpn_evi_delete(ctx, (uint32_t)eid);
    return rc == EVPN_OK ? ok() : err("EVI not found");
}

static char *h_list_evis(evpn_ctx_t *ctx)
{
    char *buf = malloc(EVPN_IPC_MAX_MSG); if (!buf) return err("oom");
    size_t pos = 0, left = EVPN_IPC_MAX_MSG;
    pos += snprintf(buf + pos, left - pos, "{\"status\":\"ok\",\"evis\":[");
    bool first = true;
    pthread_rwlock_rdlock(&ctx->evi_table.lock);
    for (uint32_t i = 0; i < ctx->evi_table.n_buckets; i++)
        for (evpn_evi_t *e = ctx->evi_table.buckets[i]; e; e = e->next) {
            char rd_s[32]; evpn_rd_to_str(e->rd, rd_s, sizeof(rd_s));
            char vtep_s[INET6_ADDRSTRLEN];
            evpn_addr_to_str(&e->local_vtep_ip, vtep_s, sizeof(vtep_s));
            pos += snprintf(buf + pos, left - pos,
                "%s{\"evi_id\":%u,\"l2_vni\":%u,\"l3_vni\":%u,"
                "\"vrf_id\":%u,\"flags\":%u,\"rd\":\"%s\","
                "\"local_vtep\":\"%s\","
                "\"n_macs\":%u,\"n_prefixes\":%u,\"n_imet\":%u,"
                "\"rx_mac\":%llu,\"tx_mac\":%llu,"
                "\"rx_pfx\":%llu,\"tx_pfx\":%llu}",
                first ? "" : ",",
                e->evi_id, e->l2_vni, e->l3_vni, e->vrf_id,
                e->flags, rd_s, vtep_s,
                e->mac_table.n_entries, e->pfx_table.n_entries, e->n_imet,
                (unsigned long long)e->rx_mac_routes,
                (unsigned long long)e->tx_mac_routes,
                (unsigned long long)e->rx_pfx_routes,
                (unsigned long long)e->tx_pfx_routes);
            first = false;
        }
    pthread_rwlock_unlock(&ctx->evi_table.lock);
    snprintf(buf + pos, left - pos, "]}\n");
    return buf;
}

static char *h_get_evi(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_evi_t *e = evpn_evi_find(ctx, (uint32_t)eid);
    if (!e) return err("EVI not found");
    char rd_s[32], vtep_s[INET6_ADDRSTRLEN], irb_ip_s[INET6_ADDRSTRLEN]="",
         irb_mac_s[20]="";
    evpn_rd_to_str(e->rd, rd_s, sizeof(rd_s));
    evpn_addr_to_str(&e->local_vtep_ip, vtep_s, sizeof(vtep_s));
    if (e->irb_configured) {
        evpn_addr_to_str(&e->irb_ip, irb_ip_s, sizeof(irb_ip_s));
        evpn_mac_to_str(&e->irb_mac, irb_mac_s, sizeof(irb_mac_s));
    }
    char *buf = malloc(1024); if (!buf) return err("oom");
    snprintf(buf, 1024,
        "{\"status\":\"ok\",\"evi_id\":%u,\"l2_vni\":%u,\"l3_vni\":%u,"
        "\"vrf_id\":%u,\"flags\":%u,\"rd\":\"%s\",\"encap\":%u,"
        "\"local_vtep\":\"%s\",\"n_rt_export\":%u,\"n_rt_import\":%u,"
        "\"n_macs\":%u,\"n_prefixes\":%u,\"n_imet\":%u,"
        "\"irb_ip\":\"%s\",\"irb_mac\":\"%s\"}\n",
        e->evi_id, e->l2_vni, e->l3_vni, e->vrf_id, e->flags,
        rd_s, e->encap, vtep_s, e->n_rt_export, e->n_rt_import,
        e->mac_table.n_entries, e->pfx_table.n_entries, e->n_imet,
        irb_ip_s, irb_mac_s);
    return buf;
}

static char *h_set_rd(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    char rd_s[32] = {0}; jstr(req, "rd", rd_s, sizeof(rd_s));
    uint64_t rd = parse_rd_str(rd_s);
    if (!rd) return err("invalid rd (format ASN:local)");
    return evpn_evi_set_rd(ctx, (uint32_t)eid, rd) == EVPN_OK
           ? ok() : err("EVI not found");
}

static char *h_add_rt(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    char rt_s[32] = {0}; jstr(req, "rt", rt_s, sizeof(rt_s));
    uint64_t rt = parse_rd_str(rt_s); if (!rt) return err("invalid rt");
    bool is_exp = jbool(req, "export");
    bool is_imp = jbool(req, "import");
    if (!is_exp && !is_imp) is_exp = is_imp = true; /* default: both */
    int rc = EVPN_OK;
    if (is_exp) rc = evpn_evi_add_rt(ctx, (uint32_t)eid, rt, true);
    if (rc == EVPN_OK && is_imp) rc = evpn_evi_add_rt(ctx, (uint32_t)eid, rt, false);
    if (rc == EVPN_ERR_FULL) return err("RT list full");
    return rc == EVPN_OK ? ok() : err("failed");
}

static char *h_del_rt(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    char rt_s[32] = {0}; jstr(req, "rt", rt_s, sizeof(rt_s));
    uint64_t rt = parse_rd_str(rt_s); if (!rt) return err("invalid rt");
    bool is_exp = jbool(req, "export");
    bool is_imp = jbool(req, "import");
    if (!is_exp && !is_imp) is_exp = is_imp = true;
    if (is_exp) evpn_evi_del_rt(ctx, (uint32_t)eid, rt, true);
    if (is_imp) evpn_evi_del_rt(ctx, (uint32_t)eid, rt, false);
    return ok();
}

static char *h_set_irb(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_addr_t ip; evpn_mac_t mac;
    if (!parse_addr(req, "ip", &ip))         return err("missing ip");
    if (!parse_mac_field(req, "mac", &mac))  return err("missing mac");
    int rc = evpn_evi_set_irb(ctx, (uint32_t)eid, &ip, &mac);
    return rc == EVPN_OK ? ok() : err("EVI not found");
}

/* -----------------------------------------------------------------------
 * VTEP handlers
 * --------------------------------------------------------------------- */
static char *h_add_vtep(evpn_ctx_t *ctx, const char *req)
{
    evpn_addr_t ip; if (!parse_addr(req, "ip", &ip)) return err("missing ip");
    long long enc = jll(req, "encap");
    long long flg = jll(req, "flags");
    int rc = evpn_vtep_add(ctx, &ip,
                           enc > 0 ? (uint8_t)enc : EVPN_ENCAP_VXLAN,
                           flg > 0 ? (uint32_t)flg : EVPN_VTEP_ACTIVE);
    if (rc == EVPN_ERR_EXISTS) return err("VTEP already exists");
    return rc == EVPN_OK ? ok() : err("failed");
}

static char *h_del_vtep(evpn_ctx_t *ctx, const char *req)
{
    evpn_addr_t ip; if (!parse_addr(req, "ip", &ip)) return err("missing ip");
    return evpn_vtep_del(ctx, &ip) == EVPN_OK ? ok() : err("VTEP not found");
}

static char *h_list_vteps(evpn_ctx_t *ctx)
{
    char *buf = malloc(EVPN_IPC_MAX_MSG); if (!buf) return err("oom");
    size_t pos = 0, left = EVPN_IPC_MAX_MSG;
    pos += snprintf(buf + pos, left - pos, "{\"status\":\"ok\",\"vteps\":[");
    bool first = true;
    pthread_rwlock_rdlock(&ctx->vtep_table.lock);
    for (uint32_t i = 0; i < ctx->vtep_table.n_buckets; i++)
        for (evpn_vtep_t *v = ctx->vtep_table.buckets[i]; v; v = v->next) {
            char ip_s[INET6_ADDRSTRLEN];
            evpn_addr_to_str(&v->ip, ip_s, sizeof(ip_s));
            pos += snprintf(buf + pos, left - pos,
                "%s{\"ip\":\"%s\",\"encap\":%u,\"flags\":%u,"
                "\"rx_pkts\":%llu,\"tx_pkts\":%llu}",
                first ? "" : ",", ip_s, v->encap, v->flags,
                (unsigned long long)v->rx_pkts,
                (unsigned long long)v->tx_pkts);
            first = false;
        }
    pthread_rwlock_unlock(&ctx->vtep_table.lock);
    snprintf(buf + pos, left - pos, "]}\n");
    return buf;
}

/* -----------------------------------------------------------------------
 * MAC-IP handlers
 * --------------------------------------------------------------------- */
static char *h_add_mac(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_mac_t mac; if (!parse_mac_field(req, "mac", &mac)) return err("missing mac");
    evpn_addr_t ip = {0}; parse_addr(req, "ip", &ip);
    evpn_addr_t vtep = {0}; parse_addr(req, "vtep", &vtep);
    long long flg = jll(req, "flags");
    long long oif = jll(req, "ifindex");
    char rd_s[32] = {0}; jstr(req, "rd", rd_s, sizeof(rd_s));
    uint64_t rd = parse_rd_str(rd_s);
    int rc = evpn_mac_add(ctx, (uint32_t)eid, &mac,
                          ip.af ? &ip : NULL,
                          flg > 0 ? (uint32_t)flg : EVPN_MAC_REMOTE,
                          vtep.af ? &vtep : NULL,
                          oif > 0 ? (uint32_t)oif : 0, rd);
    if (rc == EVPN_ERR_FULL)     return err("MAC table full");
    if (rc == EVPN_ERR_NOTFOUND) return err("EVI not found");
    return rc == EVPN_OK ? ok() : err("failed");
}

static char *h_del_mac(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_mac_t mac; if (!parse_mac_field(req, "mac", &mac)) return err("missing mac");
    evpn_addr_t ip = {0}; parse_addr(req, "ip", &ip);
    int rc = evpn_mac_del(ctx, (uint32_t)eid, &mac, ip.af ? &ip : NULL);
    return rc == EVPN_OK ? ok() : err("MAC not found");
}

static char *h_learn_mac(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_mac_t mac; if (!parse_mac_field(req, "mac", &mac)) return err("missing mac");
    evpn_addr_t ip = {0}; parse_addr(req, "ip", &ip);
    long long oif = jll(req, "ifindex");
    int rc = evpn_mac_learn(ctx, (uint32_t)eid, &mac,
                            ip.af ? &ip : NULL,
                            oif > 0 ? (uint32_t)oif : 0);
    return rc == EVPN_OK ? ok() : err("failed");
}

static char *h_list_macs(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_evi_t *evi = evpn_evi_find(ctx, (uint32_t)eid);
    if (!evi) return err("EVI not found");
    char *buf = malloc(EVPN_IPC_MAX_MSG); if (!buf) return err("oom");
    size_t pos = 0, left = EVPN_IPC_MAX_MSG;
    pos += snprintf(buf + pos, left - pos, "{\"status\":\"ok\",\"macs\":[");
    bool first = true;
    pthread_rwlock_rdlock(&evi->mac_table.lock);
    for (uint32_t i = 0; i < evi->mac_table.n_buckets; i++)
        for (evpn_mac_ip_t *m = evi->mac_table.buckets[i]; m; m = m->next) {
            char mac_s[20], ip_s[INET6_ADDRSTRLEN] = "", vtep_s[INET6_ADDRSTRLEN] = "";
            evpn_mac_to_str(&m->mac, mac_s, sizeof(mac_s));
            if (m->ip.af) evpn_addr_to_str(&m->ip, ip_s, sizeof(ip_s));
            if (m->vtep) evpn_addr_to_str(&m->vtep->ip, vtep_s, sizeof(vtep_s));
            pos += snprintf(buf + pos, left - pos,
                "%s{\"mac\":\"%s\",\"ip\":\"%s\",\"flags\":%u,"
                "\"vtep\":\"%s\",\"ifindex\":%u,\"hits\":%llu}",
                first ? "" : ",", mac_s, ip_s, m->flags,
                vtep_s, m->out_ifindex,
                (unsigned long long)m->hit_count);
            first = false;
            if (pos + 512 >= left) break;
        }
    pthread_rwlock_unlock(&evi->mac_table.lock);
    snprintf(buf + pos, left - pos, "]}\n");
    return buf;
}

static char *h_lookup_mac(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_mac_t mac; if (!parse_mac_field(req, "mac", &mac)) return err("missing mac");
    evpn_addr_t ip = {0}; parse_addr(req, "ip", &ip);
    evpn_mac_ip_t *m = evpn_mac_lookup(ctx, (uint32_t)eid, &mac, ip.af ? &ip : NULL);
    if (!m) return err("not found");
    char mac_s[20], ip_s[INET6_ADDRSTRLEN]="", vtep_s[INET6_ADDRSTRLEN]="";
    evpn_mac_to_str(&m->mac, mac_s, sizeof(mac_s));
    if (m->ip.af) evpn_addr_to_str(&m->ip, ip_s, sizeof(ip_s));
    if (m->vtep) evpn_addr_to_str(&m->vtep->ip, vtep_s, sizeof(vtep_s));
    char *buf = malloc(512);
    snprintf(buf, 512,
        "{\"status\":\"ok\",\"mac\":\"%s\",\"ip\":\"%s\","
        "\"flags\":%u,\"vtep\":\"%s\",\"ifindex\":%u}\n",
        mac_s, ip_s, m->flags, vtep_s, m->out_ifindex);
    return buf;
}

static char *h_flush_mac(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_addr_t vtep = {0}; parse_addr(req, "vtep", &vtep);
    int rc = evpn_mac_flush(ctx, (uint32_t)eid, vtep.af ? &vtep : NULL);
    return rc == EVPN_OK ? ok() : err("EVI not found");
}

/* -----------------------------------------------------------------------
 * IMET handlers
 * --------------------------------------------------------------------- */
static char *h_add_imet(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_addr_t vtep; if (!parse_addr(req, "vtep", &vtep)) return err("missing vtep");
    char rd_s[32] = {0}; jstr(req, "rd", rd_s, sizeof(rd_s));
    return evpn_imet_add(ctx, (uint32_t)eid, &vtep, parse_rd_str(rd_s)) == EVPN_OK
           ? ok() : err("failed");
}

static char *h_del_imet(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_addr_t vtep; if (!parse_addr(req, "vtep", &vtep)) return err("missing vtep");
    return evpn_imet_del(ctx, (uint32_t)eid, &vtep) == EVPN_OK
           ? ok() : err("not found");
}

static char *h_list_imet(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_evi_t *evi = evpn_evi_find(ctx, (uint32_t)eid);
    if (!evi) return err("EVI not found");
    char *buf = malloc(65536); if (!buf) return err("oom");
    size_t pos = 0, left = 65536;
    pos += snprintf(buf + pos, left - pos, "{\"status\":\"ok\",\"flood_list\":[");
    bool first = true;
    pthread_rwlock_rdlock(&evi->lock);
    for (evpn_imet_t *im = evi->imet_list; im; im = im->next) {
        char ip_s[INET6_ADDRSTRLEN], rd_s[32];
        evpn_addr_to_str(&im->vtep_ip, ip_s, sizeof(ip_s));
        evpn_rd_to_str(im->rd, rd_s, sizeof(rd_s));
        pos += snprintf(buf + pos, left - pos,
            "%s{\"vtep\":\"%s\",\"vni\":%u,\"rd\":\"%s\"}",
            first ? "" : ",", ip_s, im->vni, rd_s);
        first = false;
    }
    pthread_rwlock_unlock(&evi->lock);
    snprintf(buf + pos, left - pos, "]}\n");
    return buf;
}

/* -----------------------------------------------------------------------
 * IP-prefix handlers
 * --------------------------------------------------------------------- */
static char *h_add_prefix(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    char pfx_s[INET6_ADDRSTRLEN+4] = {0};
    if (!jstr(req, "prefix", pfx_s, sizeof(pfx_s))) return err("missing prefix");
    evpn_prefix_t pfx;
    if (evpn_prefix_parse(pfx_s, &pfx) != EVPN_OK) return err("invalid prefix");
    evpn_addr_t gw_ip = {0}; parse_addr(req, "gw_ip", &gw_ip);
    evpn_mac_t  gw_mac = {0}; parse_mac_field(req, "gw_mac", &gw_mac);
    evpn_addr_t vtep = {0}; parse_addr(req, "vtep", &vtep);
    char rd_s[32] = {0}; jstr(req, "rd", rd_s, sizeof(rd_s));
    bool local = jbool(req, "local");
    int rc = evpn_prefix_add(ctx, (uint32_t)eid, &pfx,
                             gw_ip.af ? &gw_ip : NULL, &gw_mac,
                             vtep.af ? &vtep : NULL,
                             parse_rd_str(rd_s), local);
    if (rc == EVPN_ERR_FULL)     return err("prefix table full");
    if (rc == EVPN_ERR_NOTFOUND) return err("EVI not found");
    return rc == EVPN_OK ? ok() : err("failed");
}

static char *h_del_prefix(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    char pfx_s[INET6_ADDRSTRLEN+4] = {0};
    if (!jstr(req, "prefix", pfx_s, sizeof(pfx_s))) return err("missing prefix");
    evpn_prefix_t pfx;
    if (evpn_prefix_parse(pfx_s, &pfx) != EVPN_OK) return err("invalid prefix");
    return evpn_prefix_del(ctx, (uint32_t)eid, &pfx) == EVPN_OK
           ? ok() : err("not found");
}

static char *h_list_prefixes(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_evi_t *evi = evpn_evi_find(ctx, (uint32_t)eid);
    if (!evi) return err("EVI not found");
    char *buf = malloc(EVPN_IPC_MAX_MSG); if (!buf) return err("oom");
    size_t pos = 0, left = EVPN_IPC_MAX_MSG;
    pos += snprintf(buf + pos, left - pos, "{\"status\":\"ok\",\"prefixes\":[");
    bool first = true;
    pthread_rwlock_rdlock(&evi->pfx_table.lock);
    for (uint32_t i = 0; i < evi->pfx_table.n_buckets; i++)
        for (evpn_ip_prefix_t *p = evi->pfx_table.buckets[i]; p; p = p->next) {
            char pfx_s[INET6_ADDRSTRLEN+4], gw_s[INET6_ADDRSTRLEN]="",
                 gw_mac_s[20]="", vtep_s[INET6_ADDRSTRLEN]="";
            evpn_prefix_to_str(&p->prefix, pfx_s, sizeof(pfx_s));
            if (p->gw_ip.af) evpn_addr_to_str(&p->gw_ip, gw_s, sizeof(gw_s));
            evpn_mac_to_str(&p->gw_mac, gw_mac_s, sizeof(gw_mac_s));
            if (p->vtep) evpn_addr_to_str(&p->vtep->ip, vtep_s, sizeof(vtep_s));
            pos += snprintf(buf + pos, left - pos,
                "%s{\"prefix\":\"%s\",\"gw_ip\":\"%s\","
                "\"gw_mac\":\"%s\",\"vtep\":\"%s\","
                "\"local\":%s,\"hits\":%llu}",
                first ? "" : ",", pfx_s, gw_s, gw_mac_s, vtep_s,
                p->local ? "true" : "false",
                (unsigned long long)p->hit_count);
            first = false;
        }
    pthread_rwlock_unlock(&evi->pfx_table.lock);
    snprintf(buf + pos, left - pos, "]}\n");
    return buf;
}

static char *h_lookup_prefix(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id"); if (eid <= 0) return err("missing evi_id");
    evpn_addr_t dst; if (!parse_addr(req, "dst", &dst)) return err("missing dst");
    evpn_ip_prefix_t *p = evpn_prefix_lookup(ctx, (uint32_t)eid, &dst);
    if (!p) return err("no route");
    char pfx_s[INET6_ADDRSTRLEN+4], gw_s[INET6_ADDRSTRLEN]="",
         gw_mac_s[20]="", vtep_s[INET6_ADDRSTRLEN]="";
    evpn_prefix_to_str(&p->prefix, pfx_s, sizeof(pfx_s));
    if (p->gw_ip.af) evpn_addr_to_str(&p->gw_ip, gw_s, sizeof(gw_s));
    evpn_mac_to_str(&p->gw_mac, gw_mac_s, sizeof(gw_mac_s));
    if (p->vtep) evpn_addr_to_str(&p->vtep->ip, vtep_s, sizeof(vtep_s));
    char *buf = malloc(512);
    snprintf(buf, 512,
        "{\"status\":\"ok\",\"prefix\":\"%s\","
        "\"gw_ip\":\"%s\",\"gw_mac\":\"%s\","
        "\"vtep\":\"%s\",\"local\":%s}\n",
        pfx_s, gw_s, gw_mac_s, vtep_s,
        p->local ? "true" : "false");
    return buf;
}

/* -----------------------------------------------------------------------
 * ES handlers
 * --------------------------------------------------------------------- */
static char *h_add_es(evpn_ctx_t *ctx, const char *req)
{
    char esi_s[40] = {0}; if (!jstr(req, "esi", esi_s, sizeof(esi_s))) return err("missing esi");
    evpn_esi_t esi; if (evpn_esi_parse(esi_s, &esi) != EVPN_OK) return err("invalid esi");
    long long type = jll(req, "es_type");
    long long ld   = jll(req, "local_disc");
    evpn_mac_t mac = {0}; parse_mac_field(req, "sys_mac", &mac);
    int rc = evpn_es_add(ctx, &esi, type > 0 ? (uint8_t)type : 0, &mac,
                         ld > 0 ? (uint32_t)ld : 0);
    if (rc == EVPN_ERR_EXISTS) return err("ES already exists");
    return rc == EVPN_OK ? ok() : err("failed");
}

static char *h_del_es(evpn_ctx_t *ctx, const char *req)
{
    char esi_s[40] = {0}; if (!jstr(req, "esi", esi_s, sizeof(esi_s))) return err("missing esi");
    evpn_esi_t esi; if (evpn_esi_parse(esi_s, &esi) != EVPN_OK) return err("invalid esi");
    return evpn_es_del(ctx, &esi) == EVPN_OK ? ok() : err("ES not found");
}

static char *h_list_es(evpn_ctx_t *ctx)
{
    char *buf = malloc(65536); if (!buf) return err("oom");
    size_t pos = 0, left = 65536;
    pos += snprintf(buf + pos, left - pos, "{\"status\":\"ok\",\"segments\":[");
    bool first = true;
    pthread_rwlock_rdlock(&ctx->es_lock);
    for (evpn_es_t *es = ctx->es_list; es; es = es->next) {
        char esi_s[40], mac_s[20];
        evpn_esi_to_str(&es->esi, esi_s, sizeof(esi_s));
        evpn_mac_to_str(&es->sys_mac, mac_s, sizeof(mac_s));
        pos += snprintf(buf + pos, left - pos,
            "%s{\"esi\":\"%s\",\"type\":%u,\"sys_mac\":\"%s\","
            "\"local_disc\":%u,\"df_local\":%s}",
            first ? "" : ",", esi_s, es->type, mac_s,
            es->local_disc, es->df_local ? "true" : "false");
        first = false;
    }
    pthread_rwlock_unlock(&ctx->es_lock);
    snprintf(buf + pos, left - pos, "]}\n");
    return buf;
}

/* -----------------------------------------------------------------------
 * Stats
 * --------------------------------------------------------------------- */
static char *h_get_stats(evpn_ctx_t *ctx, const char *req)
{
    long long eid = jll(req, "evi_id");
    if (eid <= 0) {
        /* Global summary */
        char *buf = malloc(512);
        snprintf(buf, 512,
            "{\"status\":\"ok\",\"n_evis\":%u,\"n_vteps\":%u,\"n_es\":%u}\n",
            ctx->evi_table.n_evis, ctx->vtep_table.n_vteps, ctx->n_es);
        return buf;
    }
    evpn_evi_t *e = evpn_evi_find(ctx, (uint32_t)eid);
    if (!e) return err("EVI not found");
    char *buf = malloc(512);
    snprintf(buf, 512,
        "{\"status\":\"ok\",\"evi_id\":%u,"
        "\"n_macs\":%u,\"n_prefixes\":%u,\"n_imet\":%u,"
        "\"rx_mac\":%llu,\"tx_mac\":%llu,"
        "\"rx_pfx\":%llu,\"tx_pfx\":%llu,"
        "\"arp_suppressed\":%llu}\n",
        e->evi_id,
        e->mac_table.n_entries, e->pfx_table.n_entries, e->n_imet,
        (unsigned long long)e->rx_mac_routes,
        (unsigned long long)e->tx_mac_routes,
        (unsigned long long)e->rx_pfx_routes,
        (unsigned long long)e->tx_pfx_routes,
        (unsigned long long)e->arp_suppressed);
    return buf;
}

/* -----------------------------------------------------------------------
 * Dispatch
 * --------------------------------------------------------------------- */
char *evpn_ipc_handle(evpn_ctx_t *ctx, const char *req, size_t req_len)
{
    (void)req_len;
    char cmd[64] = {0}; jstr(req, "cmd", cmd, sizeof(cmd));

    if (!strcmp(cmd, EVPN_CMD_CREATE_EVI))    return h_create_evi(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_DELETE_EVI))    return h_delete_evi(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_LIST_EVIS))     return h_list_evis(ctx);
    if (!strcmp(cmd, EVPN_CMD_GET_EVI))       return h_get_evi(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_SET_EVI_RD))    return h_set_rd(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_ADD_EVI_RT))    return h_add_rt(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_DEL_EVI_RT))    return h_del_rt(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_SET_IRB))       return h_set_irb(ctx, req);

    if (!strcmp(cmd, EVPN_CMD_ADD_VTEP))      return h_add_vtep(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_DEL_VTEP))      return h_del_vtep(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_LIST_VTEPS))    return h_list_vteps(ctx);

    if (!strcmp(cmd, EVPN_CMD_ADD_MAC))       return h_add_mac(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_DEL_MAC))       return h_del_mac(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_LEARN_MAC))     return h_learn_mac(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_LIST_MACS))     return h_list_macs(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_LOOKUP_MAC))    return h_lookup_mac(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_FLUSH_MAC))     return h_flush_mac(ctx, req);

    if (!strcmp(cmd, EVPN_CMD_ADD_IMET))      return h_add_imet(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_DEL_IMET))      return h_del_imet(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_LIST_IMET))     return h_list_imet(ctx, req);

    if (!strcmp(cmd, EVPN_CMD_ADD_PREFIX))    return h_add_prefix(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_DEL_PREFIX))    return h_del_prefix(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_LIST_PREFIXES)) return h_list_prefixes(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_LOOKUP_PREFIX)) return h_lookup_prefix(ctx, req);

    if (!strcmp(cmd, EVPN_CMD_ADD_ES))        return h_add_es(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_DEL_ES))        return h_del_es(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_LIST_ES))       return h_list_es(ctx);

    if (!strcmp(cmd, EVPN_CMD_GET_STATS))     return h_get_stats(ctx, req);
    if (!strcmp(cmd, EVPN_CMD_CLEAR_STATS)) {
        long long eid = jll(req, "evi_id");
        if (eid > 0) {
            evpn_evi_t *e = evpn_evi_find(ctx, (uint32_t)eid);
            if (!e) return err("EVI not found");
            pthread_rwlock_wrlock(&e->lock);
            e->rx_mac_routes = e->tx_mac_routes = 0;
            e->rx_pfx_routes = e->tx_pfx_routes = 0;
            e->arp_suppressed = 0;
            pthread_rwlock_unlock(&e->lock);
        }
        return ok();
    }
    if (!strcmp(cmd, EVPN_CMD_DUMP_CONFIG)) {
        char path[256] = "evpn_runtime_config.json";
        jstr(req, "path", path, sizeof(path));
        char *buf = malloc(512);
        snprintf(buf, 512, "{\"status\":\"%s\",\"path\":\"%s\"}\n",
                 evpn_save_config(ctx, path) == EVPN_OK ? "ok" : "error", path);
        return buf;
    }
    if (!strcmp(cmd, EVPN_CMD_LOAD_CONFIG)) {
        char path[256] = "evpn_runtime_config.json";
        jstr(req, "path", path, sizeof(path));
        return evpn_load_config(ctx, path) == EVPN_OK ? ok() : err("load failed");
    }
    return err("unknown command");
}

/* -----------------------------------------------------------------------
 * IPC server
 * --------------------------------------------------------------------- */
int evpn_ipc_init(evpn_ctx_t *ctx)
{
    struct sockaddr_un addr = {0}; addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%.*s",
             (int)(sizeof(addr.sun_path) - 1), ctx->sock_path);
    unlink(ctx->sock_path);
    ctx->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx->sock_fd < 0) return EVPN_ERR_INVAL;
    if (bind(ctx->sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(ctx->sock_fd, 16) < 0) {
        close(ctx->sock_fd); ctx->sock_fd = -1; return EVPN_ERR_INVAL;
    }
    return EVPN_OK;
}

void evpn_ipc_stop(evpn_ctx_t *ctx)
{
    if (ctx->sock_fd >= 0) { close(ctx->sock_fd); ctx->sock_fd = -1; }
    unlink(ctx->sock_path);
}

void *evpn_ipc_thread(void *arg)
{
    evpn_ctx_t *ctx = arg;
    char buf[EVPN_IPC_MAX_MSG];
    while (ctx->running) {
        int client = accept(ctx->sock_fd, NULL, NULL);
        if (client < 0) { if (!ctx->running) break; continue; }
        ssize_t n = recv(client, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            char *resp = evpn_ipc_handle(ctx, buf, (size_t)n);
            if (resp) { send(client, resp, strlen(resp), 0); free(resp); }
        }
        close(client);
    }
    return NULL;
}
