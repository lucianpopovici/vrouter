/*
 * test_evpn.c — BGP EVPN module unit + stress tests
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "evpn.h"

#define PASS(n)    printf("  [PASS] %s\n", n)
#define FAIL(n)    do { printf("  [FAIL] %s\n", n); g_failures++; } while(0)
#define CHECK(e,n) do { if(e) PASS(n); else FAIL(n); } while(0)

static int g_failures = 0;

static evpn_addr_t maddr(const char *s)
{ evpn_addr_t a; evpn_addr_parse(s, &a); return a; }

static evpn_mac_t mmac(const char *s)
{ evpn_mac_t m; evpn_mac_parse(s, &m); return m; }

static evpn_prefix_t mpfx(const char *s)
{ evpn_prefix_t p; evpn_prefix_parse(s, &p); return p; }

static evpn_ctx_t *make_ctx(void)
{
    evpn_ctx_t *ctx = evpn_ctx_create(); assert(ctx);
    evpn_addr_t vtep = maddr("10.0.0.1");
    ctx->local_vtep_ip = vtep;
    ctx->local_asn     = 65001;
    return ctx;
}

/* -----------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */
static void test_helpers(void)
{
    printf("[test_helpers]\n");
    evpn_addr_t a;
    CHECK(evpn_addr_parse("10.1.2.3",    &a) == EVPN_OK && a.af == AF_INET,  "v4 parse");
    CHECK(evpn_addr_parse("2001:db8::1", &a) == EVPN_OK && a.af == AF_INET6, "v6 parse");
    CHECK(evpn_addr_parse("bad", &a)         == EVPN_ERR_INVAL,              "bad addr");

    evpn_prefix_t pfx;
    CHECK(evpn_prefix_parse("10.0.0.0/8",   &pfx) == EVPN_OK && pfx.plen == 8,  "v4 prefix");
    CHECK(evpn_prefix_parse("2001:db8::/32", &pfx) == EVPN_OK && pfx.plen == 32, "v6 prefix");

    evpn_mac_t mac;
    CHECK(evpn_mac_parse("aa:bb:cc:dd:ee:ff", &mac) == EVPN_OK, "mac parse");
    char buf[20]; evpn_mac_to_str(&mac, buf, sizeof(buf));
    CHECK(strcmp(buf, "aa:bb:cc:dd:ee:ff") == 0, "mac to_str");

    evpn_esi_t esi;
    CHECK(evpn_esi_parse("00:01:02:03:04:05:06:07:08:09", &esi) == EVPN_OK, "esi parse");
    char esi_buf[40]; evpn_esi_to_str(&esi, esi_buf, sizeof(esi_buf));
    CHECK(strcmp(esi_buf, "00:01:02:03:04:05:06:07:08:09") == 0, "esi to_str");

    uint64_t rd = evpn_rd_make(65001, 100);
    char rd_buf[32]; evpn_rd_to_str(rd, rd_buf, sizeof(rd_buf));
    CHECK(strcmp(rd_buf, "65001:100") == 0, "rd make+to_str");

    /* LPM containment */
    evpn_prefix_t net24 = mpfx("10.1.2.0/24");
    evpn_addr_t   host  = maddr("10.1.2.50");
    evpn_addr_t   other = maddr("10.1.3.1");
    CHECK(evpn_prefix_contains(&net24, &host),  "prefix_contains yes");
    CHECK(!evpn_prefix_contains(&net24, &other), "prefix_contains no");
}

/* -----------------------------------------------------------------------
 * EVI CRUD
 * --------------------------------------------------------------------- */
static void test_evi_crud(void)
{
    printf("[test_evi_crud]\n");
    evpn_ctx_t *ctx = make_ctx();

    CHECK(evpn_evi_create(ctx, 1, 10000, 0,     0, 0) == EVPN_OK,        "create L2-only EVI");
    CHECK(evpn_evi_create(ctx, 2, 20000, 20001, 1, 0) == EVPN_OK,        "create L3 EVI");
    CHECK(evpn_evi_create(ctx, 1, 10000, 0,     0, 0) == EVPN_ERR_EXISTS,"dup rejected");
    CHECK(evpn_evi_create(ctx, 9, 0, 0, 0, 0)         == EVPN_ERR_INVAL, "invalid VNI 0");

    evpn_evi_t *e = evpn_evi_find(ctx, 1);
    CHECK(e != NULL,                  "find by evi_id");
    CHECK(e->l2_vni == 10000,         "l2_vni stored");
    CHECK(e->n_rt_export == 1,        "auto RT-export set");
    CHECK(e->n_rt_import == 1,        "auto RT-import set");

    CHECK(evpn_evi_find_by_vni(ctx, 20000) != NULL, "find by l2_vni");
    CHECK(evpn_evi_find_by_vni(ctx, 20001) != NULL, "find by l3_vni");
    CHECK(evpn_evi_find(ctx, 99)           == NULL,  "missing=NULL");

    /* RD and RT management */
    uint64_t rd = evpn_rd_make(65001, 1);
    CHECK(evpn_evi_set_rd(ctx, 1, rd) == EVPN_OK, "set_rd");
    CHECK(evpn_evi_find(ctx, 1)->rd == rd,         "rd stored");

    uint64_t rt = evpn_rt_make(65001, 999);
    CHECK(evpn_evi_add_rt(ctx, 1, rt, true)  == EVPN_OK, "add export RT");
    CHECK(evpn_evi_add_rt(ctx, 1, rt, false) == EVPN_OK, "add import RT");
    CHECK(evpn_evi_del_rt(ctx, 1, rt, true)  == EVPN_OK, "del export RT");

    /* IRB */
    evpn_addr_t irb_ip = maddr("192.168.100.1");
    evpn_mac_t  irb_mac = mmac("00:11:22:33:44:55");
    CHECK(evpn_evi_set_irb(ctx, 1, &irb_ip, &irb_mac) == EVPN_OK, "set_irb");
    CHECK(evpn_evi_find(ctx, 1)->irb_configured, "irb configured flag");

    CHECK(evpn_evi_delete(ctx, 1) == EVPN_OK,    "delete EVI 1");
    CHECK(evpn_evi_find(ctx, 1)   == NULL,        "gone after delete");

    evpn_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * VTEP
 * --------------------------------------------------------------------- */
static void test_vtep(void)
{
    printf("[test_vtep]\n");
    evpn_ctx_t *ctx = make_ctx();

    evpn_addr_t v1 = maddr("10.0.0.2"), v2 = maddr("10.0.0.3");
    CHECK(evpn_vtep_add(ctx, &v1, EVPN_ENCAP_VXLAN, EVPN_VTEP_ACTIVE) == EVPN_OK, "add v1");
    CHECK(evpn_vtep_add(ctx, &v2, EVPN_ENCAP_VXLAN, EVPN_VTEP_ACTIVE) == EVPN_OK, "add v2");
    CHECK(evpn_vtep_add(ctx, &v1, EVPN_ENCAP_VXLAN, 0) == EVPN_ERR_EXISTS, "dup rejected");
    CHECK(evpn_vtep_find(ctx, &v1) != NULL, "find v1");
    CHECK(evpn_vtep_find(ctx, &v2) != NULL, "find v2");
    evpn_addr_t missing = maddr("1.2.3.4");
    CHECK(evpn_vtep_find(ctx, &missing) == NULL, "missing=NULL");
    CHECK(evpn_vtep_del(ctx, &v1) == EVPN_OK,   "del v1");
    CHECK(evpn_vtep_find(ctx, &v1) == NULL,      "gone after del");

    evpn_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * MAC-IP table (RT-2)
 * --------------------------------------------------------------------- */
static void test_mac_ip(void)
{
    printf("[test_mac_ip]\n");
    evpn_ctx_t *ctx = make_ctx();
    evpn_evi_create(ctx, 1, 10000, 0, 0, 0);

    evpn_addr_t vtep_ip = maddr("10.0.0.2");
    evpn_vtep_add(ctx, &vtep_ip, EVPN_ENCAP_VXLAN, EVPN_VTEP_ACTIVE);

    evpn_mac_t mac1 = mmac("aa:bb:cc:00:00:01");
    evpn_mac_t mac2 = mmac("aa:bb:cc:00:00:02");
    evpn_addr_t ip1 = maddr("192.168.1.10");
    evpn_addr_t ip2 = maddr("192.168.1.11");
    uint64_t rd = evpn_rd_make(65002, 1);

    /* Remote MAC+IP */
    CHECK(evpn_mac_add(ctx, 1, &mac1, &ip1, EVPN_MAC_REMOTE,
                       &vtep_ip, 0, rd) == EVPN_OK, "add remote mac+ip");
    /* Pure MAC (no IP) */
    CHECK(evpn_mac_add(ctx, 1, &mac2, NULL, EVPN_MAC_REMOTE,
                       &vtep_ip, 0, rd) == EVPN_OK, "add pure MAC");
    /* Local learn */
    CHECK(evpn_mac_learn(ctx, 1, &mac1, &ip2, 3) == EVPN_OK, "learn local (update)");

    evpn_mac_ip_t *m = evpn_mac_lookup(ctx, 1, &mac1, &ip1);
    CHECK(m != NULL,                      "lookup mac+ip1");
    CHECK(m->vtep != NULL,               "vtep pointer set");
    CHECK(m->hit_count == 1,             "hit counter incremented");

    m = evpn_mac_lookup(ctx, 1, &mac2, NULL);
    CHECK(m != NULL,                      "lookup pure-MAC");

    CHECK(evpn_mac_del(ctx, 1, &mac2, NULL) == EVPN_OK,        "del pure-MAC");
    CHECK(evpn_mac_lookup(ctx, 1, &mac2, NULL) == NULL,         "gone after del");

    /* Flush all remote MACs */
    evpn_mac_t mac3 = mmac("aa:bb:cc:00:00:03");
    evpn_mac_add(ctx, 1, &mac3, NULL, EVPN_MAC_REMOTE, &vtep_ip, 0, rd);
    CHECK(evpn_mac_flush(ctx, 1, NULL) == EVPN_OK, "flush all remote");
    CHECK(evpn_mac_lookup(ctx, 1, &mac3, NULL) == NULL, "mac3 flushed");

    /* EVI not found */
    CHECK(evpn_mac_add(ctx, 99, &mac1, NULL, 0, NULL, 0, 0) == EVPN_ERR_NOTFOUND,
          "unknown EVI rejected");

    evpn_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * IMET (RT-3) flood list
 * --------------------------------------------------------------------- */
static void test_imet(void)
{
    printf("[test_imet]\n");
    evpn_ctx_t *ctx = make_ctx();
    evpn_evi_create(ctx, 1, 10000, 0, 0, 0);

    evpn_addr_t v1 = maddr("10.0.0.2"), v2 = maddr("10.0.0.3");
    uint64_t rd1 = evpn_rd_make(65002, 1), rd2 = evpn_rd_make(65003, 1);

    CHECK(evpn_imet_add(ctx, 1, &v1, rd1) == EVPN_OK, "add imet v1");
    CHECK(evpn_imet_add(ctx, 1, &v2, rd2) == EVPN_OK, "add imet v2");
    /* Duplicate → update */
    CHECK(evpn_imet_add(ctx, 1, &v1, rd1) == EVPN_OK, "dup imet updates");
    CHECK(evpn_evi_find(ctx, 1)->n_imet == 2, "flood list has 2 entries");

    CHECK(evpn_imet_del(ctx, 1, &v1) == EVPN_OK,   "del imet v1");
    CHECK(evpn_evi_find(ctx, 1)->n_imet == 1,        "flood list has 1 entry");
    CHECK(evpn_imet_del(ctx, 1, &v1) == EVPN_ERR_NOTFOUND, "del missing=NOTFOUND");

    evpn_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * IP-prefix table (RT-5) with LPM
 * --------------------------------------------------------------------- */
static void test_prefix(void)
{
    printf("[test_prefix]\n");
    evpn_ctx_t *ctx = make_ctx();
    evpn_evi_create(ctx, 1, 10000, 10001, 0, 0);

    evpn_addr_t vtep1 = maddr("10.0.0.2"), vtep2 = maddr("10.0.0.3");
    evpn_vtep_add(ctx, &vtep1, EVPN_ENCAP_VXLAN, EVPN_VTEP_ACTIVE);
    evpn_vtep_add(ctx, &vtep2, EVPN_ENCAP_VXLAN, EVPN_VTEP_ACTIVE);

    evpn_prefix_t net8   = mpfx("10.0.0.0/8");
    evpn_prefix_t net24  = mpfx("10.1.2.0/24");
    evpn_prefix_t net6   = mpfx("2001:db8::/32");
    evpn_addr_t   gw1    = maddr("10.0.0.1");
    evpn_addr_t   gw6    = maddr("fe80::1");
    evpn_mac_t    gw_mac = mmac("00:aa:bb:cc:dd:ee");
    uint64_t      rd     = evpn_rd_make(65002, 1);

    CHECK(evpn_prefix_add(ctx, 1, &net8,  &gw1, &gw_mac, &vtep1, rd, false) == EVPN_OK,
          "add /8 from vtep1");
    CHECK(evpn_prefix_add(ctx, 1, &net24, &gw1, &gw_mac, &vtep2, rd, false) == EVPN_OK,
          "add /24 from vtep2");
    CHECK(evpn_prefix_add(ctx, 1, &net6,  &gw6, &gw_mac, &vtep1, rd, false) == EVPN_OK,
          "add v6 /32");

    /* LPM: 10.1.2.5 → /24 (most specific) */
    evpn_addr_t dst = maddr("10.1.2.5");
    evpn_ip_prefix_t *p = evpn_prefix_lookup(ctx, 1, &dst);
    CHECK(p != NULL,               "lookup 10.1.2.5 found");
    CHECK(p->prefix.plen == 24,    "LPM chose /24");
    CHECK(p->vtep != NULL,         "VTEP pointer resolved");

    /* LPM: 10.5.0.1 → /8 */
    dst = maddr("10.5.0.1");
    p = evpn_prefix_lookup(ctx, 1, &dst);
    CHECK(p != NULL,            "lookup 10.5.0.1 found");
    CHECK(p->prefix.plen == 8,  "LPM chose /8");

    /* Miss */
    dst = maddr("8.8.8.8");
    CHECK(evpn_prefix_lookup(ctx, 1, &dst) == NULL, "no route for 8.8.8.8");

    /* v6 */
    dst = maddr("2001:db8::dead");
    p = evpn_prefix_lookup(ctx, 1, &dst);
    CHECK(p != NULL && p->prefix.plen == 32, "v6 LPM /32");

    /* Update existing */
    CHECK(evpn_prefix_add(ctx, 1, &net8, &vtep2, &gw_mac, &vtep2, rd, true) == EVPN_OK,
          "update /8 (local)");
    dst = maddr("10.5.0.1");
    p = evpn_prefix_lookup(ctx, 1, &dst);
    CHECK(p && p->local, "updated to local");

    /* Delete */
    CHECK(evpn_prefix_del(ctx, 1, &net24) == EVPN_OK, "del /24");
    dst = maddr("10.1.2.5");
    p = evpn_prefix_lookup(ctx, 1, &dst);
    CHECK(p && p->prefix.plen == 8, "falls back to /8 after /24 del");

    evpn_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Ethernet Segment (RT-4)
 * --------------------------------------------------------------------- */
static void test_es(void)
{
    printf("[test_es]\n");
    evpn_ctx_t *ctx = make_ctx();

    evpn_esi_t esi1, esi2;
    evpn_esi_parse("00:01:02:03:04:05:06:07:08:09", &esi1);
    evpn_esi_parse("00:0a:0b:0c:0d:0e:0f:10:11:12", &esi2);
    evpn_mac_t sys_mac = mmac("aa:bb:cc:dd:ee:ff");

    CHECK(evpn_es_add(ctx, &esi1, 1, &sys_mac, 100) == EVPN_OK,        "add ES1");
    CHECK(evpn_es_add(ctx, &esi2, 0, NULL,      0)   == EVPN_OK,        "add ES2");
    CHECK(evpn_es_add(ctx, &esi1, 1, &sys_mac, 100) == EVPN_ERR_EXISTS, "dup rejected");
    CHECK(evpn_es_find(ctx, &esi1) != NULL, "find ES1");
    CHECK(evpn_es_find(ctx, &esi2) != NULL, "find ES2");
    CHECK(ctx->n_es == 2, "n_es == 2");
    CHECK(evpn_es_del(ctx, &esi1) == EVPN_OK,  "del ES1");
    CHECK(evpn_es_find(ctx, &esi1) == NULL,     "gone after del");
    CHECK(ctx->n_es == 1, "n_es == 1");

    evpn_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Persistence round-trip
 * --------------------------------------------------------------------- */
static void test_persistence(void)
{
    printf("[test_persistence]\n");
    const char *path = "/tmp/evpn_test_config.json";
    evpn_ctx_t *ctx = make_ctx();

    /* Setup */
    evpn_addr_t vtep2 = maddr("10.0.0.2");
    evpn_vtep_add(ctx, &vtep2, EVPN_ENCAP_VXLAN, EVPN_VTEP_ACTIVE);
    evpn_evi_create(ctx, 1, 10000, 10001, 0, EVPN_EVI_SYMMETRIC);
    evpn_evi_create(ctx, 2, 20000, 0,     0, 0);

    uint64_t rt = evpn_rt_make(65001, 9999);
    evpn_evi_add_rt(ctx, 1, rt, true);
    evpn_evi_add_rt(ctx, 1, rt, false);

    evpn_addr_t irb_ip = maddr("192.168.1.1");
    evpn_mac_t  irb_mac = mmac("00:11:22:33:44:55");
    evpn_evi_set_irb(ctx, 1, &irb_ip, &irb_mac);

    evpn_mac_t mac = mmac("aa:bb:cc:00:00:01");
    evpn_addr_t mac_ip = maddr("192.168.1.10");
    uint64_t rd = evpn_rd_make(65002, 1);
    evpn_mac_add(ctx, 1, &mac, &mac_ip, EVPN_MAC_REMOTE, &vtep2, 0, rd);

    evpn_imet_add(ctx, 1, &vtep2, rd);

    evpn_prefix_t pfx = mpfx("172.16.0.0/16");
    evpn_addr_t   gw  = maddr("10.0.0.2");
    evpn_mac_t    gw_mac = mmac("00:aa:bb:cc:dd:ee");
    evpn_prefix_add(ctx, 1, &pfx, &gw, &gw_mac, &vtep2, rd, false);

    evpn_esi_t esi; evpn_esi_parse("00:01:02:03:04:05:06:07:08:09", &esi);
    evpn_es_add(ctx, &esi, 1, &irb_mac, 100);

    CHECK(evpn_save_config(ctx, path) == EVPN_OK, "save");
    evpn_ctx_destroy(ctx);

    /* Reload */
    ctx = make_ctx();
    CHECK(evpn_load_config(ctx, path) == EVPN_OK, "load");

    CHECK(evpn_evi_find(ctx, 1) != NULL,        "EVI 1 restored");
    CHECK(evpn_evi_find(ctx, 2) != NULL,        "EVI 2 restored");
    CHECK(evpn_evi_find(ctx, 1)->irb_configured,"IRB restored");
    CHECK(evpn_vtep_find(ctx, &vtep2) != NULL,  "VTEP restored");
    CHECK(ctx->n_es == 1,                       "ES restored");

    evpn_mac_ip_t *m = evpn_mac_lookup(ctx, 1, &mac, &mac_ip);
    CHECK(m != NULL, "MAC-IP restored");

    CHECK(evpn_evi_find(ctx, 1)->n_imet == 1, "IMET restored");

    evpn_addr_t dst = maddr("172.16.5.1");
    evpn_ip_prefix_t *p = evpn_prefix_lookup(ctx, 1, &dst);
    CHECK(p != NULL && p->prefix.plen == 16, "prefix restored");

    evpn_ctx_destroy(ctx);
    unlink(path);
}

/* -----------------------------------------------------------------------
 * Stress: concurrent MAC installs + lookups across 2 EVIs
 * --------------------------------------------------------------------- */
#define STRESS_THREADS 8
#define STRESS_OPS     2000

typedef struct { evpn_ctx_t *ctx; int id; uint32_t evi_id; } sarg_t;

static void *stress_writer(void *arg)
{
    sarg_t *a = arg;
    evpn_addr_t vtep = maddr("10.0.0.2");
    for (int i = 0; i < STRESS_OPS; i++) {
        evpn_mac_t mac;
        mac.b[0] = 0xaa; mac.b[1] = (uint8_t)a->id;
        mac.b[2] = (uint8_t)(i >> 8); mac.b[3] = (uint8_t)i;
        mac.b[4] = 0; mac.b[5] = 0;
        char ip_s[32]; snprintf(ip_s, sizeof(ip_s), "10.%d.%d.%d",
                                a->id & 0xff, (i >> 8) & 0xff, i & 0xff);
        evpn_addr_t ip = maddr(ip_s);
        uint64_t rd = evpn_rd_make(65000 + a->id, (uint16_t)i);
        evpn_mac_add(a->ctx, a->evi_id, &mac, &ip,
                     EVPN_MAC_REMOTE, &vtep, 0, rd);
    }
    return NULL;
}

static void *stress_reader(void *arg)
{
    sarg_t *a = arg;
    for (int i = 0; i < STRESS_OPS; i++) {
        evpn_mac_t mac; memset(&mac, 0, sizeof(mac)); mac.b[0] = 0xaa;
        evpn_mac_lookup(a->ctx, a->evi_id, &mac, NULL);
        evpn_addr_t dst = maddr("10.1.2.3");
        evpn_prefix_lookup(a->ctx, a->evi_id, &dst);
    }
    return NULL;
}

static void test_stress(void)
{
    printf("[test_stress] %d threads × %d ops\n", STRESS_THREADS, STRESS_OPS);
    evpn_ctx_t *ctx = make_ctx();
    evpn_evi_create(ctx, 1, 10000, 0, 0, 0);
    evpn_evi_create(ctx, 2, 20000, 0, 0, 0);
    evpn_addr_t vtep = maddr("10.0.0.2");
    evpn_vtep_add(ctx, &vtep, EVPN_ENCAP_VXLAN, EVPN_VTEP_ACTIVE);

    pthread_t threads[STRESS_THREADS]; sarg_t args[STRESS_THREADS];
    for (int i = 0; i < STRESS_THREADS; i++) {
        args[i].ctx    = ctx;
        args[i].id     = i;
        args[i].evi_id = (i % 2) + 1;
        if (i < STRESS_THREADS / 2)
            pthread_create(&threads[i], NULL, stress_writer, &args[i]);
        else
            pthread_create(&threads[i], NULL, stress_reader, &args[i]);
    }
    for (int i = 0; i < STRESS_THREADS; i++) pthread_join(threads[i], NULL);
    CHECK(1, "stress completed without crash");
    evpn_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Main
 * --------------------------------------------------------------------- */
int main(void)
{
    printf("=== BGP EVPN module tests ===\n\n");
    test_helpers();
    test_evi_crud();
    test_vtep();
    test_mac_ip();
    test_imet();
    test_prefix();
    test_es();
    test_persistence();
    test_stress();
    printf("\n=== %s (%d failure%s) ===\n",
           g_failures == 0 ? "ALL PASS" : "FAIL",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
