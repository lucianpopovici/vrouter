/*
 * test_ip.c — unit and thread-safety stress tests for the IP module.
 *
 * Build:   (handled by Makefile)
 * Run:     ./test_ip
 * Returns: 0 on success, non-zero on failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "ip.h"

#define PASS(name) printf("  [PASS] %s\n", name)
#define FAIL(name) do { printf("  [FAIL] %s\n", name); g_failures++; } while(0)
#define CHECK(expr, name) do { if (expr) PASS(name); else FAIL(name); } while(0)

static int g_failures = 0;

/* -----------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */
static ip_prefix_t make_prefix4(const char *str)
{
    ip_prefix_t p;
    ip_prefix_parse(str, &p);
    return p;
}

static ip_prefix_t make_prefix6(const char *str)
{
    ip_prefix_t p;
    ip_prefix_parse(str, &p);
    return p;
}

static ip_addr_t make_addr(const char *str)
{
    ip_addr_t a;
    ip_addr_parse(str, &a);
    return a;
}

/* -----------------------------------------------------------------------
 * Test: address parsing
 * --------------------------------------------------------------------- */
static void test_addr_parse(void)
{
    printf("[test_addr_parse]\n");
    ip_addr_t a;
    CHECK(ip_addr_parse("192.168.1.1",  &a) == IP_OK && a.af == AF_INET,  "v4 parse ok");
    CHECK(ip_addr_parse("2001:db8::1",  &a) == IP_OK && a.af == AF_INET6, "v6 parse ok");
    CHECK(ip_addr_parse("not-an-addr",  &a) == IP_ERR_INVAL,              "bad addr rejected");
    CHECK(ip_addr_parse(NULL, &a)           == IP_ERR_INVAL,              "null rejected");
}

static void test_prefix_parse(void)
{
    printf("[test_prefix_parse]\n");
    ip_prefix_t p;
    CHECK(ip_prefix_parse("10.0.0.0/8",      &p) == IP_OK && p.plen == 8,   "v4 /8");
    CHECK(ip_prefix_parse("192.168.1.0/24",  &p) == IP_OK && p.plen == 24,  "v4 /24");
    CHECK(ip_prefix_parse("2001:db8::/32",   &p) == IP_OK && p.plen == 32,  "v6 /32");
    CHECK(ip_prefix_parse("::1/128",         &p) == IP_OK && p.plen == 128, "v6 /128");
}

static void test_prefix_contains(void)
{
    printf("[test_prefix_contains]\n");
    ip_prefix_t p10  = make_prefix4("10.0.0.0/8");
    ip_addr_t   in10 = make_addr("10.1.2.3");
    ip_addr_t   out  = make_addr("11.0.0.1");
    CHECK(ip_prefix_contains(&p10, &in10), "10.1.2.3 in 10/8");
    CHECK(!ip_prefix_contains(&p10, &out), "11.0.0.1 not in 10/8");

    ip_prefix_t p6 = make_prefix6("2001:db8::/32");
    ip_addr_t   in6 = make_addr("2001:db8::1");
    ip_addr_t   out6 = make_addr("2001:db9::1");
    CHECK(ip_prefix_contains(&p6, &in6),  "2001:db8::1 in 2001:db8::/32");
    CHECK(!ip_prefix_contains(&p6, &out6), "2001:db9::1 not in 2001:db8::/32");
}

/* -----------------------------------------------------------------------
 * Test: martian / loopback / multicast classification
 * --------------------------------------------------------------------- */
static void test_classifiers(void)
{
    printf("[test_classifiers]\n");
    ip_addr_t lo4   = make_addr("127.0.0.1");
    ip_addr_t mc4   = make_addr("224.0.0.1");
    ip_addr_t ll4   = make_addr("169.254.1.1");
    ip_addr_t lo6   = make_addr("::1");
    ip_addr_t mc6   = make_addr("ff02::1");
    ip_addr_t ll6   = make_addr("fe80::1");
    ip_addr_t norm4 = make_addr("8.8.8.8");

    CHECK(ip_is_loopback(&lo4),      "127.0.0.1 loopback");
    CHECK(!ip_is_loopback(&norm4),   "8.8.8.8 not loopback");
    CHECK(ip_is_loopback(&lo6),      "::1 loopback");
    CHECK(ip_is_multicast(&mc4),     "224.0.0.1 multicast");
    CHECK(ip_is_multicast(&mc6),     "ff02::1 multicast");
    CHECK(!ip_is_multicast(&norm4),  "8.8.8.8 not multicast");
    CHECK(ip_is_link_local(&ll4),    "169.254.1.1 link-local");
    CHECK(ip_is_link_local(&ll6),    "fe80::1 link-local");
    CHECK(!ip_is_link_local(&norm4), "8.8.8.8 not link-local");

    CHECK(ip_is_martian_v4(&lo4.u.v4),              "127.0.0.1 martian v4");
    CHECK(ip_is_martian_v4(&ll4.u.v4),              "169.254.x.x martian v4");
    CHECK(!ip_is_martian_v4(&norm4.u.v4),           "8.8.8.8 not martian");
    CHECK(ip_is_martian_v6(&lo6.u.v6),              "::1 martian v6");
}

/* -----------------------------------------------------------------------
 * Test: interface table
 * --------------------------------------------------------------------- */
static void test_if_table(void)
{
    printf("[test_if_table]\n");
    ip_ctx_t *ctx = ip_ctx_create();
    assert(ctx);

    uint8_t mac[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
    CHECK(ip_if_add(ctx, "eth0", 1, IP_IF_UP|IP_IF_RUNNING, 1500, mac) == IP_OK,
          "add eth0");
    CHECK(ip_if_add(ctx, "eth0", 1, 0, 1500, mac) == IP_ERR_EXISTS,
          "duplicate ifindex rejected");
    CHECK(ip_if_find(ctx, 1) != NULL,             "find by ifindex");
    CHECK(ip_if_find_by_name(ctx, "eth0") != NULL, "find by name");
    CHECK(ip_if_find(ctx, 99) == NULL,            "missing ifindex returns NULL");

    CHECK(ip_if_del(ctx, 1) == IP_OK,             "del eth0");
    CHECK(ip_if_find(ctx, 1) == NULL,             "gone after del");

    ip_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Test: address management
 * --------------------------------------------------------------------- */
static void test_addresses(void)
{
    printf("[test_addresses]\n");
    ip_ctx_t *ctx = ip_ctx_create();
    assert(ctx);

    uint8_t mac[6] = {0};
    ip_if_add(ctx, "eth0", 1, IP_IF_UP, 1500, mac);

    ip_prefix_t pfx4 = make_prefix4("192.168.1.1/24");
    ip_prefix_t pfx6 = make_prefix6("2001:db8::1/64");

    CHECK(ip_addr_add(ctx, 1, &pfx4, 0, 0) == IP_OK,  "add v4 addr");
    CHECK(ip_addr_add(ctx, 1, &pfx4, 0, 0) == IP_ERR_EXISTS, "dup v4 rejected");
    CHECK(ip_addr_add(ctx, 1, &pfx6, 3600, 1800) == IP_OK,   "add v6 addr");
    CHECK(ip_addr_add(ctx, 99, &pfx4, 0, 0) == IP_ERR_NOTFOUND, "bad ifindex");

    ip_interface_t *ifc = ip_if_find(ctx, 1);
    CHECK(ifc && ifc->n_addrs == 2, "n_addrs == 2");

    CHECK(ip_addr_del(ctx, 1, &pfx4) == IP_OK,    "del v4 addr");
    ifc = ip_if_find(ctx, 1);
    CHECK(ifc && ifc->n_addrs == 1, "n_addrs == 1 after del");

    ip_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Test: forwarding table + LPM
 * --------------------------------------------------------------------- */
static void test_fwd_table(void)
{
    printf("[test_fwd_table]\n");
    ip_ctx_t *ctx = ip_ctx_create();
    assert(ctx);

    ip_prefix_t default4 = make_prefix4("0.0.0.0/0");
    ip_prefix_t net10    = make_prefix4("10.0.0.0/8");
    ip_prefix_t net1024  = make_prefix4("10.2.4.0/24");
    ip_addr_t   gw1      = make_addr("192.168.1.254");
    ip_addr_t   gw2      = make_addr("10.0.0.1");
    ip_addr_t   gw3      = make_addr("10.0.0.2");

    CHECK(ip_fwd_add(ctx, &default4, &gw1, 1, IP_AD_STATIC, 100) == IP_OK, "add default route");
    CHECK(ip_fwd_add(ctx, &net10,    &gw2, 2, IP_AD_STATIC, 10)  == IP_OK, "add 10/8");
    CHECK(ip_fwd_add(ctx, &net1024,  &gw3, 3, IP_AD_CONNECTED, 0) == IP_OK,"add 10.2.4/24");

    /* LPM: 10.2.4.1 should match /24 (most specific) */
    ip_addr_t       dst     = make_addr("10.2.4.1");
    ip_fwd_entry_t  result;
    CHECK(ip_fwd_lookup(ctx, &dst, &result) == IP_OK, "lookup 10.2.4.1");
    CHECK(result.prefix.plen == 24,                    "LPM chose /24");
    CHECK(result.out_ifindex == 3,                     "correct ifindex for /24");

    /* 10.5.0.1 should match /8 */
    dst = make_addr("10.5.0.1");
    CHECK(ip_fwd_lookup(ctx, &dst, &result) == IP_OK, "lookup 10.5.0.1");
    CHECK(result.prefix.plen == 8,                     "LPM chose /8");

    /* 8.8.8.8 should hit default */
    dst = make_addr("8.8.8.8");
    CHECK(ip_fwd_lookup(ctx, &dst, &result) == IP_OK, "lookup 8.8.8.8");
    CHECK(result.prefix.plen == 0,                     "LPM chose default");

    /* IPv6 */
    ip_prefix_t pfx6 = make_prefix6("2001:db8::/32");
    ip_addr_t   nh6  = make_addr("fe80::1");
    CHECK(ip_fwd_add(ctx, &pfx6, &nh6, 4, IP_AD_STATIC, 5) == IP_OK, "add v6 route");
    dst = make_addr("2001:db8::cafe");
    CHECK(ip_fwd_lookup(ctx, &dst, &result) == IP_OK, "v6 lookup");
    CHECK(result.prefix.plen == 32,                    "v6 LPM /32");

    /* delete */
    CHECK(ip_fwd_del(ctx, &net10) == IP_OK, "del 10/8");
    dst = make_addr("10.5.0.1");
    CHECK(ip_fwd_lookup(ctx, &dst, &result) == IP_OK, "10.5.0.1 falls back to default");
    CHECK(result.prefix.plen == 0,                     "fell back to default");

    ip_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Test: forwarding config
 * --------------------------------------------------------------------- */
static void test_fwd_config(void)
{
    printf("[test_fwd_config]\n");
    ip_ctx_t *ctx = ip_ctx_create();
    assert(ctx);

    CHECK(ip_get_forwarding(ctx, AF_INET),  "v4 fwd on by default");
    CHECK(ip_get_forwarding(ctx, AF_INET6), "v6 fwd on by default");

    ip_set_forwarding(ctx, AF_INET, false);
    CHECK(!ip_get_forwarding(ctx, AF_INET), "v4 fwd disabled");
    CHECK(ip_get_forwarding(ctx, AF_INET6), "v6 fwd still on");

    ip_set_forwarding(ctx, AF_INET, true);
    CHECK(ip_get_forwarding(ctx, AF_INET),  "v4 fwd re-enabled");

    uint8_t mac[6] = {0};
    ip_if_add(ctx, "eth0", 1, IP_IF_UP, 1500, mac);
    CHECK(ip_set_if_forwarding(ctx, 1, AF_INET, false) == IP_OK, "per-if v4 fwd off");
    ip_interface_t *ifc = ip_if_find(ctx, 1);
    CHECK(ifc && !ifc->ip4_fwd, "per-if v4 fwd reflected");

    ip_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Test: persistence round-trip
 * --------------------------------------------------------------------- */
static void test_persistence(void)
{
    printf("[test_persistence]\n");
    const char *path = "/tmp/ip_test_config.json";

    ip_ctx_t *ctx = ip_ctx_create();
    assert(ctx);

    uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    ip_if_add(ctx, "eth0", 1, IP_IF_UP|IP_IF_RUNNING, 1500, mac);
    ip_if_add(ctx, "eth1", 2, IP_IF_UP, 9000, mac);

    ip_prefix_t p4a = make_prefix4("192.168.0.1/24");
    ip_prefix_t p4b = make_prefix4("10.0.0.1/8");
    ip_prefix_t p6a = make_prefix6("2001:db8::1/64");
    ip_addr_add(ctx, 1, &p4a, 0, 0);
    ip_addr_add(ctx, 1, &p6a, 3600, 1800);
    ip_addr_add(ctx, 2, &p4b, 0, 0);

    ip_prefix_t route = make_prefix4("0.0.0.0/0");
    ip_addr_t   gw    = make_addr("192.168.0.254");
    ip_fwd_add(ctx, &route, &gw, 1, IP_AD_STATIC, 1);
    ip_set_forwarding(ctx, AF_INET6, false);

    CHECK(ip_save_config(ctx, path) == IP_OK, "save config");
    ip_ctx_destroy(ctx);

    /* reload into fresh context */
    ctx = ip_ctx_create();
    assert(ctx);
    CHECK(ip_load_config(ctx, path) == IP_OK, "load config");

    CHECK(!ip_get_forwarding(ctx, AF_INET6), "v6 fwd persisted as off");
    CHECK(ip_if_find(ctx, 1) != NULL,        "eth0 restored");
    CHECK(ip_if_find(ctx, 2) != NULL,        "eth1 restored");

    ip_interface_t *ifc = ip_if_find(ctx, 1);
    CHECK(ifc && ifc->n_addrs == 2, "eth0 has 2 addrs");

    ip_fwd_entry_t result;
    ip_addr_t dst = make_addr("1.2.3.4");
    CHECK(ip_fwd_lookup(ctx, &dst, &result) == IP_OK, "default route restored");

    ip_ctx_destroy(ctx);
    unlink(path);
}

/* -----------------------------------------------------------------------
 * Stress: concurrent reads + writes to forwarding table
 * --------------------------------------------------------------------- */
#define STRESS_THREADS  8
#define STRESS_OPS      10000

typedef struct { ip_ctx_t *ctx; int id; } stress_arg_t;

static void *stress_writer(void *arg)
{
    stress_arg_t *a = arg;
    char buf[64];
    for (int i = 0; i < STRESS_OPS; i++) {
        snprintf(buf, sizeof(buf), "10.%d.%d.0/24",
                 (a->id * STRESS_OPS + i) % 256,
                 i % 256);
        ip_prefix_t pfx = make_prefix4(buf);
        ip_addr_t   nh  = make_addr("192.168.1.1");
        ip_fwd_add(a->ctx, &pfx, &nh, 1, IP_AD_STATIC, 0);
    }
    return NULL;
}

static void *stress_reader(void *arg)
{
    stress_arg_t *a = arg;
    ip_fwd_entry_t result;
    for (int i = 0; i < STRESS_OPS; i++) {
        ip_addr_t dst = make_addr("10.1.2.3");
        ip_fwd_lookup(a->ctx, &dst, &result);
    }
    return NULL;
}

static void test_stress(void)
{
    printf("[test_stress] %d threads × %d ops\n", STRESS_THREADS, STRESS_OPS);
    ip_ctx_t *ctx = ip_ctx_create();
    assert(ctx);

    pthread_t writers[STRESS_THREADS/2], readers[STRESS_THREADS/2];
    stress_arg_t args[STRESS_THREADS];

    for (int i = 0; i < STRESS_THREADS/2; i++) {
        args[i].ctx = ctx; args[i].id = i;
        pthread_create(&writers[i], NULL, stress_writer, &args[i]);
    }
    for (int i = 0; i < STRESS_THREADS/2; i++) {
        args[STRESS_THREADS/2 + i].ctx = ctx;
        args[STRESS_THREADS/2 + i].id  = i;
        pthread_create(&readers[i], NULL, stress_reader,
                       &args[STRESS_THREADS/2 + i]);
    }
    for (int i = 0; i < STRESS_THREADS/2; i++) {
        pthread_join(writers[i], NULL);
        pthread_join(readers[i], NULL);
    }

    CHECK(1, "stress completed without crash");
    ip_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Main
 * --------------------------------------------------------------------- */
int main(void)
{
    printf("=== IP module tests ===\n\n");

    test_addr_parse();
    test_prefix_parse();
    test_prefix_contains();
    test_classifiers();
    test_if_table();
    test_addresses();
    test_fwd_table();
    test_fwd_config();
    test_persistence();
    test_stress();

    printf("\n=== %s (%d failure%s) ===\n",
           g_failures == 0 ? "ALL PASS" : "FAIL",
           g_failures,
           g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
