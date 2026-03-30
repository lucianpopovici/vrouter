/*
 * test_vrf.c — unit + stress tests for the VRF module (with ECMP).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "vrf.h"

#define PASS(n)   printf("  [PASS] %s\n", n)
#define FAIL(n)   do { printf("  [FAIL] %s\n", n); g_failures++; } while(0)
#define CHECK(e,n) do { if(e) PASS(n); else FAIL(n); } while(0)

static int g_failures = 0;

static vrf_prefix_t mpfx(const char *s)
{ vrf_prefix_t p; vrf_prefix_parse(s, &p); return p; }
static vrf_addr_t maddr(const char *s)
{ vrf_addr_t a; vrf_addr_parse(s, &a); return a; }

/* -----------------------------------------------------------------------
 * Parsing
 * --------------------------------------------------------------------- */
static void test_parsing(void)
{
    printf("[test_parsing]\n");
    vrf_addr_t a;
    CHECK(vrf_addr_parse("10.0.0.1",    &a) == VRF_OK && a.af == AF_INET,  "v4 parse");
    CHECK(vrf_addr_parse("2001:db8::1", &a) == VRF_OK && a.af == AF_INET6, "v6 parse");
    CHECK(vrf_addr_parse("bad", &a)         == VRF_ERR_INVAL,              "bad addr");
    vrf_prefix_t p;
    CHECK(vrf_prefix_parse("192.168.0.0/24", &p) == VRF_OK && p.plen == 24, "v4 prefix");
    CHECK(vrf_prefix_parse("2001:db8::/32",  &p) == VRF_OK && p.plen == 32, "v6 prefix");
}

/* -----------------------------------------------------------------------
 * VRF CRUD
 * --------------------------------------------------------------------- */
static void test_vrf_crud(void)
{
    printf("[test_vrf_crud]\n");
    vrf_ctx_t *ctx = vrf_ctx_create(); assert(ctx);
    CHECK(vrf_create(ctx, 1, "red",  0, 10, 0) == VRF_OK,         "create red");
    CHECK(vrf_create(ctx, 2, "blue", 0, 11, 0) == VRF_OK,         "create blue");
    CHECK(vrf_create(ctx, 1, "dup",  0,  0, 0) == VRF_ERR_EXISTS, "dup id rejected");
    CHECK(vrf_find(ctx, 1)              != NULL, "find by id");
    CHECK(vrf_find_by_name(ctx, "blue") != NULL, "find by name");
    CHECK(vrf_find(ctx, 99)             == NULL, "missing returns NULL");
    CHECK(vrf_delete(ctx, 1)            == VRF_OK,       "delete red");
    CHECK(vrf_find(ctx, 1)              == NULL,          "gone after delete");
    CHECK(vrf_delete(ctx, VRF_ID_DEFAULT) == VRF_ERR_INVAL, "cannot delete default");
    vrf_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Interface binding
 * --------------------------------------------------------------------- */
static void test_if_binding(void)
{
    printf("[test_if_binding]\n");
    vrf_ctx_t *ctx = vrf_ctx_create(); assert(ctx);
    vrf_create(ctx, 1, "red",  0, 10, 0);
    vrf_create(ctx, 2, "blue", 0, 11, 0);
    CHECK(vrf_bind_if(ctx, 1, 3, "eth0") == VRF_OK,        "bind eth0→red");
    CHECK(vrf_bind_if(ctx, 2, 3, "eth0") == VRF_ERR_BOUND, "re-bind rejected");
    CHECK(vrf_bind_if(ctx, 1, 4, "eth1") == VRF_OK,        "bind eth1→red");
    CHECK(vrf_if_lookup(ctx, 3) == 1,            "eth0 in red");
    CHECK(vrf_if_lookup(ctx, 4) == 1,            "eth1 in red");
    CHECK(vrf_if_lookup(ctx, 9) == VRF_ID_INVALID, "unbound=INVALID");
    CHECK(vrf_unbind_if(ctx, 3) == VRF_OK,       "unbind eth0");
    CHECK(vrf_if_lookup(ctx, 3) == VRF_ID_INVALID,"eth0 gone");
    CHECK(vrf_unbind_if(ctx, 4) == VRF_OK,       "unbind eth1");
    CHECK(vrf_bind_if(ctx, 2, 4, "eth1") == VRF_OK, "re-bind eth1→blue");
    CHECK(vrf_if_lookup(ctx, 4) == 2,            "eth1 now in blue");
    vrf_bind_if(ctx, 2, 5, "eth2");
    vrf_delete(ctx, 2);
    CHECK(vrf_if_lookup(ctx, 4) == VRF_ID_INVALID, "eth1 unbound on VRF delete");
    CHECK(vrf_if_lookup(ctx, 5) == VRF_ID_INVALID, "eth2 unbound on VRF delete");
    vrf_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * LPM routing (single-path)
 * --------------------------------------------------------------------- */
static void test_routing(void)
{
    printf("[test_routing]\n");
    vrf_ctx_t *ctx = vrf_ctx_create(); assert(ctx);
    vrf_create(ctx, 1, "red", 0, 10, 0);

    vrf_prefix_t def   = mpfx("0.0.0.0/0");
    vrf_prefix_t net10 = mpfx("10.0.0.0/8");
    vrf_prefix_t net24 = mpfx("10.1.2.0/24");
    vrf_addr_t   gw1   = maddr("192.168.1.1");
    vrf_addr_t   gw2   = maddr("10.0.0.1");
    vrf_addr_t   gw3   = maddr("10.0.0.2");

    CHECK(vrf_route_add(ctx, 1, &def,   &gw1, 1, VRF_AD_STATIC,    100, 1) == VRF_OK, "add default");
    CHECK(vrf_route_add(ctx, 1, &net10, &gw2, 2, VRF_AD_STATIC,     10, 1) == VRF_OK, "add 10/8");
    CHECK(vrf_route_add(ctx, 1, &net24, &gw3, 3, VRF_AD_CONNECTED,   0, 1) == VRF_OK, "add 10.1.2/24");
    CHECK(vrf_route_add(ctx, 99, &def,  &gw1, 1, VRF_AD_STATIC,      1, 1) == VRF_ERR_NOTFOUND,
          "unknown VRF rejected");

    vrf_route_t entry; vrf_nexthop_t path;
    vrf_addr_t dst = maddr("10.1.2.5");
    CHECK(vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path) == VRF_OK, "lookup 10.1.2.5");
    CHECK(entry.prefix.plen == 24, "LPM /24");

    dst = maddr("10.5.0.1");
    CHECK(vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path) == VRF_OK, "lookup 10.5.0.1");
    CHECK(entry.prefix.plen == 8,  "LPM /8");

    dst = maddr("8.8.8.8");
    CHECK(vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path) == VRF_OK, "lookup 8.8.8.8");
    CHECK(entry.prefix.plen == 0, "LPM default");

    /* v6 */
    vrf_prefix_t pfx6 = mpfx("2001:db8::/32");
    vrf_addr_t   nh6  = maddr("fe80::1");
    vrf_route_add(ctx, 1, &pfx6, &nh6, 4, VRF_AD_STATIC, 5, 1);
    dst = maddr("2001:db8::dead");
    CHECK(vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path) == VRF_OK, "v6 lookup");
    CHECK(entry.prefix.plen == 32, "v6 LPM /32");

    vrf_route_del(ctx, 1, &net10);
    dst = maddr("10.5.0.1");
    CHECK(vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path) == VRF_OK, "fallback after del");
    CHECK(entry.prefix.plen == 0, "fell back to default");

    vrf_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * ECMP: multiple equal-cost paths + weighted selection
 * --------------------------------------------------------------------- */
static void test_ecmp(void)
{
    printf("[test_ecmp]\n");
    vrf_ctx_t *ctx = vrf_ctx_create(); assert(ctx);
    vrf_create(ctx, 1, "red", 0, 10, 0);

    vrf_prefix_t pfx = mpfx("10.0.0.0/8");
    vrf_addr_t   nh1 = maddr("192.168.1.1");
    vrf_addr_t   nh2 = maddr("192.168.1.2");
    vrf_addr_t   nh3 = maddr("192.168.1.3");

    /* First add creates the route with one path */
    CHECK(vrf_route_add(ctx, 1, &pfx, &nh1, 1, VRF_AD_STATIC, 10, 1) == VRF_OK, "add path 1");
    /* Second add at same AD appends */
    CHECK(vrf_route_add(ctx, 1, &pfx, &nh2, 2, VRF_AD_STATIC, 10, 1) == VRF_OK, "add path 2");
    /* Third via add_nexthop */
    CHECK(vrf_nexthop_add(ctx, 1, &pfx, &nh3, 3, 1) == VRF_OK, "add path 3 via nexthop_add");

    vrf_route_t entry; vrf_nexthop_t path;
    vrf_addr_t dst = maddr("10.5.0.1");
    CHECK(vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path) == VRF_OK, "ecmp lookup ok");
    CHECK(entry.n_paths == 3, "3 paths present");

    /* All 3 paths reachable across different flow hashes */
    bool seen[3] = {false, false, false};
    for (int sp = 0; sp < 300; sp++) {
        vrf_flow_key_t flow = {0};
        flow.src = maddr("1.2.3.4"); flow.dst = dst;
        flow.src_port = (uint16_t)(sp * 17); flow.proto = 6;
        vrf_route_t e2; vrf_nexthop_t p2;
        vrf_route_lookup(ctx, 1, &dst, &flow, &e2, &p2);
        char nhstr[INET6_ADDRSTRLEN];
        vrf_addr_to_str(&p2.addr, nhstr, sizeof(nhstr));
        if (strcmp(nhstr, "192.168.1.1") == 0) seen[0] = true;
        if (strcmp(nhstr, "192.168.1.2") == 0) seen[1] = true;
        if (strcmp(nhstr, "192.168.1.3") == 0) seen[2] = true;
    }
    CHECK(seen[0] && seen[1] && seen[2], "all 3 paths selected across flows");

    /* Weighted ECMP: nh1 weight=10, nh2 weight=1 */
    vrf_nexthop_add(ctx, 1, &pfx, &nh1, 1, 10);  /* update weight */
    vrf_nexthop_add(ctx, 1, &pfx, &nh2, 2, 1);

    int count_nh1 = 0, count_nh2 = 0, count_nh3 = 0;
    for (int sp = 0; sp < 1200; sp++) {
        vrf_flow_key_t flow = {0};
        flow.src = maddr("1.2.3.4"); flow.dst = dst;
        flow.src_port = (uint16_t)(sp * 7 + 1); flow.proto = 6;
        vrf_route_t e2; vrf_nexthop_t p2;
        vrf_route_lookup(ctx, 1, &dst, &flow, &e2, &p2);
        char nhstr[INET6_ADDRSTRLEN];
        vrf_addr_to_str(&p2.addr, nhstr, sizeof(nhstr));
        if (strcmp(nhstr, "192.168.1.1") == 0) count_nh1++;
        else if (strcmp(nhstr, "192.168.1.2") == 0) count_nh2++;
        else count_nh3++;
    }
    /* nh1 weight=10, nh2 weight=1, nh3 weight=1 → nh1 should dominate */
    (void)count_nh3;
    CHECK(count_nh1 > count_nh2 * 5, "weighted: nh1 gets majority");

    /* Remove one nexthop, verify group shrinks */
    CHECK(vrf_nexthop_del(ctx, 1, &pfx, &nh2, 2) == VRF_OK, "del nexthop 2");
    vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path);
    CHECK(entry.n_paths == 2, "2 paths after del");

    /* Better AD replaces whole group */
    CHECK(vrf_route_add(ctx, 1, &pfx, &nh1, 1, VRF_AD_CONNECTED, 0, 1) == VRF_OK, "better AD");
    vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path);
    CHECK(entry.n_paths == 1 && entry.ad == VRF_AD_CONNECTED, "group replaced by better AD");

    /* Worse AD is silently ignored */
    CHECK(vrf_route_add(ctx, 1, &pfx, &nh2, 2, VRF_AD_IBGP, 0, 1) == VRF_OK, "worse AD add");
    vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path);
    CHECK(entry.n_paths == 1 && entry.ad == VRF_AD_CONNECTED, "worse AD ignored");

    /* Removing last nexthop deletes the route entry */
    vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path);
    vrf_addr_t selected = path.addr; uint32_t sel_if = path.ifindex;
    CHECK(vrf_nexthop_del(ctx, 1, &pfx, &selected, sel_if) == VRF_OK, "del last nexthop");
    CHECK(vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path) == VRF_ERR_NOTFOUND,
          "route gone after last nexthop removed");

    /* set_ecmp_hash per-prefix */
    vrf_route_add(ctx, 1, &pfx, &nh1, 1, VRF_AD_STATIC, 10, 1);
    vrf_route_add(ctx, 1, &pfx, &nh2, 2, VRF_AD_STATIC, 10, 1);
    CHECK(vrf_set_ecmp_hash(ctx, 1, &pfx, VRF_ECMP_HASH_DST_IP) == VRF_OK, "set_ecmp_hash");
    /* same dst → same path regardless of src_port variation */
    vrf_nexthop_t first_path, cur_path;
    vrf_flow_key_t fk = {0}; fk.dst = dst; fk.src = maddr("5.5.5.5");
    vrf_route_lookup(ctx, 1, &dst, &fk, &entry, &first_path);
    bool all_same = true;
    for (int i = 0; i < 50; i++) {
        fk.src_port = (uint16_t)(i * 31);
        vrf_route_t e2;
        vrf_route_lookup(ctx, 1, &dst, &fk, &e2, &cur_path);
        if (memcmp(&cur_path.addr, &first_path.addr, sizeof(vrf_addr_t)) != 0) all_same = false;
    }
    CHECK(all_same, "DST_IP-only hash: same dst → same path");

    vrf_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Route leaking (unchanged API; leaks install with LEAKED AD)
 * --------------------------------------------------------------------- */
static void test_leaking(void)
{
    printf("[test_leaking]\n");
    vrf_ctx_t *ctx = vrf_ctx_create(); assert(ctx);
    vrf_create(ctx, 1, "red",  0, 10, 0);
    vrf_create(ctx, 2, "blue", 0, 11, 0);

    vrf_prefix_t pfx = mpfx("172.16.0.0/16");
    vrf_addr_t   gw  = maddr("10.0.0.1");
    vrf_route_add(ctx, 1, &pfx, &gw, 1, VRF_AD_STATIC, 10, 1);

    CHECK(vrf_leak_route(ctx, 1, 2, &pfx, &gw, 1, 10) == VRF_OK,      "leak red→blue");
    CHECK(vrf_leak_route(ctx, 1, 1, &pfx, &gw, 1, 10) == VRF_ERR_LOOP,"self-leak rejected");

    vrf_route_t entry; vrf_nexthop_t path;
    vrf_addr_t dst = maddr("172.16.5.1");
    CHECK(vrf_route_lookup(ctx, 2, &dst, NULL, &entry, &path) == VRF_OK, "blue resolves leaked");
    CHECK(entry.src_vrf_id == 1,           "src_vrf_id tagged");
    CHECK(entry.ad == VRF_AD_LEAKED,       "leaked AD applied");

    CHECK(vrf_unleak_route(ctx, 1, 2, &pfx) == VRF_OK, "unleak");
    CHECK(vrf_route_lookup(ctx, 2, &dst, NULL, &entry, &path) == VRF_ERR_NOTFOUND,
          "blue: no route after unleak");

    vrf_instance_t *red = vrf_find(ctx, 1);
    pthread_rwlock_rdlock(&red->lock);
    bool no_leaks = (red->n_leaks_out == 0);
    pthread_rwlock_unlock(&red->lock);
    CHECK(no_leaks, "leak descriptor removed from src");

    vrf_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Persistence round-trip (includes multi-path routes)
 * --------------------------------------------------------------------- */
static void test_persistence(void)
{
    printf("[test_persistence]\n");
    const char *path = "/tmp/vrf_ecmp_test.json";

    vrf_ctx_t *ctx = vrf_ctx_create(); assert(ctx);
    vrf_create(ctx, 1, "red",  0, 10, 100);
    vrf_create(ctx, 2, "blue", 0, 11, 200);
    vrf_bind_if(ctx, 1, 3, "eth0");
    vrf_bind_if(ctx, 2, 4, "eth1");

    /* multi-path route in red */
    vrf_prefix_t pfx  = mpfx("10.0.0.0/8");
    vrf_addr_t   gw1  = maddr("192.168.1.1"), gw2 = maddr("192.168.1.2");
    vrf_route_add(ctx, 1, &pfx, &gw1, 1, VRF_AD_STATIC, 10, 2);  /* weight=2 */
    vrf_route_add(ctx, 1, &pfx, &gw2, 2, VRF_AD_STATIC, 10, 1);  /* weight=1 */

    vrf_prefix_t pfx6 = mpfx("2001:db8::/32");
    vrf_addr_t   gw6  = maddr("fe80::1");
    vrf_route_add(ctx, 2, &pfx6, &gw6, 4, VRF_AD_STATIC, 5, 1);

    vrf_prefix_t leaked = mpfx("172.16.0.0/16");
    vrf_leak_route(ctx, 1, 2, &leaked, &gw1, 1, 20);

    CHECK(vrf_save_config(ctx, path) == VRF_OK, "save");
    vrf_ctx_destroy(ctx);

    ctx = vrf_ctx_create(); assert(ctx);
    CHECK(vrf_load_config(ctx, path) == VRF_OK, "load");

    CHECK(vrf_find(ctx, 1) != NULL,              "red restored");
    CHECK(vrf_find(ctx, 2) != NULL,              "blue restored");
    CHECK(vrf_find_by_name(ctx, "red") != NULL,  "find red by name");
    CHECK(vrf_if_lookup(ctx, 3) == 1,            "eth0 binding restored");
    CHECK(vrf_if_lookup(ctx, 4) == 2,            "eth1 binding restored");

    vrf_route_t entry; vrf_nexthop_t path2;
    vrf_addr_t dst = maddr("10.5.0.1");
    CHECK(vrf_route_lookup(ctx, 1, &dst, NULL, &entry, &path2) == VRF_OK, "red v4 route restored");
    CHECK(entry.n_paths == 2, "both paths restored");

    /* verify weight restored */
    bool w_ok = (entry.paths[0].weight == 2 && entry.paths[1].weight == 1) ||
                (entry.paths[0].weight == 1 && entry.paths[1].weight == 2);
    CHECK(w_ok, "weights restored");

    dst = maddr("172.16.5.1");
    CHECK(vrf_route_lookup(ctx, 2, &dst, NULL, &entry, &path2) == VRF_OK, "leaked route restored");

    vrf_ctx_destroy(ctx);
    unlink(path);
}

/* -----------------------------------------------------------------------
 * Stress: concurrent route writes + lookups across two VRFs
 * --------------------------------------------------------------------- */
#define STRESS_THREADS 8
#define STRESS_OPS     5000

typedef struct { vrf_ctx_t *ctx; int id; uint32_t vrf_id; } stress_arg_t;

static void *stress_writer(void *arg)
{
    stress_arg_t *a = arg;
    char buf[64];
    for (int i = 0; i < STRESS_OPS; i++) {
        snprintf(buf, sizeof(buf), "10.%d.%d.0/24",
                 (a->id * 17 + i) % 256, i % 256);
        vrf_prefix_t pfx = mpfx(buf);
        vrf_addr_t   nh  = maddr("192.168.1.1");
        vrf_route_add(a->ctx, a->vrf_id, &pfx, &nh, 1, VRF_AD_STATIC, 0, 1);
        /* add a second path to some routes */
        if (i % 3 == 0) {
            vrf_addr_t nh2 = maddr("192.168.1.2");
            vrf_nexthop_add(a->ctx, a->vrf_id, &pfx, &nh2, 2, 1);
        }
    }
    return NULL;
}

static void *stress_reader(void *arg)
{
    stress_arg_t *a = arg;
    for (int i = 0; i < STRESS_OPS; i++) {
        vrf_addr_t dst = maddr("10.1.2.3");
        vrf_flow_key_t flow = {0};
        flow.src = maddr("5.5.5.5"); flow.dst = dst;
        flow.src_port = (uint16_t)(i * 13); flow.proto = 6;
        vrf_route_t entry; vrf_nexthop_t path;
        vrf_route_lookup(a->ctx, a->vrf_id, &dst, &flow, &entry, &path);
    }
    return NULL;
}

static void test_stress(void)
{
    printf("[test_stress] %d threads × %d ops\n", STRESS_THREADS, STRESS_OPS);
    vrf_ctx_t *ctx = vrf_ctx_create(); assert(ctx);
    vrf_create(ctx, 1, "red",  0, 10, 0);
    vrf_create(ctx, 2, "blue", 0, 11, 0);

    pthread_t threads[STRESS_THREADS];
    stress_arg_t args[STRESS_THREADS];
    for (int i = 0; i < STRESS_THREADS; i++) {
        args[i].ctx    = ctx;
        args[i].id     = i;
        args[i].vrf_id = (i % 2) + 1;
        if (i < STRESS_THREADS / 2)
            pthread_create(&threads[i], NULL, stress_writer, &args[i]);
        else
            pthread_create(&threads[i], NULL, stress_reader, &args[i]);
    }
    for (int i = 0; i < STRESS_THREADS; i++) pthread_join(threads[i], NULL);
    CHECK(1, "stress completed without crash");
    vrf_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Main
 * --------------------------------------------------------------------- */
int main(void)
{
    printf("=== VRF+ECMP module tests ===\n\n");
    test_parsing();
    test_vrf_crud();
    test_if_binding();
    test_routing();
    test_ecmp();
    test_leaking();
    test_persistence();
    test_stress();
    printf("\n=== %s (%d failure%s) ===\n",
           g_failures == 0 ? "ALL PASS" : "FAIL",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
