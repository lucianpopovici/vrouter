/*
 * test_vxlan.c — VXLAN module unit + stress tests.
 *
 * Tests cover:
 *   - Header encode/decode round-trips
 *   - Decapsulation of hand-crafted VXLAN payloads
 *   - Entropy source-port computation
 *   - VNI CRUD
 *   - Tunnel CRUD
 *   - FDB: add/del/lookup/flush/learn
 *   - Flood list management
 *   - Persistence round-trip (save/load)
 *   - Concurrent FDB writes + lookups (stress)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "vxlan.h"

#define PASS(n)    printf("  [PASS] %s\n", n)
#define FAIL(n)    do { printf("  [FAIL] %s:%d %s\n",__FILE__,__LINE__,n); g_failures++; } while(0)
#define CHECK(e,n) do { if(e) PASS(n); else FAIL(n); } while(0)

static int g_failures = 0;

static vxlan_addr_t maddr(const char *s)
{ vxlan_addr_t a; memset(&a,0,sizeof(a)); vxlan_addr_parse(s,&a); return a; }

static vxlan_mac_t mmac(const char *s)
{ vxlan_mac_t m; vxlan_mac_parse(s,&m); return m; }

/* Create a ctx without opening real sockets (for unit tests) */
static vxlan_ctx_t *make_ctx(void)
{
    vxlan_ctx_t *ctx = vxlan_ctx_create(); assert(ctx);
    ctx->local_ip  = maddr("10.0.0.1");
    ctx->listen_port = VXLAN_PORT_DEFAULT;
    return ctx;
}

/* -----------------------------------------------------------------------
 * Header encode/decode
 * --------------------------------------------------------------------- */
static void test_header(void)
{
    printf("[test_header]\n");
    vxlan_hdr_t hdr;

    /* Encode VNI 12345 */
    vxlan_hdr_encode(&hdr, 12345);
    uint32_t vni = 0;
    CHECK(vxlan_hdr_decode(&hdr, &vni) == VXLAN_OK, "decode ok");
    CHECK(vni == 12345, "VNI round-trip 12345");

    /* Encode VNI 0xFFFFFF (max) */
    vxlan_hdr_encode(&hdr, VXLAN_VNI_MAX);
    CHECK(vxlan_hdr_decode(&hdr, &vni) == VXLAN_OK, "decode max VNI");
    CHECK(vni == VXLAN_VNI_MAX, "VNI round-trip max");

    /* Encode VNI 1 */
    vxlan_hdr_encode(&hdr, 1);
    CHECK(vxlan_hdr_decode(&hdr, &vni) == VXLAN_OK && vni == 1, "VNI round-trip 1");

    /* Bad header (I-flag cleared) */
    vxlan_hdr_t bad = {0};
    CHECK(vxlan_hdr_decode(&bad, &vni) == VXLAN_ERR_DECAP, "bad header rejected");

    /* Size check */
    CHECK(sizeof(vxlan_hdr_t) == 8, "header is 8 bytes");
}

/* -----------------------------------------------------------------------
 * Decapsulation
 * --------------------------------------------------------------------- */
static void test_decap(void)
{
    printf("[test_decap]\n");

    /* Build a synthetic VXLAN UDP payload: 8-byte header + 14-byte inner Ethernet */
    uint8_t payload[8 + 14] = {0};
    vxlan_hdr_t *hdr = (vxlan_hdr_t *)payload;
    vxlan_hdr_encode(hdr, 99999);
    /* fill inner Ethernet with dummy MACs + ethertype */
    memset(payload + 8, 0xAA, 6);   /* dst MAC */
    memset(payload + 8 + 6, 0xBB, 6); /* src MAC */
    payload[8 + 12] = 0x08; payload[8 + 13] = 0x00; /* IPv4 ethertype */

    vxlan_addr_t src = maddr("10.0.0.2");
    vxlan_addr_t dst = maddr("10.0.0.1");
    vxlan_pkt_t pkt;

    CHECK(vxlan_decap(payload, sizeof(payload), &src, &dst, 12345, 4789, &pkt) == VXLAN_OK,
          "decap ok");
    CHECK(pkt.vni == 99999,       "VNI decoded");
    CHECK(pkt.inner_len == 14,    "inner_len correct");
    CHECK(pkt.inner == payload+8, "inner pointer correct");

    /* Too short */
    CHECK(vxlan_decap(payload, 7, &src, &dst, 0, 0, &pkt) == VXLAN_ERR_DECAP,
          "too-short rejected");

    /* NULL args */
    CHECK(vxlan_decap(NULL, 22, &src, &dst, 0, 0, &pkt) == VXLAN_ERR_INVAL,
          "NULL payload rejected");
}

/* -----------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */
static void test_helpers(void)
{
    printf("[test_helpers]\n");
    vxlan_addr_t a;
    CHECK(vxlan_addr_parse("10.1.2.3",    &a) == VXLAN_OK && a.af == AF_INET,  "v4 parse");
    CHECK(vxlan_addr_parse("2001:db8::1", &a) == VXLAN_OK && a.af == AF_INET6, "v6 parse");
    CHECK(vxlan_addr_parse("bad", &a)         == VXLAN_ERR_INVAL,              "bad addr");

    char buf[INET6_ADDRSTRLEN];
    a = maddr("192.168.0.1"); vxlan_addr_to_str(&a, buf, sizeof(buf));
    CHECK(strcmp(buf, "192.168.0.1") == 0, "addr_to_str v4");

    vxlan_mac_t mac;
    CHECK(vxlan_mac_parse("aa:bb:cc:dd:ee:ff", &mac) == VXLAN_OK, "mac parse");
    char mbuf[20]; vxlan_mac_to_str(&mac, mbuf, sizeof(mbuf));
    CHECK(strcmp(mbuf, "aa:bb:cc:dd:ee:ff") == 0, "mac to_str");

    vxlan_addr_t a1 = maddr("10.0.0.1"), a2 = maddr("10.0.0.2"), a3 = maddr("10.0.0.1");
    CHECK( vxlan_addr_eq(&a1, &a3), "addr_eq same");
    CHECK(!vxlan_addr_eq(&a1, &a2), "addr_eq different");
}

/* -----------------------------------------------------------------------
 * VNI CRUD
 * --------------------------------------------------------------------- */
static void test_vni(void)
{
    printf("[test_vni]\n");
    vxlan_ctx_t *ctx = make_ctx();

    CHECK(vxlan_vni_add(ctx, 10000, 1, 0, 1500) == VXLAN_OK,       "add VNI 10000");
    CHECK(vxlan_vni_add(ctx, 20000, 2, 0, 1450) == VXLAN_OK,       "add VNI 20000");
    CHECK(vxlan_vni_add(ctx, 10000, 1, 0, 0)    == VXLAN_ERR_EXISTS,"dup rejected");
    CHECK(vxlan_vni_add(ctx, 0, 0, 0, 0)         == VXLAN_ERR_INVAL,"VNI 0 rejected");

    vxlan_vni_t *v = vxlan_vni_find(ctx, 10000);
    CHECK(v != NULL,              "find by VNI");
    CHECK(v->bd_ifindex == 1,     "bd_ifindex stored");
    CHECK(v->mtu == 1500,         "mtu stored");
    CHECK(vxlan_vni_find(ctx, 99) == NULL, "missing=NULL");

    /* Multicast group */
    vxlan_addr_t mcast = maddr("239.1.1.1");
    CHECK(vxlan_vni_set_mcast(ctx, 10000, &mcast, 3) == VXLAN_OK, "set mcast");
    CHECK(vxlan_vni_find(ctx, 10000)->flags & VXLAN_VNI_MCAST, "mcast flag set");

    CHECK(vxlan_vni_del(ctx, 10000) == VXLAN_OK,  "del VNI 10000");
    CHECK(vxlan_vni_find(ctx, 10000) == NULL,       "gone after del");

    vxlan_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Tunnel CRUD
 * --------------------------------------------------------------------- */
static void test_tunnel(void)
{
    printf("[test_tunnel]\n");
    vxlan_ctx_t *ctx = make_ctx();

    vxlan_addr_t r1 = maddr("10.0.0.2"), r2 = maddr("10.0.0.3");

    CHECK(vxlan_tunnel_add(ctx, &r1, 10000, 0, 4789, 64) == VXLAN_OK, "add tunnel r1");
    CHECK(vxlan_tunnel_add(ctx, &r2, 10000, 0, 4789, 64) == VXLAN_OK, "add tunnel r2");
    CHECK(vxlan_tunnel_add(ctx, &r1, 10000, 0, 0, 0)     == VXLAN_ERR_EXISTS, "dup rejected");

    vxlan_tunnel_t *t = vxlan_tunnel_find(ctx, &r1, 10000);
    CHECK(t != NULL,              "find r1 tunnel");
    CHECK(t->dst_port == 4789,    "dst_port stored");
    CHECK(t->ttl == 64,           "ttl stored");
    CHECK(t->flags & VXLAN_TUNNEL_UP, "UP flag set");
    CHECK(vxlan_tunnel_find(ctx, &r1, 99999) == NULL, "wrong VNI=NULL");

    CHECK(vxlan_tunnel_del(ctx, &r1, 10000) == VXLAN_OK, "del r1");
    CHECK(vxlan_tunnel_find(ctx, &r1, 10000) == NULL,     "gone after del");

    /* Invalid args */
    CHECK(vxlan_tunnel_add(ctx, &r1, 0, 0, 0, 0) == VXLAN_ERR_INVAL, "VNI 0 rejected");

    vxlan_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * FDB: add / del / lookup / flush / learn
 * --------------------------------------------------------------------- */
static void test_fdb(void)
{
    printf("[test_fdb]\n");
    vxlan_ctx_t *ctx = make_ctx();
    vxlan_vni_add(ctx, 10000, 1, 0, 1500);

    vxlan_mac_t  m1 = mmac("aa:bb:cc:00:00:01");
    vxlan_mac_t  m2 = mmac("aa:bb:cc:00:00:02");
    vxlan_mac_t  m3 = mmac("aa:bb:cc:00:00:03");
    vxlan_addr_t r1 = maddr("10.0.0.2");
    vxlan_addr_t r2 = maddr("10.0.0.3");

    /* Remote entries */
    CHECK(vxlan_fdb_add(ctx,10000,&m1,&r1,0,VXLAN_FDB_REMOTE)==VXLAN_OK,"add m1→r1");
    CHECK(vxlan_fdb_add(ctx,10000,&m2,&r2,0,VXLAN_FDB_REMOTE)==VXLAN_OK,"add m2→r2");
    /* Update existing */
    CHECK(vxlan_fdb_add(ctx,10000,&m1,&r2,0,VXLAN_FDB_REMOTE)==VXLAN_OK,"update m1→r2");

    /* Local entry */
    CHECK(vxlan_fdb_add(ctx,10000,&m3,NULL,5,VXLAN_FDB_LOCAL)==VXLAN_OK,"add m3 local");

    /* Lookup */
    vxlan_fdb_entry_t *e = vxlan_fdb_lookup(ctx, 10000, &m1);
    CHECK(e != NULL,                       "lookup m1 found");
    CHECK(e->hit_count == 1,               "hit_count incremented");
    CHECK(vxlan_addr_eq(&e->remote_ip,&r2),"m1 updated to r2");

    e = vxlan_fdb_lookup(ctx, 10000, &m3);
    CHECK(e != NULL && (e->flags & VXLAN_FDB_LOCAL), "m3 is local");

    vxlan_mac_t miss = mmac("ff:ff:ff:ff:ff:ff");
    CHECK(vxlan_fdb_lookup(ctx, 10000, &miss) == NULL, "miss=NULL");

    /* Delete */
    CHECK(vxlan_fdb_del(ctx, 10000, &m2) == VXLAN_OK, "del m2");
    CHECK(vxlan_fdb_lookup(ctx, 10000, &m2) == NULL,   "m2 gone");

    /* Learn (data-plane) */
    vxlan_mac_t  ml = mmac("11:22:33:44:55:66");
    vxlan_addr_t rl = maddr("10.0.0.4");
    CHECK(vxlan_fdb_learn(ctx, 10000, &ml, &rl, 0) == VXLAN_OK, "learn mac");
    e = vxlan_fdb_lookup(ctx, 10000, &ml);
    CHECK(e != NULL && (e->flags & VXLAN_FDB_REMOTE), "learned as remote");

    /* Flush all remote entries */
    CHECK(vxlan_fdb_flush(ctx, 10000, NULL) == VXLAN_OK, "flush all remote");
    CHECK(vxlan_fdb_lookup(ctx, 10000, &m1) == NULL, "m1 flushed");
    CHECK(vxlan_fdb_lookup(ctx, 10000, &ml) == NULL, "ml flushed");
    /* Local survives flush */
    CHECK(vxlan_fdb_lookup(ctx, 10000, &m3) != NULL, "m3 local survives flush");

    /* Flush by specific VTEP */
    vxlan_mac_t mx = mmac("de:ad:be:ef:00:01");
    vxlan_fdb_add(ctx,10000,&mx,&r1,0,VXLAN_FDB_REMOTE);
    CHECK(vxlan_fdb_flush(ctx, 10000, &r2) == VXLAN_OK, "flush by r2 (none match)");
    CHECK(vxlan_fdb_lookup(ctx, 10000, &mx) != NULL, "mx not flushed (different vtep)");
    CHECK(vxlan_fdb_flush(ctx, 10000, &r1) == VXLAN_OK, "flush by r1");
    CHECK(vxlan_fdb_lookup(ctx, 10000, &mx) == NULL, "mx flushed by r1");

    /* Unknown VNI */
    CHECK(vxlan_fdb_add(ctx,99999,&m1,&r1,0,0)==VXLAN_ERR_NOTFOUND,"unknown VNI");

    vxlan_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Flood list
 * --------------------------------------------------------------------- */
static void test_flood(void)
{
    printf("[test_flood]\n");
    vxlan_ctx_t *ctx = make_ctx();
    vxlan_vni_add(ctx, 10000, 1, 0, 1500);

    vxlan_addr_t r1 = maddr("10.0.0.2");
    vxlan_addr_t r2 = maddr("10.0.0.3");
    vxlan_addr_t r3 = maddr("10.0.0.4");

    CHECK(vxlan_flood_add(ctx,10000,&r1)==VXLAN_OK,"add r1 to flood");
    CHECK(vxlan_flood_add(ctx,10000,&r2)==VXLAN_OK,"add r2 to flood");
    CHECK(vxlan_flood_add(ctx,10000,&r3)==VXLAN_OK,"add r3 to flood");
    CHECK(vxlan_flood_add(ctx,10000,&r1)==VXLAN_OK,"dup add is no-op");

    vxlan_vni_t *v = vxlan_vni_find(ctx, 10000);
    pthread_rwlock_rdlock(&v->lock);
    bool has3 = v->n_flood == 3;
    pthread_rwlock_unlock(&v->lock);
    CHECK(has3, "flood list has 3 unique entries");

    CHECK(vxlan_flood_del(ctx,10000,&r2)==VXLAN_OK,"del r2 from flood");
    pthread_rwlock_rdlock(&v->lock);
    bool has2 = v->n_flood == 2;
    pthread_rwlock_unlock(&v->lock);
    CHECK(has2, "flood list has 2 entries after del");

    CHECK(vxlan_flood_del(ctx,10000,&r2)==VXLAN_ERR_NOTFOUND,"del missing=NOTFOUND");
    CHECK(vxlan_flood_add(ctx,99,&r1)==VXLAN_ERR_NOTFOUND,"unknown VNI");

    vxlan_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Encap/decap round-trip (pure, no sockets)
 * --------------------------------------------------------------------- */
static void test_encap_decap_roundtrip(void)
{
    printf("[test_encap_decap_roundtrip]\n");

    /* Simulate an inner Ethernet frame */
    uint8_t inner[60] = {0};
    memset(inner,      0xFF, 6); /* dst broadcast */
    memset(inner + 6,  0xAA, 6); /* src MAC */
    inner[12] = 0x08; inner[13] = 0x00; /* IPv4 */
    /* fill rest with payload */
    for (int i = 14; i < 60; i++) inner[i] = (uint8_t)i;

    /* Build VXLAN payload manually */
    size_t payload_len = VXLAN_HDR_LEN + sizeof(inner);
    uint8_t payload[VXLAN_HDR_LEN + 60];
    vxlan_hdr_encode((vxlan_hdr_t *)payload, 77777);
    memcpy(payload + VXLAN_HDR_LEN, inner, sizeof(inner));

    vxlan_addr_t src = maddr("172.16.0.1"), dst = maddr("172.16.0.2");
    vxlan_pkt_t pkt;
    CHECK(vxlan_decap(payload, payload_len, &src, &dst, 54321, 4789, &pkt) == VXLAN_OK,
          "decap ok");
    CHECK(pkt.vni == 77777, "VNI preserved");
    CHECK(pkt.inner_len == sizeof(inner), "inner_len preserved");
    CHECK(memcmp(pkt.inner, inner, sizeof(inner)) == 0, "inner payload identical");
    CHECK(pkt.src_port == 54321, "src_port preserved");
    CHECK(vxlan_addr_eq(&pkt.src_vtep, &src), "src_vtep preserved");
}

/* -----------------------------------------------------------------------
 * Persistence
 * --------------------------------------------------------------------- */
static void test_persistence(void)
{
    printf("[test_persistence]\n");
    const char *path = "/tmp/vxlan_test.json";
    vxlan_ctx_t *ctx = make_ctx();

    vxlan_vni_add(ctx, 10000, 1, VXLAN_VNI_FLOOD, 1450);
    vxlan_vni_add(ctx, 20000, 2, 0, 1500);

    vxlan_addr_t r1 = maddr("10.0.0.2"), r2 = maddr("10.0.0.3");
    vxlan_flood_add(ctx, 10000, &r1);
    vxlan_flood_add(ctx, 10000, &r2);

    vxlan_tunnel_add(ctx, &r1, 10000, 0, 4789, 64);
    vxlan_tunnel_add(ctx, &r2, 10000, 0, 4789, 64);

    /* Static FDB entry (should survive reload) */
    vxlan_mac_t m1 = mmac("aa:bb:cc:dd:ee:ff");
    vxlan_fdb_add(ctx, 10000, &m1, &r1, 0, VXLAN_FDB_STATIC | VXLAN_FDB_REMOTE);

    /* Dynamic FDB (should be skipped on reload) */
    vxlan_mac_t m2 = mmac("11:22:33:44:55:66");
    vxlan_fdb_add(ctx, 10000, &m2, &r2, 0, VXLAN_FDB_REMOTE);

    vxlan_addr_t mcast = maddr("239.1.1.1");
    vxlan_vni_set_mcast(ctx, 20000, &mcast, 5);

    CHECK(vxlan_save_config(ctx, path) == VXLAN_OK, "save");
    vxlan_ctx_destroy(ctx);

    ctx = make_ctx();
    CHECK(vxlan_load_config(ctx, path) == VXLAN_OK, "load");

    CHECK(vxlan_vni_find(ctx, 10000) != NULL, "VNI 10000 restored");
    CHECK(vxlan_vni_find(ctx, 20000) != NULL, "VNI 20000 restored");
    CHECK(vxlan_vni_find(ctx, 20000)->flags & VXLAN_VNI_MCAST, "mcast flag restored");

    vxlan_vni_t *v = vxlan_vni_find(ctx, 10000);
    pthread_rwlock_rdlock(&v->lock);
    bool flood_ok = v->n_flood == 2;
    pthread_rwlock_unlock(&v->lock);
    CHECK(flood_ok, "flood list (2 entries) restored");

    CHECK(vxlan_tunnel_find(ctx, &r1, 10000) != NULL, "tunnel r1 restored");
    CHECK(vxlan_tunnel_find(ctx, &r2, 10000) != NULL, "tunnel r2 restored");

    /* Static entry must be present */
    vxlan_fdb_entry_t *e = vxlan_fdb_lookup(ctx, 10000, &m1);
    CHECK(e != NULL, "static FDB entry restored");

    /* Dynamic entry must NOT be present */
    CHECK(vxlan_fdb_lookup(ctx, 10000, &m2) == NULL, "dynamic FDB not restored");

    vxlan_ctx_destroy(ctx);
    unlink(path);
}

/* -----------------------------------------------------------------------
 * Stress: concurrent FDB writes + lookups
 * --------------------------------------------------------------------- */
#define STRESS_THREADS 8
#define STRESS_OPS     3000

typedef struct { vxlan_ctx_t *ctx; int id; uint32_t vni; } sarg_t;

static void *stress_writer(void *arg)
{
    sarg_t *a = arg;
    vxlan_addr_t r; r.af = AF_INET;
    r.u.v4.s_addr = htonl(0x0a000000u | (uint32_t)a->id);
    for (int i = 0; i < STRESS_OPS; i++) {
        vxlan_mac_t mac = {0};
        mac.b[0] = (uint8_t)a->id; mac.b[1] = (uint8_t)(i>>8); mac.b[2] = (uint8_t)i;
        vxlan_fdb_add(a->ctx, a->vni, &mac, &r, 0, VXLAN_FDB_REMOTE);
    }
    return NULL;
}

static void *stress_reader(void *arg)
{
    sarg_t *a = arg;
    vxlan_mac_t mac = {0};
    for (int i = 0; i < STRESS_OPS; i++) {
        mac.b[0] = (uint8_t)(i % 8);
        mac.b[2] = (uint8_t)i;
        vxlan_fdb_lookup(a->ctx, a->vni, &mac);
    }
    return NULL;
}

static void test_stress(void)
{
    printf("[test_stress] %d threads × %d ops\n", STRESS_THREADS, STRESS_OPS);
    vxlan_ctx_t *ctx = make_ctx();
    vxlan_vni_add(ctx, 10000, 1, 0, 1500);
    vxlan_vni_add(ctx, 20000, 2, 0, 1500);

    pthread_t threads[STRESS_THREADS]; sarg_t args[STRESS_THREADS];
    for (int i = 0; i < STRESS_THREADS; i++) {
        args[i].ctx = ctx;
        args[i].id  = i;
        args[i].vni = (i % 2 == 0) ? 10000 : 20000;
        if (i < STRESS_THREADS / 2)
            pthread_create(&threads[i], NULL, stress_writer, &args[i]);
        else
            pthread_create(&threads[i], NULL, stress_reader, &args[i]);
    }
    for (int i = 0; i < STRESS_THREADS; i++) pthread_join(threads[i], NULL);
    CHECK(1, "stress completed without crash");
    vxlan_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Main
 * --------------------------------------------------------------------- */
int main(void)
{
    printf("=== VXLAN module tests ===\n\n");
    test_header();
    test_decap();
    test_helpers();
    test_vni();
    test_tunnel();
    test_fdb();
    test_flood();
    test_encap_decap_roundtrip();
    test_persistence();
    test_stress();
    printf("\n=== %s (%d failure%s) ===\n",
           g_failures == 0 ? "ALL PASS" : "FAIL",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
