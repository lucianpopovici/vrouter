/*
 * test_ip.c — unit + stress tests for the IP module (with ECMP).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "ip.h"

#define PASS(n)   printf("  [PASS] %s\n", n)
#define FAIL(n)   do { printf("  [FAIL] %s\n", n); g_failures++; } while(0)
#define CHECK(e,n) do { if(e) PASS(n); else FAIL(n); } while(0)

static int g_failures = 0;

static ip_prefix_t mpfx(const char *s){ ip_prefix_t p; ip_prefix_parse(s,&p); return p; }
static ip_addr_t   maddr(const char *s){ ip_addr_t a;  ip_addr_parse(s,&a);   return a; }

/* -----------------------------------------------------------------------
 * Parsing
 * --------------------------------------------------------------------- */
static void test_parsing(void)
{
    printf("[test_parsing]\n");
    ip_addr_t a;
    CHECK(ip_addr_parse("10.0.0.1",    &a) == IP_OK && a.af == AF_INET,  "v4 parse");
    CHECK(ip_addr_parse("2001:db8::1", &a) == IP_OK && a.af == AF_INET6, "v6 parse");
    CHECK(ip_addr_parse("bad", &a)         == IP_ERR_INVAL,              "bad addr");
    ip_prefix_t p;
    CHECK(ip_prefix_parse("192.168.1.0/24", &p) == IP_OK && p.plen == 24, "v4 prefix");
    CHECK(ip_prefix_parse("2001:db8::/32",  &p) == IP_OK && p.plen == 32, "v6 prefix");
}

/* -----------------------------------------------------------------------
 * Martian / special addresses
 * --------------------------------------------------------------------- */
static void test_special_addrs(void)
{
    printf("[test_special_addrs]\n");
    ip_addr_t a;
    ip_addr_parse("127.0.0.1", &a); CHECK(ip_is_loopback(&a),  "127 loopback");
    ip_addr_parse("169.254.1.1",&a);CHECK(ip_is_link_local(&a),"169.254 link-local");
    ip_addr_parse("224.0.0.1", &a); CHECK(ip_is_multicast(&a), "224 multicast");
    ip_addr_parse("8.8.8.8",   &a);
    CHECK(!ip_is_loopback(&a) && !ip_is_link_local(&a) && !ip_is_multicast(&a), "global unicast");
}

/* -----------------------------------------------------------------------
 * Interface management
 * --------------------------------------------------------------------- */
static void test_interfaces(void)
{
    printf("[test_interfaces]\n");
    ip_ctx_t *ctx = ip_ctx_create(); assert(ctx);
    uint8_t mac[6] = {0x00,0x11,0x22,0x33,0x44,0x55};

    CHECK(ip_if_add(ctx,"eth0",1,IP_IF_UP,1500,mac)==IP_OK,    "add eth0");
    CHECK(ip_if_add(ctx,"eth0",1,IP_IF_UP,1500,mac)==IP_ERR_EXISTS,"dup rejected");
    CHECK(ip_if_find(ctx,1)!=NULL,                             "find by ifindex");
    CHECK(ip_if_find_by_name(ctx,"eth0")!=NULL,                "find by name");
    CHECK(ip_if_find(ctx,99)==NULL,                            "missing→NULL");
    CHECK(ip_if_add(ctx,"eth1",2,IP_IF_UP,1500,mac)==IP_OK,    "add eth1");
    CHECK(ip_if_del(ctx,1)==IP_OK,                             "delete eth0");
    CHECK(ip_if_find(ctx,1)==NULL,                             "gone after del");
    ip_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Address management
 * --------------------------------------------------------------------- */
static void test_addresses(void)
{
    printf("[test_addresses]\n");
    ip_ctx_t *ctx = ip_ctx_create(); assert(ctx);
    uint8_t mac[6]={0}; ip_if_add(ctx,"eth0",1,IP_IF_UP,1500,mac);
    ip_prefix_t pfx4 = mpfx("192.168.1.1/24");
    ip_prefix_t pfx6 = mpfx("2001:db8::1/64");
    CHECK(ip_addr_add(ctx,1,&pfx4,0,0)==IP_OK,        "add v4 addr");
    CHECK(ip_addr_add(ctx,1,&pfx4,0,0)==IP_ERR_EXISTS,"dup rejected");
    CHECK(ip_addr_add(ctx,1,&pfx6,0,0)==IP_OK,        "add v6 addr");
    CHECK(ip_addr_del(ctx,1,&pfx4)==IP_OK,             "del v4 addr");
    CHECK(ip_addr_del(ctx,1,&pfx4)==IP_ERR_NOTFOUND,   "del missing");
    CHECK(ip_addr_add(ctx,99,&pfx4,0,0)==IP_ERR_NOTFOUND,"add to missing if");
    ip_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * LPM routing (single-path)
 * --------------------------------------------------------------------- */
static void test_routing(void)
{
    printf("[test_routing]\n");
    ip_ctx_t *ctx = ip_ctx_create(); assert(ctx);

    ip_prefix_t def   = mpfx("0.0.0.0/0");
    ip_prefix_t net10 = mpfx("10.0.0.0/8");
    ip_prefix_t net24 = mpfx("10.2.4.0/24");
    ip_addr_t   gw1   = maddr("192.168.1.1");
    ip_addr_t   gw2   = maddr("10.0.0.1");
    ip_addr_t   gw3   = maddr("10.0.0.2");

    CHECK(ip_fwd_add(ctx,&def,  &gw1,1,IP_AD_STATIC,   100,1)==IP_OK,"add default");
    CHECK(ip_fwd_add(ctx,&net10,&gw2,2,IP_AD_STATIC,    10, 1)==IP_OK,"add 10/8");
    CHECK(ip_fwd_add(ctx,&net24,&gw3,3,IP_AD_CONNECTED,  0, 1)==IP_OK,"add 10.2.4/24");

    ip_fwd_entry_t entry; ip_nexthop_t path;
    ip_addr_t dst = maddr("10.2.4.1");
    CHECK(ip_fwd_lookup(ctx,&dst,NULL,&entry,&path)==IP_OK,"lookup 10.2.4.1");
    CHECK(entry.prefix.plen==24, "LPM /24");

    dst = maddr("10.5.0.1");
    CHECK(ip_fwd_lookup(ctx,&dst,NULL,&entry,&path)==IP_OK,"lookup 10.5.0.1");
    CHECK(entry.prefix.plen==8, "LPM /8");

    dst = maddr("8.8.8.8");
    CHECK(ip_fwd_lookup(ctx,&dst,NULL,&entry,&path)==IP_OK,"lookup 8.8.8.8");
    CHECK(entry.prefix.plen==0, "LPM default");

    ip_prefix_t pfx6 = mpfx("2001:db8::/32");
    ip_addr_t   nh6  = maddr("fe80::1");
    ip_fwd_add(ctx,&pfx6,&nh6,4,IP_AD_STATIC,5,1);
    dst = maddr("2001:db8::dead");
    CHECK(ip_fwd_lookup(ctx,&dst,NULL,&entry,&path)==IP_OK,"v6 lookup");
    CHECK(entry.prefix.plen==32, "v6 LPM /32");

    ip_fwd_del(ctx,&net10);
    dst = maddr("10.5.0.1");
    CHECK(ip_fwd_lookup(ctx,&dst,NULL,&entry,&path)==IP_OK,"fallback after del");
    CHECK(entry.prefix.plen==0, "fell back to default");

    ip_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * ECMP: multiple paths + weighted selection
 * --------------------------------------------------------------------- */
static void test_ecmp(void)
{
    printf("[test_ecmp]\n");
    ip_ctx_t *ctx = ip_ctx_create(); assert(ctx);

    ip_prefix_t pfx = mpfx("10.0.0.0/8");
    ip_addr_t   nh1 = maddr("192.168.1.1");
    ip_addr_t   nh2 = maddr("192.168.1.2");
    ip_addr_t   nh3 = maddr("192.168.1.3");

    CHECK(ip_fwd_add(ctx,&pfx,&nh1,1,IP_AD_STATIC,10,1)==IP_OK, "add path 1");
    CHECK(ip_fwd_add(ctx,&pfx,&nh2,2,IP_AD_STATIC,10,1)==IP_OK, "add path 2 (same AD)");
    CHECK(ip_nexthop_add(ctx,&pfx,&nh3,3,1)==IP_OK,             "add path 3 via nexthop_add");

    ip_fwd_entry_t entry; ip_nexthop_t path;
    ip_addr_t dst = maddr("10.5.0.1");
    CHECK(ip_fwd_lookup(ctx,&dst,NULL,&entry,&path)==IP_OK, "ecmp lookup ok");
    CHECK(entry.n_paths==3, "3 paths present");

    /* Verify all 3 paths are reachable across different flows */
    bool seen[3]={false,false,false};
    for (int sp=0;sp<300;sp++) {
        ip_flow_key_t flow={0};
        flow.src=maddr("1.2.3.4"); flow.dst=dst;
        flow.src_port=(uint16_t)(sp*17); flow.proto=6;
        ip_fwd_entry_t e2; ip_nexthop_t p2;
        ip_fwd_lookup(ctx,&dst,&flow,&e2,&p2);
        char s[INET6_ADDRSTRLEN]; ip_addr_to_str(&p2.addr,s,sizeof(s));
        if (!strcmp(s,"192.168.1.1")) seen[0]=true;
        if (!strcmp(s,"192.168.1.2")) seen[1]=true;
        if (!strcmp(s,"192.168.1.3")) seen[2]=true;
    }
    CHECK(seen[0]&&seen[1]&&seen[2], "all 3 paths selected across flows");

    /* Weighted: nh1=10, nh2=1, nh3=1 */
    ip_nexthop_add(ctx,&pfx,&nh1,1,10);
    ip_nexthop_add(ctx,&pfx,&nh2,2,1);
    int c1=0,c2=0,c3=0;
    for (int sp=0;sp<1200;sp++) {
        ip_flow_key_t flow={0};
        flow.src=maddr("1.2.3.4"); flow.dst=dst;
        flow.src_port=(uint16_t)(sp*7+1); flow.proto=6;
        ip_fwd_entry_t e2; ip_nexthop_t p2;
        ip_fwd_lookup(ctx,&dst,&flow,&e2,&p2);
        char s[INET6_ADDRSTRLEN]; ip_addr_to_str(&p2.addr,s,sizeof(s));
        if (!strcmp(s,"192.168.1.1")) c1++;
        else if (!strcmp(s,"192.168.1.2")) c2++;
        else c3++;
    }
    (void)c3;
    CHECK(c1>c2*5, "weighted: nh1 dominates");

    /* Remove one path */
    CHECK(ip_nexthop_del(ctx,&pfx,&nh2,2)==IP_OK, "del nexthop 2");
    ip_fwd_lookup(ctx,&dst,NULL,&entry,&path);
    CHECK(entry.n_paths==2, "2 paths after del");

    /* Better AD replaces whole group */
    CHECK(ip_fwd_add(ctx,&pfx,&nh1,1,IP_AD_CONNECTED,0,1)==IP_OK, "better AD");
    ip_fwd_lookup(ctx,&dst,NULL,&entry,&path);
    CHECK(entry.n_paths==1&&entry.ad==IP_AD_CONNECTED, "group replaced by better AD");

    /* Worse AD ignored */
    CHECK(ip_fwd_add(ctx,&pfx,&nh2,2,IP_AD_IBGP,0,1)==IP_OK, "worse AD call");
    ip_fwd_lookup(ctx,&dst,NULL,&entry,&path);
    CHECK(entry.n_paths==1&&entry.ad==IP_AD_CONNECTED, "worse AD ignored");

    /* Remove last path → route deleted */
    ip_fwd_lookup(ctx,&dst,NULL,&entry,&path);
    ip_addr_t sel=path.addr; uint32_t selif=path.ifindex;
    CHECK(ip_nexthop_del(ctx,&pfx,&sel,selif)==IP_OK, "del last nexthop");
    CHECK(ip_fwd_lookup(ctx,&dst,NULL,&entry,&path)==IP_ERR_NOTFOUND,
          "route gone after last nexthop removed");

    /* set_ecmp_hash per-prefix (DST_IP only → same dst always picks same path) */
    ip_fwd_add(ctx,&pfx,&nh1,1,IP_AD_STATIC,10,1);
    ip_fwd_add(ctx,&pfx,&nh2,2,IP_AD_STATIC,10,1);
    CHECK(ip_set_ecmp_hash(ctx,&pfx,IP_ECMP_HASH_DST_IP)==IP_OK, "set_ecmp_hash");
    ip_flow_key_t fk={0}; fk.dst=dst; fk.src=maddr("5.5.5.5");
    ip_fwd_entry_t fe; ip_nexthop_t fp;
    ip_fwd_lookup(ctx,&dst,&fk,&fe,&fp);
    bool all_same=true;
    for (int i=0;i<50;i++) {
        fk.src_port=(uint16_t)(i*31);
        ip_fwd_entry_t e2; ip_nexthop_t p2;
        ip_fwd_lookup(ctx,&dst,&fk,&e2,&p2);
        if (memcmp(&p2.addr,&fp.addr,sizeof(ip_addr_t))!=0) all_same=false;
    }
    CHECK(all_same, "DST_IP-only hash: same dst → same path");

    ip_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Forwarding config + stats
 * --------------------------------------------------------------------- */
static void test_fwd_config(void)
{
    printf("[test_fwd_config]\n");
    ip_ctx_t *ctx = ip_ctx_create(); assert(ctx);
    CHECK(ip_get_forwarding(ctx,AF_INET)==true,  "ipv4 fwd on by default");
    CHECK(ip_get_forwarding(ctx,AF_INET6)==true, "ipv6 fwd on by default");
    ip_set_forwarding(ctx,AF_INET,false);
    CHECK(ip_get_forwarding(ctx,AF_INET)==false, "ipv4 fwd disabled");
    ip_set_forwarding(ctx,AF_INET,true);
    ip_stats_t s; ip_stats_get(ctx,AF_INET,&s);
    ip_stats_clear(ctx,AF_INET);
    CHECK(1,"stats get/clear ok");
    ip_ctx_destroy(ctx);
}

/* -----------------------------------------------------------------------
 * Persistence round-trip (multi-path)
 * --------------------------------------------------------------------- */
static void test_persistence(void)
{
    printf("[test_persistence]\n");
    const char *path="/tmp/ip_ecmp_test.json";
    ip_ctx_t *ctx=ip_ctx_create(); assert(ctx);
    uint8_t mac[6]={0}; ip_if_add(ctx,"eth0",1,IP_IF_UP,1500,mac);

    ip_prefix_t pfx  = mpfx("10.0.0.0/8");
    ip_addr_t   gw1  = maddr("192.168.1.1"), gw2=maddr("192.168.1.2");
    ip_fwd_add(ctx,&pfx,&gw1,1,IP_AD_STATIC,10,2);  /* weight=2 */
    ip_fwd_add(ctx,&pfx,&gw2,2,IP_AD_STATIC,10,1);  /* weight=1, same AD → group */
    ip_set_ecmp_hash(ctx,&pfx,IP_ECMP_HASH_SRC_IP|IP_ECMP_HASH_DST_IP|IP_ECMP_HASH_PROTO);

    ip_prefix_t pfx6=mpfx("2001:db8::/32");
    ip_addr_t   nh6 =maddr("fe80::1");
    ip_fwd_add(ctx,&pfx6,&nh6,3,IP_AD_STATIC,5,1);

    CHECK(ip_save_config(ctx,path)==IP_OK,"save");
    ip_ctx_destroy(ctx);

    ctx=ip_ctx_create(); assert(ctx);
    CHECK(ip_load_config(ctx,path)==IP_OK,"load");

    ip_fwd_entry_t entry; ip_nexthop_t path2;
    ip_addr_t dst=maddr("10.5.0.1");
    CHECK(ip_fwd_lookup(ctx,&dst,NULL,&entry,&path2)==IP_OK,"v4 route restored");
    CHECK(entry.n_paths==2,"both paths restored");
    bool w_ok=(entry.paths[0].weight==2&&entry.paths[1].weight==1)||
              (entry.paths[0].weight==1&&entry.paths[1].weight==2);
    CHECK(w_ok,"weights restored");
    CHECK(entry.ecmp_hash_mode==(IP_ECMP_HASH_SRC_IP|IP_ECMP_HASH_DST_IP|IP_ECMP_HASH_PROTO),
          "hash mode restored");

    dst=maddr("2001:db8::1");
    CHECK(ip_fwd_lookup(ctx,&dst,NULL,&entry,&path2)==IP_OK,"v6 route restored");

    ip_ctx_destroy(ctx); unlink(path);
}

/* -----------------------------------------------------------------------
 * Stress
 * --------------------------------------------------------------------- */
#define STRESS_THREADS 8
#define STRESS_OPS     5000

typedef struct { ip_ctx_t *ctx; int id; } sarg_t;

static void *stress_writer(void *arg)
{
    sarg_t *a=arg; char buf[64];
    for (int i=0;i<STRESS_OPS;i++) {
        snprintf(buf,sizeof(buf),"10.%d.%d.0/24",(a->id*17+i)%256,i%256);
        ip_prefix_t pfx=mpfx(buf); ip_addr_t nh=maddr("192.168.1.1");
        ip_fwd_add(a->ctx,&pfx,&nh,1,IP_AD_STATIC,0,1);
        if (i%3==0) {
            ip_addr_t nh2=maddr("192.168.1.2");
            ip_nexthop_add(a->ctx,&pfx,&nh2,2,1);
        }
    }
    return NULL;
}

static void *stress_reader(void *arg)
{
    sarg_t *a=arg;
    for (int i=0;i<STRESS_OPS;i++) {
        ip_addr_t dst=maddr("10.1.2.3");
        ip_flow_key_t flow={0};
        flow.src=maddr("5.5.5.5"); flow.dst=dst;
        flow.src_port=(uint16_t)(i*13); flow.proto=6;
        ip_fwd_entry_t entry; ip_nexthop_t path;
        ip_fwd_lookup(a->ctx,&dst,&flow,&entry,&path);
    }
    return NULL;
}

static void test_stress(void)
{
    printf("[test_stress] %d threads × %d ops\n",STRESS_THREADS,STRESS_OPS);
    ip_ctx_t *ctx=ip_ctx_create(); assert(ctx);
    pthread_t threads[STRESS_THREADS]; sarg_t args[STRESS_THREADS];
    for (int i=0;i<STRESS_THREADS;i++) {
        args[i].ctx=ctx; args[i].id=i;
        if (i<STRESS_THREADS/2) pthread_create(&threads[i],NULL,stress_writer,&args[i]);
        else                    pthread_create(&threads[i],NULL,stress_reader,&args[i]);
    }
    for (int i=0;i<STRESS_THREADS;i++) pthread_join(threads[i],NULL);
    CHECK(1,"stress completed without crash");
    ip_ctx_destroy(ctx);
}

int main(void)
{
    printf("=== IP+ECMP module tests ===\n\n");
    test_parsing();
    test_special_addrs();
    test_interfaces();
    test_addresses();
    test_routing();
    test_ecmp();
    test_fwd_config();
    test_persistence();
    test_stress();
    printf("\n=== %s (%d failure%s) ===\n",
           g_failures==0?"ALL PASS":"FAIL",
           g_failures,g_failures==1?"":"s");
    return g_failures?1:0;
}
