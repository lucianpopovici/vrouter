#ifndef VRF_H
#define VRF_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/* -----------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------- */
#define VRF_NAME_MAX            64
#define VRF_MAX_INSTANCES       256
#define VRF_TABLE_BUCKETS       64
#define VRF_IF_BUCKETS          32
#define VRF_FWD_BUCKETS         512
#define VRF_MAX_ROUTES          4096
#define VRF_MAX_IFS_PER_VRF     512
#define VRF_LEAK_MAX            1024

/* Reserved VRF IDs */
#define VRF_ID_DEFAULT          0
#define VRF_ID_INVALID          UINT32_MAX

/* Administrative distances */
#define VRF_AD_CONNECTED        0
#define VRF_AD_STATIC           1
#define VRF_AD_EBGP             20
#define VRF_AD_OSPF             110
#define VRF_AD_IBGP             200
#define VRF_AD_LEAKED           210

/* ECMP */
#define VRF_ECMP_MAX_PATHS      64
#define VRF_ECMP_HASH_SRC_IP    (1 << 0)
#define VRF_ECMP_HASH_DST_IP    (1 << 1)
#define VRF_ECMP_HASH_SRC_PORT  (1 << 2)
#define VRF_ECMP_HASH_DST_PORT  (1 << 3)
#define VRF_ECMP_HASH_PROTO     (1 << 4)
#define VRF_ECMP_HASH_DEFAULT   (VRF_ECMP_HASH_SRC_IP | VRF_ECMP_HASH_DST_IP)

/* VRF flags */
#define VRF_FLAG_ACTIVE         (1 << 0)
#define VRF_FLAG_DEFAULT        (1 << 1)
#define VRF_FLAG_MGMT           (1 << 2)
#define VRF_FLAG_L3VPN          (1 << 3)

/* Error codes */
#define VRF_OK                  0
#define VRF_ERR_NOMEM          -1
#define VRF_ERR_NOTFOUND       -2
#define VRF_ERR_EXISTS         -3
#define VRF_ERR_INVAL          -4
#define VRF_ERR_FULL           -5
#define VRF_ERR_BOUND          -6
#define VRF_ERR_LOOP           -7

/* -----------------------------------------------------------------------
 * Address / prefix
 * --------------------------------------------------------------------- */
typedef struct vrf_addr {
    sa_family_t af;
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } u;
} vrf_addr_t;

typedef struct vrf_prefix {
    vrf_addr_t  addr;
    uint8_t     plen;
} vrf_prefix_t;

/* -----------------------------------------------------------------------
 * ECMP nexthop group
 * --------------------------------------------------------------------- */

/* Flow key for ECMP path selection */
typedef struct vrf_flow_key {
    vrf_addr_t  src;
    vrf_addr_t  dst;
    uint16_t    src_port;
    uint16_t    dst_port;
    uint8_t     proto;
} vrf_flow_key_t;

/* One path in a nexthop group */
typedef struct vrf_nexthop {
    vrf_addr_t  addr;
    uint32_t    ifindex;
    uint32_t    weight;
    bool        active;
    uint64_t    hit_count;
} vrf_nexthop_t;

/* Per-VRF route: prefix → nexthop group */
typedef struct vrf_route {
    vrf_prefix_t    prefix;
    uint32_t        src_vrf_id;         /* VRF_ID_INVALID = local */
    uint8_t         ad;
    uint32_t        metric;
    vrf_nexthop_t   paths[VRF_ECMP_MAX_PATHS];
    uint8_t         n_paths;
    uint32_t        ecmp_hash_mode;
    uint64_t        hit_count;
    time_t          installed_at;
    struct vrf_route *next;
} vrf_route_t;

typedef struct vrf_fib {
    vrf_route_t    **buckets;
    uint32_t         n_buckets;
    uint32_t         n_routes;
    pthread_rwlock_t lock;
} vrf_fib_t;

/* -----------------------------------------------------------------------
 * Interface binding
 * --------------------------------------------------------------------- */
typedef struct vrf_if_binding {
    uint32_t    ifindex;
    char        ifname[IFNAMSIZ];
    uint32_t    vrf_id;
    time_t      bound_at;
    struct vrf_if_binding *next;
} vrf_if_binding_t;

/* -----------------------------------------------------------------------
 * Route-leak descriptor
 * --------------------------------------------------------------------- */
typedef struct vrf_leak {
    uint32_t        src_vrf_id;
    uint32_t        dst_vrf_id;
    vrf_prefix_t    prefix;
    vrf_addr_t      nexthop;
    uint32_t        out_ifindex;
    uint32_t        metric;
    time_t          leaked_at;
    struct vrf_leak *next;
} vrf_leak_t;

/* -----------------------------------------------------------------------
 * VRF instance
 * --------------------------------------------------------------------- */
typedef struct vrf_instance {
    uint32_t        id;
    char            name[VRF_NAME_MAX];
    uint32_t        flags;
    uint32_t        table_id;
    uint64_t        rd;
    vrf_fib_t       fib4;
    vrf_fib_t       fib6;
    uint32_t        ecmp_hash_mode;     /* default mode for new routes */
    vrf_if_binding_t *ifaces;
    uint32_t          n_ifaces;
    vrf_leak_t       *leaks_out;
    uint32_t          n_leaks_out;
    uint64_t        rx_pkts;
    uint64_t        tx_pkts;
    uint64_t        fwd_pkts;
    uint64_t        drop_noroute;
    uint64_t        drop_rpf;
    time_t          created_at;
    pthread_rwlock_t lock;
    struct vrf_instance *next;
} vrf_instance_t;

typedef struct vrf_table {
    vrf_instance_t **buckets;
    uint32_t         n_buckets;
    uint32_t         n_vrfs;
    pthread_rwlock_t lock;
} vrf_table_t;

typedef struct vrf_if_map {
    vrf_if_binding_t **buckets;
    uint32_t           n_buckets;
    pthread_rwlock_t   lock;
} vrf_if_map_t;

typedef struct vrf_ctx {
    vrf_table_t  vrf_table;
    vrf_if_map_t if_map;
    char         sock_path[256];
    int          sock_fd;
    bool         running;
    pthread_t    ipc_thread;
} vrf_ctx_t;

/* -----------------------------------------------------------------------
 * IPC command names
 * --------------------------------------------------------------------- */
#define VRF_CMD_CREATE          "create_vrf"
#define VRF_CMD_DELETE          "delete_vrf"
#define VRF_CMD_LIST            "list_vrfs"
#define VRF_CMD_GET             "get_vrf"
#define VRF_CMD_BIND_IF         "bind_interface"
#define VRF_CMD_UNBIND_IF       "unbind_interface"
#define VRF_CMD_LIST_IFS        "list_interfaces"
#define VRF_CMD_GET_IF_VRF      "get_if_vrf"
#define VRF_CMD_ADD_ROUTE       "add_route"
#define VRF_CMD_ADD_NEXTHOP     "add_nexthop"
#define VRF_CMD_DEL_NEXTHOP     "del_nexthop"
#define VRF_CMD_DEL_ROUTE       "del_route"
#define VRF_CMD_LIST_ROUTES     "list_routes"
#define VRF_CMD_LOOKUP          "lookup"
#define VRF_CMD_SET_ECMP_HASH   "set_ecmp_hash"
#define VRF_CMD_LEAK_ROUTE      "leak_route"
#define VRF_CMD_UNLEAK_ROUTE    "unleak_route"
#define VRF_CMD_LIST_LEAKS      "list_leaks"
#define VRF_CMD_GET_STATS       "get_stats"
#define VRF_CMD_CLEAR_STATS     "clear_stats"
#define VRF_CMD_DUMP_CONFIG     "dump_config"
#define VRF_CMD_LOAD_CONFIG     "load_config"

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

vrf_ctx_t      *vrf_ctx_create(void);
void            vrf_ctx_destroy(vrf_ctx_t *ctx);
int             vrf_init(vrf_ctx_t *ctx, const char *sock_path);
void            vrf_shutdown(vrf_ctx_t *ctx);

int             vrf_create(vrf_ctx_t *ctx, uint32_t id, const char *name,
                           uint32_t flags, uint32_t table_id, uint64_t rd);
int             vrf_delete(vrf_ctx_t *ctx, uint32_t id);
vrf_instance_t *vrf_find(vrf_ctx_t *ctx, uint32_t id);
vrf_instance_t *vrf_find_by_name(vrf_ctx_t *ctx, const char *name);

int             vrf_bind_if(vrf_ctx_t *ctx, uint32_t vrf_id,
                            uint32_t ifindex, const char *ifname);
int             vrf_unbind_if(vrf_ctx_t *ctx, uint32_t ifindex);
uint32_t        vrf_if_lookup(vrf_ctx_t *ctx, uint32_t ifindex);

/* Route-level (creates/replaces group) */
int             vrf_route_add(vrf_ctx_t *ctx, uint32_t vrf_id,
                              const vrf_prefix_t *pfx,
                              const vrf_addr_t *nexthop,
                              uint32_t out_ifindex,
                              uint8_t ad, uint32_t metric, uint32_t weight);
int             vrf_route_del(vrf_ctx_t *ctx, uint32_t vrf_id,
                              const vrf_prefix_t *pfx);

/* Nexthop-level (ECMP group manipulation) */
int             vrf_nexthop_add(vrf_ctx_t *ctx, uint32_t vrf_id,
                                const vrf_prefix_t *pfx,
                                const vrf_addr_t *nexthop,
                                uint32_t out_ifindex, uint32_t weight);
int             vrf_nexthop_del(vrf_ctx_t *ctx, uint32_t vrf_id,
                                const vrf_prefix_t *pfx,
                                const vrf_addr_t *nexthop,
                                uint32_t out_ifindex);

/* ECMP-aware lookup */
int             vrf_route_lookup(vrf_ctx_t *ctx, uint32_t vrf_id,
                                 const vrf_addr_t *dst,
                                 const vrf_flow_key_t *flow,  /* may be NULL */
                                 vrf_route_t   *entry_out,
                                 vrf_nexthop_t *path_out);

int             vrf_set_ecmp_hash(vrf_ctx_t *ctx, uint32_t vrf_id,
                                  const vrf_prefix_t *pfx, uint32_t mode);

int             vrf_leak_route(vrf_ctx_t *ctx,
                               uint32_t src_vrf_id, uint32_t dst_vrf_id,
                               const vrf_prefix_t *pfx,
                               const vrf_addr_t *nexthop,
                               uint32_t out_ifindex, uint32_t metric);
int             vrf_unleak_route(vrf_ctx_t *ctx,
                                 uint32_t src_vrf_id, uint32_t dst_vrf_id,
                                 const vrf_prefix_t *pfx);

int             vrf_save_config(vrf_ctx_t *ctx, const char *path);
int             vrf_load_config(vrf_ctx_t *ctx, const char *path);

/* Helpers */
int      vrf_addr_parse(const char *str, vrf_addr_t *out);
int      vrf_prefix_parse(const char *str, vrf_prefix_t *out);
void     vrf_addr_to_str(const vrf_addr_t *a, char *buf, size_t len);
void     vrf_prefix_to_str(const vrf_prefix_t *p, char *buf, size_t len);
bool     vrf_prefix_contains(const vrf_prefix_t *pfx, const vrf_addr_t *addr);
uint32_t vrf_fnv1a(uint32_t val, uint32_t n_buckets);
uint32_t vrf_fnv1a_prefix(const vrf_prefix_t *pfx, uint32_t n_buckets);
uint8_t  vrf_ecmp_select(const vrf_route_t *route,
                         const vrf_flow_key_t *flow);

#endif /* VRF_H */
