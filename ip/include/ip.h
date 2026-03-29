#ifndef IP_H
#define IP_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <time.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/* -----------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------- */
#define IP_MAX_INTERFACES       256
#define IP_MAX_ADDRS_PER_IF     64
#define IP_MAX_STATIC_ROUTES    4096
#define IP_ADDR_TABLE_BUCKETS   512
#define IP_IF_TABLE_BUCKETS     64

/* Administrative distances */
#define IP_AD_CONNECTED         0
#define IP_AD_STATIC            1
#define IP_AD_EBGP              20
#define IP_AD_OSPF              110
#define IP_AD_IBGP              200

/* Forwarding flags */
#define IP_FWD_ENABLED          (1 << 0)
#define IP_FWD_MARTIAN_DROP     (1 << 1)
#define IP_FWD_ICMP_REDIRECT    (1 << 2)
#define IP_FWD_ICMP_UNREACH     (1 << 3)
#define IP_FWD_RPF_STRICT       (1 << 4)
#define IP_FWD_RPF_LOOSE        (1 << 5)

/* Address families */
#define IP_AF_IPV4              AF_INET
#define IP_AF_IPV6              AF_INET6

/* Prefix lengths */
#define IPV4_MAX_PREFIXLEN      32
#define IPV6_MAX_PREFIXLEN      128

/* Interface state */
#define IP_IF_UP                (1 << 0)
#define IP_IF_RUNNING           (1 << 1)
#define IP_IF_PROMISC           (1 << 2)
#define IP_IF_LOOPBACK          (1 << 3)
#define IP_IF_MULTICAST         (1 << 4)
#define IP_IF_NO_AUTOCONF       (1 << 5)

/* Address state (IPv6) */
#define IP_ADDR_PREFERRED       0
#define IP_ADDR_DEPRECATED      1
#define IP_ADDR_TENTATIVE       2
#define IP_ADDR_DUPLICATE       3

/* ECMP */
#define IP_ECMP_MAX_PATHS       64
#define IP_ECMP_HASH_SRC_IP     (1 << 0)
#define IP_ECMP_HASH_DST_IP     (1 << 1)
#define IP_ECMP_HASH_SRC_PORT   (1 << 2)
#define IP_ECMP_HASH_DST_PORT   (1 << 3)
#define IP_ECMP_HASH_PROTO      (1 << 4)
#define IP_ECMP_HASH_DEFAULT    (IP_ECMP_HASH_SRC_IP | IP_ECMP_HASH_DST_IP)

/* Error codes */
#define IP_OK                   0
#define IP_ERR_NOMEM           -1
#define IP_ERR_NOTFOUND        -2
#define IP_ERR_EXISTS          -3
#define IP_ERR_INVAL           -4
#define IP_ERR_LOCKED          -5
#define IP_ERR_AF              -6
#define IP_ERR_FULL            -7

/* -----------------------------------------------------------------------
 * Data types
 * --------------------------------------------------------------------- */

typedef struct ip_addr {
    sa_family_t     af;
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } u;
} ip_addr_t;

typedef struct ip_prefix {
    ip_addr_t       addr;
    uint8_t         plen;
} ip_prefix_t;

typedef struct ip_if_addr {
    ip_prefix_t     prefix;
    ip_addr_t       broadcast;
    ip_addr_t       anycast;
    uint32_t        flags;
    uint8_t         state;
    uint32_t        valid_lft;
    uint32_t        pref_lft;
    time_t          assigned_at;
    struct ip_if_addr *next;
} ip_if_addr_t;

typedef struct ip_interface {
    char            name[IFNAMSIZ];
    uint32_t        ifindex;
    uint32_t        flags;
    uint32_t        mtu;
    uint8_t         mac[6];
    bool            ip4_fwd;
    bool            ip6_fwd;
    bool            ip6_ra_enable;
    uint8_t         ip6_hop_limit;
    ip_if_addr_t   *addrs;
    uint32_t        n_addrs;
    uint64_t        rx_pkts;
    uint64_t        tx_pkts;
    uint64_t        rx_bytes;
    uint64_t        tx_bytes;
    uint64_t        rx_errors;
    uint64_t        tx_errors;
    uint64_t        rx_dropped;
    uint64_t        tx_dropped;
    pthread_rwlock_t lock;
    struct ip_interface *next;
} ip_interface_t;

/* -----------------------------------------------------------------------
 * ECMP nexthop group
 * --------------------------------------------------------------------- */

/* One path within a nexthop group */
typedef struct ip_nexthop {
    ip_addr_t   addr;
    uint32_t    ifindex;
    uint32_t    weight;     /* relative weight >= 1; equal-cost = all 1 */
    bool        active;     /* false => path is down, skip during selection */
    uint64_t    hit_count;  /* per-path forwarding counter */
} ip_nexthop_t;

/*
 * Forwarding entry: one prefix maps to a nexthop group of 1..IP_ECMP_MAX_PATHS.
 * Single-path routes have n_paths == 1 (identical to legacy behaviour).
 * The selected path for a given flow is determined by ip_ecmp_select().
 */
typedef struct ip_fwd_entry {
    ip_prefix_t     prefix;
    uint8_t         ad;
    uint32_t        metric;
    ip_nexthop_t    paths[IP_ECMP_MAX_PATHS];
    uint8_t         n_paths;
    uint32_t        ecmp_hash_mode; /* IP_ECMP_HASH_* bitmask */
    uint64_t        hit_count;      /* total lookups for this prefix */
    time_t          installed_at;
    struct ip_fwd_entry *next;
} ip_fwd_entry_t;

typedef struct ip_fwd_table {
    ip_fwd_entry_t **buckets;
    uint32_t         n_buckets;
    uint32_t         n_entries;
    pthread_rwlock_t lock;
} ip_fwd_table_t;

typedef struct ip_if_table {
    ip_interface_t **buckets;
    uint32_t         n_buckets;
    uint32_t         n_entries;
    pthread_rwlock_t lock;
} ip_if_table_t;

/* Flow key for ECMP path selection */
typedef struct ip_flow_key {
    ip_addr_t   src;
    ip_addr_t   dst;
    uint16_t    src_port;
    uint16_t    dst_port;
    uint8_t     proto;
} ip_flow_key_t;

typedef struct ip_fwd_config {
    uint32_t    flags;
    bool        ipv4_forwarding;
    bool        ipv6_forwarding;
    uint8_t     default_ttl;
    uint8_t     default_hop_limit;
    uint32_t    fwd_table_max;
    uint32_t    ecmp_hash_mode;     /* global default hash mode */
    pthread_rwlock_t lock;
} ip_fwd_config_t;

typedef struct ip_stats {
    uint64_t    rx_pkts;
    uint64_t    tx_pkts;
    uint64_t    fwd_pkts;
    uint64_t    rx_bytes;
    uint64_t    tx_bytes;
    uint64_t    rx_drop_ttl;
    uint64_t    rx_drop_noroute;
    uint64_t    rx_drop_martian;
    uint64_t    rx_drop_rpf;
    uint64_t    rx_errors;
    uint64_t    tx_errors;
    uint64_t    icmp_redirects_sent;
    uint64_t    icmp_unreach_sent;
    pthread_rwlock_t lock;
} ip_stats_t;

typedef struct ip_ctx {
    ip_if_table_t   if_table;
    ip_fwd_table_t  fwd4;
    ip_fwd_table_t  fwd6;
    ip_fwd_config_t cfg;
    ip_stats_t      stats4;
    ip_stats_t      stats6;
    char            sock_path[256];
    int             sock_fd;
    bool            running;
    pthread_t       ipc_thread;
    pthread_t       stats_thread;
} ip_ctx_t;

/* -----------------------------------------------------------------------
 * IPC command names
 * --------------------------------------------------------------------- */
#define IP_CMD_ADD_ADDR         "add_addr"
#define IP_CMD_DEL_ADDR         "del_addr"
#define IP_CMD_LIST_ADDRS       "list_addrs"
#define IP_CMD_SET_IF_FWD       "set_if_fwd"
#define IP_CMD_GET_IF           "get_interface"
#define IP_CMD_LIST_IFS         "list_interfaces"
#define IP_CMD_ADD_ROUTE        "add_route"
#define IP_CMD_ADD_NEXTHOP      "add_nexthop"
#define IP_CMD_DEL_NEXTHOP      "del_nexthop"
#define IP_CMD_DEL_ROUTE        "del_route"
#define IP_CMD_LIST_ROUTES      "list_routes"
#define IP_CMD_LOOKUP           "lookup"
#define IP_CMD_SET_FWD          "set_forwarding"
#define IP_CMD_GET_FWD          "get_forwarding"
#define IP_CMD_SET_ECMP_HASH    "set_ecmp_hash"
#define IP_CMD_GET_STATS        "get_stats"
#define IP_CMD_CLEAR_STATS      "clear_stats"
#define IP_CMD_DUMP_CONFIG      "dump_config"
#define IP_CMD_LOAD_CONFIG      "load_config"

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

/* Lifecycle */
ip_ctx_t *ip_ctx_create(void);
void      ip_ctx_destroy(ip_ctx_t *ctx);
int       ip_init(ip_ctx_t *ctx, const char *sock_path);
void      ip_shutdown(ip_ctx_t *ctx);

/* Interface management */
int             ip_if_add(ip_ctx_t *ctx, const char *name, uint32_t ifindex,
                          uint32_t flags, uint32_t mtu, const uint8_t mac[6]);
int             ip_if_del(ip_ctx_t *ctx, uint32_t ifindex);
int             ip_if_set_flags(ip_ctx_t *ctx, uint32_t ifindex, uint32_t flags);
ip_interface_t *ip_if_find(ip_ctx_t *ctx, uint32_t ifindex);
ip_interface_t *ip_if_find_by_name(ip_ctx_t *ctx, const char *name);

/* Address management */
int ip_addr_add(ip_ctx_t *ctx, uint32_t ifindex, const ip_prefix_t *pfx,
                uint32_t valid_lft, uint32_t pref_lft);
int ip_addr_del(ip_ctx_t *ctx, uint32_t ifindex, const ip_prefix_t *pfx);

/* Forwarding table — route level */
int ip_fwd_add(ip_ctx_t *ctx, const ip_prefix_t *pfx,
               const ip_addr_t *nexthop, uint32_t out_ifindex,
               uint8_t ad, uint32_t metric, uint32_t weight);
int ip_fwd_del(ip_ctx_t *ctx, const ip_prefix_t *pfx);

/* Forwarding table — per-path manipulation (ECMP) */
int ip_nexthop_add(ip_ctx_t *ctx, const ip_prefix_t *pfx,
                   const ip_addr_t *nexthop, uint32_t out_ifindex,
                   uint32_t weight);
int ip_nexthop_del(ip_ctx_t *ctx, const ip_prefix_t *pfx,
                   const ip_addr_t *nexthop, uint32_t out_ifindex);

/* ECMP-aware lookup: selects a path given optional flow key */
int ip_fwd_lookup(ip_ctx_t *ctx, const ip_addr_t *dst,
                  const ip_flow_key_t *flow,   /* NULL => hash on dst only */
                  ip_fwd_entry_t *entry_out,   /* full entry snapshot */
                  ip_nexthop_t   *path_out);   /* selected path */

/* Per-prefix ECMP hash mode override */
int ip_set_ecmp_hash(ip_ctx_t *ctx, const ip_prefix_t *pfx, uint32_t mode);

/* Forwarding configuration */
int  ip_set_forwarding(ip_ctx_t *ctx, sa_family_t af, bool enable);
bool ip_get_forwarding(ip_ctx_t *ctx, sa_family_t af);
int  ip_set_fwd_flags(ip_ctx_t *ctx, uint32_t flags, bool enable);
int  ip_set_if_forwarding(ip_ctx_t *ctx, uint32_t ifindex,
                          sa_family_t af, bool enable);

/* Stats */
void ip_stats_get(ip_ctx_t *ctx, sa_family_t af, ip_stats_t *out);
void ip_stats_clear(ip_ctx_t *ctx, sa_family_t af);

/* Persistence */
int ip_save_config(ip_ctx_t *ctx, const char *path);
int ip_load_config(ip_ctx_t *ctx, const char *path);

/* Helpers */
int      ip_addr_parse(const char *str, ip_addr_t *out);
int      ip_prefix_parse(const char *str, ip_prefix_t *out);
void     ip_addr_to_str(const ip_addr_t *addr, char *buf, size_t len);
void     ip_prefix_to_str(const ip_prefix_t *pfx, char *buf, size_t len);
bool     ip_prefix_contains(const ip_prefix_t *pfx, const ip_addr_t *addr);
bool     ip_is_martian_v4(const struct in_addr *addr);
bool     ip_is_martian_v6(const struct in6_addr *addr);
bool     ip_is_loopback(const ip_addr_t *addr);
bool     ip_is_link_local(const ip_addr_t *addr);
bool     ip_is_multicast(const ip_addr_t *addr);
uint32_t ip_fnv1a_addr(const ip_addr_t *addr, uint32_t n_buckets);
uint32_t ip_fnv1a_prefix(const ip_prefix_t *pfx, uint32_t n_buckets);
uint8_t  ip_ecmp_select(const ip_fwd_entry_t *entry,
                        const ip_flow_key_t *flow); /* exposed for testing */

#endif /* IP_H */
