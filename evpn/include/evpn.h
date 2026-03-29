#ifndef EVPN_H
#define EVPN_H

/*
 * evpn.h — BGP EVPN (RFC 7432 / RFC 8365) module
 *
 * Architecture:
 *   - One or more EVI (EVPN Instance) objects, each tied to a VNI and a VRF.
 *   - Each EVI owns a MAC-IP table (RT-2) and an IP-prefix table (RT-5).
 *   - A global VTEP table tracks all known remote tunnel endpoints.
 *   - IMET entries (RT-3) build per-EVI flood lists.
 *   - Ethernet Segments (RT-4) support multi-homing.
 *
 * EVPN Route Types implemented:
 *   RT-1  Ethernet Auto-Discovery (EAD)
 *   RT-2  MAC/IP Advertisement
 *   RT-3  Inclusive Multicast Ethernet Tag (IMET) — VTEP discovery
 *   RT-4  Ethernet Segment (ES) route
 *   RT-5  IP Prefix (IRB / L3VNI)
 *
 * Locking: rwlock embedded in each table; single-exit (goto out) discipline.
 */

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
 * Sizing
 * --------------------------------------------------------------------- */
#define EVPN_MAX_EVI            1024
#define EVPN_MAX_VTEP           4096
#define EVPN_MAX_MAC_PER_EVI    65536
#define EVPN_MAX_PREFIX_PER_EVI 16384
#define EVPN_MAX_ES             256
#define EVPN_EVI_BUCKETS        128
#define EVPN_VTEP_BUCKETS       512
#define EVPN_MAC_BUCKETS        4096
#define EVPN_PFX_BUCKETS        1024
#define EVPN_RT_MAX_PER_EVI     32

#define EVPN_VNI_MIN            1u
#define EVPN_VNI_MAX            16777215u
#define EVPN_VNI_INVALID        0u
#define EVPN_VXLAN_PORT         4789

/* Error codes */
#define EVPN_OK                 0
#define EVPN_ERR_NOMEM         -1
#define EVPN_ERR_NOTFOUND      -2
#define EVPN_ERR_EXISTS        -3
#define EVPN_ERR_INVAL         -4
#define EVPN_ERR_FULL          -5
#define EVPN_ERR_VTEP          -6

/* EVPN Route Types */
#define EVPN_RT_EAD             1
#define EVPN_RT_MAC_IP          2
#define EVPN_RT_IMET            3
#define EVPN_RT_ES              4
#define EVPN_RT_IP_PREFIX       5

/* MAC/IP flags */
#define EVPN_MAC_LOCAL          (1u << 0)
#define EVPN_MAC_REMOTE         (1u << 1)
#define EVPN_MAC_STATIC         (1u << 2)
#define EVPN_MAC_STICKY         (1u << 3)
#define EVPN_MAC_GATEWAY        (1u << 4)
#define EVPN_MAC_ROUTER         (1u << 5)

/* VTEP flags */
#define EVPN_VTEP_LOCAL         (1u << 0)
#define EVPN_VTEP_ACTIVE        (1u << 1)
#define EVPN_VTEP_BFD           (1u << 2)

/* Encapsulation */
#define EVPN_ENCAP_VXLAN        1
#define EVPN_ENCAP_MPLS         2
#define EVPN_ENCAP_VXLAN_GPE    3

/* EVI flags */
#define EVPN_EVI_ACTIVE         (1u << 0)
#define EVPN_EVI_FLOOD_REPL     (1u << 1)
#define EVPN_EVI_ARP_SUPPRESS   (1u << 2)
#define EVPN_EVI_IRB            (1u << 3)
#define EVPN_EVI_ASYMMETRIC     (1u << 4)
#define EVPN_EVI_SYMMETRIC      (1u << 5)

/* -----------------------------------------------------------------------
 * Basic types
 * --------------------------------------------------------------------- */

typedef struct evpn_mac { uint8_t b[6]; } evpn_mac_t;

typedef struct evpn_addr {
    sa_family_t af;
    union { struct in_addr v4; struct in6_addr v6; } u;
} evpn_addr_t;

typedef struct evpn_prefix { evpn_addr_t addr; uint8_t plen; } evpn_prefix_t;

/* Ethernet Segment Identifier (10 bytes, RFC 7432 §5) */
typedef struct evpn_esi { uint8_t b[10]; } evpn_esi_t;

/* -----------------------------------------------------------------------
 * VTEP
 * --------------------------------------------------------------------- */
typedef struct evpn_vtep {
    evpn_addr_t      ip;
    uint32_t         flags;
    uint8_t          encap;
    uint16_t         udp_port;
    uint32_t         ifindex;
    uint64_t         rx_pkts;
    uint64_t         tx_pkts;
    time_t           first_seen;
    time_t           last_seen;
    struct evpn_vtep *next;
} evpn_vtep_t;

typedef struct evpn_vtep_table {
    evpn_vtep_t    **buckets;
    uint32_t         n_buckets;
    uint32_t         n_vteps;
    pthread_rwlock_t lock;
} evpn_vtep_table_t;

/* -----------------------------------------------------------------------
 * Ethernet Segment (RT-4)
 * --------------------------------------------------------------------- */
typedef struct evpn_es {
    evpn_esi_t      esi;
    uint8_t         type;
    evpn_mac_t      sys_mac;
    uint32_t        local_disc;
    uint32_t        flags;
    evpn_addr_t     df_ip;      /* designated-forwarder IP */
    bool            df_local;
    time_t          created_at;
    struct evpn_es *next;
} evpn_es_t;

/* -----------------------------------------------------------------------
 * MAC-IP entry (RT-2)
 * --------------------------------------------------------------------- */
typedef struct evpn_mac_ip {
    /* Key */
    evpn_mac_t     mac;
    evpn_addr_t    ip;          /* AF_UNSPEC = pure-MAC route */
    uint32_t       vni;

    /* Attributes */
    uint32_t       flags;
    evpn_esi_t     esi;
    uint32_t       eth_tag;
    uint32_t       l3_vni;
    evpn_mac_t     gw_mac;

    /* Reachability */
    evpn_vtep_t   *vtep;        /* NULL = local */
    uint32_t       out_ifindex;

    /* BGP */
    uint64_t       rd;
    uint32_t       local_pref;
    uint32_t       med;
    uint64_t       rt_list[EVPN_RT_MAX_PER_EVI];
    uint8_t        n_rt;

    uint64_t       hit_count;
    time_t         installed_at;
    time_t         last_update;
    struct evpn_mac_ip *next;
} evpn_mac_ip_t;

typedef struct evpn_mac_table {
    evpn_mac_ip_t  **buckets;
    uint32_t         n_buckets;
    uint32_t         n_entries;
    pthread_rwlock_t lock;
} evpn_mac_table_t;

/* -----------------------------------------------------------------------
 * IMET entry (RT-3)
 * --------------------------------------------------------------------- */
typedef struct evpn_imet {
    evpn_addr_t      vtep_ip;
    uint32_t         vni;
    uint32_t         eth_tag;
    uint64_t         rd;
    time_t           received_at;
    struct evpn_imet *next;
} evpn_imet_t;

/* -----------------------------------------------------------------------
 * IP-prefix entry (RT-5)
 * --------------------------------------------------------------------- */
typedef struct evpn_ip_prefix {
    evpn_prefix_t    prefix;
    uint32_t         vni;
    uint32_t         eth_tag;

    evpn_addr_t      gw_ip;
    evpn_mac_t       gw_mac;
    evpn_vtep_t     *vtep;
    bool             local;

    uint64_t         rd;
    uint32_t         local_pref;
    uint32_t         med;
    uint64_t         rt_list[EVPN_RT_MAX_PER_EVI];
    uint8_t          n_rt;

    uint64_t         hit_count;
    time_t           installed_at;
    time_t           last_update;
    struct evpn_ip_prefix *next;
} evpn_ip_prefix_t;

typedef struct evpn_prefix_table {
    evpn_ip_prefix_t **buckets;
    uint32_t           n_buckets;
    uint32_t           n_entries;
    pthread_rwlock_t   lock;
} evpn_prefix_table_t;

/* -----------------------------------------------------------------------
 * EVI
 * --------------------------------------------------------------------- */
typedef struct evpn_evi {
    uint32_t             evi_id;
    uint32_t             l2_vni;
    uint32_t             l3_vni;
    uint32_t             vrf_id;
    uint32_t             bd_ifindex;
    uint32_t             flags;
    uint8_t              encap;

    evpn_addr_t          local_vtep_ip;

    uint64_t             rd;
    uint64_t             rt_export[EVPN_RT_MAX_PER_EVI];
    uint8_t              n_rt_export;
    uint64_t             rt_import[EVPN_RT_MAX_PER_EVI];
    uint8_t              n_rt_import;

    /* IRB gateway */
    evpn_addr_t          irb_ip;
    evpn_mac_t           irb_mac;
    bool                 irb_configured;

    evpn_mac_table_t     mac_table;
    evpn_prefix_table_t  pfx_table;

    evpn_imet_t         *imet_list;
    uint32_t             n_imet;

    /* Stats */
    uint64_t             rx_mac_routes;
    uint64_t             tx_mac_routes;
    uint64_t             rx_pfx_routes;
    uint64_t             tx_pfx_routes;
    uint64_t             arp_suppressed;

    time_t               created_at;
    pthread_rwlock_t     lock;
    struct evpn_evi     *next;
} evpn_evi_t;

typedef struct evpn_evi_table {
    evpn_evi_t      **buckets;
    uint32_t          n_buckets;
    uint32_t          n_evis;
    pthread_rwlock_t  lock;
} evpn_evi_table_t;

/* -----------------------------------------------------------------------
 * Module context
 * --------------------------------------------------------------------- */
typedef struct evpn_ctx {
    evpn_evi_table_t  evi_table;
    evpn_vtep_table_t vtep_table;

    evpn_es_t        *es_list;
    uint32_t          n_es;
    pthread_rwlock_t  es_lock;

    evpn_addr_t       local_vtep_ip;
    uint32_t          local_vtep_ifindex;
    uint32_t          local_asn;

    char              sock_path[256];
    int               sock_fd;
    bool              running;
    pthread_t         ipc_thread;
} evpn_ctx_t;

/* -----------------------------------------------------------------------
 * IPC command names
 * --------------------------------------------------------------------- */
#define EVPN_CMD_CREATE_EVI     "create_evi"
#define EVPN_CMD_DELETE_EVI     "delete_evi"
#define EVPN_CMD_LIST_EVIS      "list_evis"
#define EVPN_CMD_GET_EVI        "get_evi"
#define EVPN_CMD_SET_EVI_RD     "set_evi_rd"
#define EVPN_CMD_ADD_EVI_RT     "add_evi_rt"
#define EVPN_CMD_DEL_EVI_RT     "del_evi_rt"
#define EVPN_CMD_SET_IRB        "set_irb"

#define EVPN_CMD_ADD_VTEP       "add_vtep"
#define EVPN_CMD_DEL_VTEP       "del_vtep"
#define EVPN_CMD_LIST_VTEPS     "list_vteps"

#define EVPN_CMD_ADD_MAC        "add_mac"
#define EVPN_CMD_DEL_MAC        "del_mac"
#define EVPN_CMD_LEARN_MAC      "learn_mac"
#define EVPN_CMD_LIST_MACS      "list_macs"
#define EVPN_CMD_LOOKUP_MAC     "lookup_mac"
#define EVPN_CMD_FLUSH_MAC      "flush_mac"

#define EVPN_CMD_ADD_IMET       "add_imet"
#define EVPN_CMD_DEL_IMET       "del_imet"
#define EVPN_CMD_LIST_IMET      "list_imet"

#define EVPN_CMD_ADD_PREFIX     "add_prefix"
#define EVPN_CMD_DEL_PREFIX     "del_prefix"
#define EVPN_CMD_LIST_PREFIXES  "list_prefixes"
#define EVPN_CMD_LOOKUP_PREFIX  "lookup_prefix"

#define EVPN_CMD_ADD_ES         "add_es"
#define EVPN_CMD_DEL_ES         "del_es"
#define EVPN_CMD_LIST_ES        "list_es"

#define EVPN_CMD_GET_STATS      "get_stats"
#define EVPN_CMD_CLEAR_STATS    "clear_stats"
#define EVPN_CMD_DUMP_CONFIG    "dump_config"
#define EVPN_CMD_LOAD_CONFIG    "load_config"

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

/* Lifecycle */
evpn_ctx_t *evpn_ctx_create(void);
void        evpn_ctx_destroy(evpn_ctx_t *ctx);
int         evpn_init(evpn_ctx_t *ctx, const char *sock_path,
                      const evpn_addr_t *local_vtep, uint32_t local_asn);
void        evpn_shutdown(evpn_ctx_t *ctx);

/* EVI */
int         evpn_evi_create(evpn_ctx_t *ctx, uint32_t evi_id,
                            uint32_t l2_vni, uint32_t l3_vni,
                            uint32_t vrf_id, uint32_t flags);
int         evpn_evi_delete(evpn_ctx_t *ctx, uint32_t evi_id);
evpn_evi_t *evpn_evi_find(evpn_ctx_t *ctx, uint32_t evi_id);
evpn_evi_t *evpn_evi_find_by_vni(evpn_ctx_t *ctx, uint32_t vni);
int         evpn_evi_set_rd(evpn_ctx_t *ctx, uint32_t evi_id, uint64_t rd);
int         evpn_evi_add_rt(evpn_ctx_t *ctx, uint32_t evi_id,
                            uint64_t rt, bool is_export);
int         evpn_evi_del_rt(evpn_ctx_t *ctx, uint32_t evi_id,
                            uint64_t rt, bool is_export);
int         evpn_evi_set_irb(evpn_ctx_t *ctx, uint32_t evi_id,
                             const evpn_addr_t *ip, const evpn_mac_t *mac);

/* VTEP */
int          evpn_vtep_add(evpn_ctx_t *ctx, const evpn_addr_t *ip,
                           uint8_t encap, uint32_t flags);
int          evpn_vtep_del(evpn_ctx_t *ctx, const evpn_addr_t *ip);
evpn_vtep_t *evpn_vtep_find(evpn_ctx_t *ctx, const evpn_addr_t *ip);

/* MAC-IP (RT-2) */
int            evpn_mac_add(evpn_ctx_t *ctx, uint32_t evi_id,
                            const evpn_mac_t *mac, const evpn_addr_t *ip,
                            uint32_t flags, const evpn_addr_t *vtep_ip,
                            uint32_t out_ifindex, uint64_t rd);
int            evpn_mac_del(evpn_ctx_t *ctx, uint32_t evi_id,
                            const evpn_mac_t *mac, const evpn_addr_t *ip);
evpn_mac_ip_t *evpn_mac_lookup(evpn_ctx_t *ctx, uint32_t evi_id,
                               const evpn_mac_t *mac, const evpn_addr_t *ip);
int            evpn_mac_learn(evpn_ctx_t *ctx, uint32_t evi_id,
                              const evpn_mac_t *mac, const evpn_addr_t *ip,
                              uint32_t in_ifindex);
int            evpn_mac_flush(evpn_ctx_t *ctx, uint32_t evi_id,
                              const evpn_addr_t *vtep_ip); /* NULL=all remote */

/* IMET (RT-3) */
int  evpn_imet_add(evpn_ctx_t *ctx, uint32_t evi_id,
                   const evpn_addr_t *vtep_ip, uint64_t rd);
int  evpn_imet_del(evpn_ctx_t *ctx, uint32_t evi_id,
                   const evpn_addr_t *vtep_ip);

/* IP-prefix (RT-5) */
int               evpn_prefix_add(evpn_ctx_t *ctx, uint32_t evi_id,
                                  const evpn_prefix_t *pfx,
                                  const evpn_addr_t *gw_ip,
                                  const evpn_mac_t *gw_mac,
                                  const evpn_addr_t *vtep_ip,
                                  uint64_t rd, bool local);
int               evpn_prefix_del(evpn_ctx_t *ctx, uint32_t evi_id,
                                  const evpn_prefix_t *pfx);
evpn_ip_prefix_t *evpn_prefix_lookup(evpn_ctx_t *ctx, uint32_t evi_id,
                                     const evpn_addr_t *dst);

/* Ethernet Segment (RT-4) */
int        evpn_es_add(evpn_ctx_t *ctx, const evpn_esi_t *esi, uint8_t type,
                       const evpn_mac_t *sys_mac, uint32_t local_disc);
int        evpn_es_del(evpn_ctx_t *ctx, const evpn_esi_t *esi);
evpn_es_t *evpn_es_find(evpn_ctx_t *ctx, const evpn_esi_t *esi);

/* Persistence */
int  evpn_save_config(evpn_ctx_t *ctx, const char *path);
int  evpn_load_config(evpn_ctx_t *ctx, const char *path);

/* Helpers */
int      evpn_addr_parse(const char *str, evpn_addr_t *out);
int      evpn_prefix_parse(const char *str, evpn_prefix_t *out);
void     evpn_addr_to_str(const evpn_addr_t *a, char *buf, size_t len);
void     evpn_prefix_to_str(const evpn_prefix_t *p, char *buf, size_t len);
bool     evpn_prefix_contains(const evpn_prefix_t *pfx, const evpn_addr_t *addr);
int      evpn_mac_parse(const char *str, evpn_mac_t *out);
void     evpn_mac_to_str(const evpn_mac_t *mac, char *buf, size_t len);
int      evpn_esi_parse(const char *str, evpn_esi_t *out);
void     evpn_esi_to_str(const evpn_esi_t *esi, char *buf, size_t len);
uint64_t evpn_rd_make(uint32_t asn, uint16_t local);
uint64_t evpn_rt_make(uint32_t asn, uint16_t local);
void     evpn_rd_to_str(uint64_t rd, char *buf, size_t len);
uint32_t evpn_fnv1a_mac(const evpn_mac_t *mac, uint32_t n);
uint32_t evpn_fnv1a_addr(const evpn_addr_t *a, uint32_t n);
uint32_t evpn_fnv1a_prefix(const evpn_prefix_t *p, uint32_t n);

#endif /* EVPN_H */
