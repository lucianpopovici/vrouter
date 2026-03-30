#ifndef VXLAN_H
#define VXLAN_H

/*
 * vxlan.h — VXLAN data-plane module (RFC 7348 / RFC 8365)
 *
 * Responsibilities:
 *   - VXLAN frame encapsulation  (inner Ethernet → outer UDP/IP)
 *   - VXLAN frame decapsulation  (outer UDP/IP → inner Ethernet)
 *   - Tunnel table: one entry per remote VTEP, keyed by (src_ip, dst_ip, vni)
 *   - Receive thread: listens on a UDP socket for incoming VXLAN frames
 *   - Statistics per tunnel and per VNI
 *   - FDB (Forwarding Database): MAC → VTEP mapping for L2 forwarding
 *   - VNI table: maps VNI → local bridge-domain / interface
 *   - IPC server: JSON commands over a Unix socket
 *   - Persistence: NDJSON atomic save/load
 *
 * Wire format (RFC 7348 §5):
 *
 *   Outer Ethernet (if routed through underlay NIC)
 *   Outer IP  (src = local VTEP, dst = remote VTEP)
 *   Outer UDP (src = entropy port, dst = 4789)
 *   VXLAN header (8 bytes):
 *     bits  0-3 : flags (bit 3 = I, VNI valid)
 *     bits  4-31: reserved
 *     bits 32-55: VNI (24 bits)
 *     bits 56-63: reserved
 *   Inner Ethernet frame
 *
 * Locking: same pattern as ip/vrf/evpn — rwlock embedded in every table,
 *          single-exit goto-out discipline throughout.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <time.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/* -----------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------- */
#define VXLAN_PORT_DEFAULT      4789
#define VXLAN_PORT_MIN          1024
#define VXLAN_PORT_MAX          65535

/* VNI range */
#define VXLAN_VNI_MIN           1u
#define VXLAN_VNI_MAX           16777215u   /* 2^24 - 1 */
#define VXLAN_VNI_INVALID       0u

/* Header sizes */
#define VXLAN_HDR_LEN           8           /* VXLAN header */
#define VXLAN_UDP_HDR_LEN       8
#define VXLAN_IPV4_HDR_LEN      20
#define VXLAN_IPV6_HDR_LEN      40
#define VXLAN_ETH_HDR_LEN       14          /* inner Ethernet (no VLAN) */
#define VXLAN_OUTER_V4_OVERHEAD (VXLAN_IPV4_HDR_LEN + VXLAN_UDP_HDR_LEN + VXLAN_HDR_LEN)
#define VXLAN_OUTER_V6_OVERHEAD (VXLAN_IPV6_HDR_LEN + VXLAN_UDP_HDR_LEN + VXLAN_HDR_LEN)

/* Max inner frame (assuming 1500-byte underlay MTU) */
#define VXLAN_MAX_FRAME         9216        /* jumbo frame support */
#define VXLAN_MTU_DEFAULT       1450        /* 1500 - 50 bytes overhead */

/* Table sizes */
#define VXLAN_TUNNEL_BUCKETS    256
#define VXLAN_FDB_BUCKETS       4096
#define VXLAN_VNI_BUCKETS       64
#define VXLAN_MAX_TUNNELS       4096
#define VXLAN_MAX_FDB_ENTRIES   65536
#define VXLAN_MAX_VNIS          1024

/* FDB entry flags */
#define VXLAN_FDB_LOCAL         (1u << 0)   /* MAC on local interface */
#define VXLAN_FDB_REMOTE        (1u << 1)   /* MAC behind remote VTEP */
#define VXLAN_FDB_STATIC        (1u << 2)   /* statically configured */
#define VXLAN_FDB_STICKY        (1u << 3)   /* no mobility */
#define VXLAN_FDB_FLOOD         (1u << 4)   /* BUM flood entry */

/* Tunnel flags */
#define VXLAN_TUNNEL_UP         (1u << 0)
#define VXLAN_TUNNEL_BFD        (1u << 1)
#define VXLAN_TUNNEL_IPSEC      (1u << 2)

/* VNI flags */
#define VXLAN_VNI_ACTIVE        (1u << 0)
#define VXLAN_VNI_MCAST         (1u << 1)   /* multicast replication */
#define VXLAN_VNI_FLOOD         (1u << 2)   /* head-end flood replication */
#define VXLAN_VNI_ARP_SUPPRESS  (1u << 3)
#define VXLAN_VNI_L3            (1u << 4)   /* L3VNI (IRB) */

/* Error codes */
#define VXLAN_OK                0
#define VXLAN_ERR_NOMEM        -1
#define VXLAN_ERR_NOTFOUND     -2
#define VXLAN_ERR_EXISTS       -3
#define VXLAN_ERR_INVAL        -4
#define VXLAN_ERR_FULL         -5
#define VXLAN_ERR_SOCKET       -6
#define VXLAN_ERR_ENCAP        -7
#define VXLAN_ERR_DECAP        -8

/* -----------------------------------------------------------------------
 * Wire format types
 * --------------------------------------------------------------------- */

/* VXLAN header (RFC 7348 §5), network byte order on wire */
typedef struct __attribute__((packed)) vxlan_hdr {
    uint32_t flags_reserved;    /* bits[3]=I (VNI valid), rest reserved */
    uint32_t vni_reserved;      /* bits[8-31]=VNI, bits[0-7]=reserved */
} vxlan_hdr_t;

/* VXLAN_HDR_LEN must equal sizeof(vxlan_hdr_t) */
_Static_assert(sizeof(vxlan_hdr_t) == 8, "vxlan_hdr_t must be 8 bytes");

/* -----------------------------------------------------------------------
 * Address type (IPv4 or IPv6)
 * --------------------------------------------------------------------- */
typedef struct vxlan_addr {
    sa_family_t af;
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } u;
} vxlan_addr_t;

/* 6-byte MAC address */
typedef struct vxlan_mac { uint8_t b[6]; } vxlan_mac_t;

/* -----------------------------------------------------------------------
 * Tunnel entry — one remote VTEP
 * A tunnel is uniquely identified by (local_ip, remote_ip, vni).
 * --------------------------------------------------------------------- */
typedef struct vxlan_tunnel {
    /* Key */
    vxlan_addr_t    local_ip;
    vxlan_addr_t    remote_ip;
    uint32_t        vni;

    /* Config */
    uint32_t        flags;          /* VXLAN_TUNNEL_* */
    uint16_t        dst_port;       /* remote UDP port (default 4789) */
    uint16_t        src_port_base;  /* entropy src port range base */
    uint32_t        out_ifindex;    /* underlay egress interface */
    uint8_t         ttl;
    uint8_t         tos;

    /* Stats */
    uint64_t        tx_pkts;
    uint64_t        tx_bytes;
    uint64_t        tx_errors;
    uint64_t        rx_pkts;
    uint64_t        rx_bytes;
    uint64_t        rx_errors;

    time_t          created_at;
    time_t          last_tx;
    time_t          last_rx;

    struct vxlan_tunnel *next;  /* hash chain */
} vxlan_tunnel_t;

typedef struct vxlan_tunnel_table {
    vxlan_tunnel_t  **buckets;
    uint32_t          n_buckets;
    uint32_t          n_tunnels;
    pthread_rwlock_t  lock;
} vxlan_tunnel_table_t;

/* -----------------------------------------------------------------------
 * FDB entry — MAC → VTEP mapping for L2 forwarding
 * --------------------------------------------------------------------- */
typedef struct vxlan_fdb_entry {
    /* Key */
    vxlan_mac_t     mac;
    uint32_t        vni;

    /* Value */
    uint32_t        flags;          /* VXLAN_FDB_* */
    vxlan_addr_t    remote_ip;      /* VTEP IP (zero for local) */
    uint32_t        out_ifindex;    /* local interface (for local entries) */
    uint32_t        dst_port;       /* per-entry dst UDP port override */

    /* Stats */
    uint64_t        hit_count;
    time_t          installed_at;
    time_t          last_seen;

    struct vxlan_fdb_entry *next;
} vxlan_fdb_entry_t;

typedef struct vxlan_fdb_table {
    vxlan_fdb_entry_t **buckets;
    uint32_t            n_buckets;
    uint32_t            n_entries;
    pthread_rwlock_t    lock;
} vxlan_fdb_table_t;

/* -----------------------------------------------------------------------
 * VNI entry — one VXLAN Network Identifier
 * --------------------------------------------------------------------- */
typedef struct vxlan_vni {
    uint32_t        vni;
    uint32_t        flags;          /* VXLAN_VNI_* */
    uint32_t        bd_ifindex;     /* bridge-domain / VLAN interface */
    uint32_t        vrf_id;         /* associated VRF (L3VNI) */
    uint16_t        mtu;

    /* Multicast group (for VNI_MCAST mode) */
    vxlan_addr_t    mcast_group;
    uint32_t        mcast_ifindex;

    /* Per-VNI FDB */
    vxlan_fdb_table_t fdb;

    /* Flood list (head-end replication) */
    vxlan_addr_t   *flood_list;     /* array of remote VTEP IPs */
    uint32_t        n_flood;

    /* Stats */
    uint64_t        rx_pkts;
    uint64_t        tx_pkts;
    uint64_t        rx_bytes;
    uint64_t        tx_bytes;
    uint64_t        rx_drop_novtep;
    uint64_t        rx_drop_nomem;
    uint64_t        rx_unknown_mac;
    uint64_t        tx_flood_pkts;

    time_t          created_at;
    pthread_rwlock_t lock;
    struct vxlan_vni *next;         /* hash chain */
} vxlan_vni_t;

typedef struct vxlan_vni_table {
    vxlan_vni_t    **buckets;
    uint32_t         n_buckets;
    uint32_t         n_vnis;
    pthread_rwlock_t lock;
} vxlan_vni_table_t;

/* -----------------------------------------------------------------------
 * Packet descriptor — used for encap/decap without extra allocation
 * --------------------------------------------------------------------- */
typedef struct vxlan_pkt {
    uint8_t    *buf;                /* pointer into frame buffer */
    size_t      len;                /* total bytes in buf */
    /* decoded fields (populated by decap) */
    uint32_t    vni;
    vxlan_addr_t src_vtep;
    vxlan_addr_t dst_vtep;
    uint16_t    src_port;
    uint16_t    dst_port;
    uint8_t    *inner;              /* pointer to inner Ethernet header */
    size_t      inner_len;
} vxlan_pkt_t;

/* Callback: called by the receive thread for each decapsulated frame */
typedef void (*vxlan_rx_cb_t)(vxlan_pkt_t *pkt, void *user);

/* -----------------------------------------------------------------------
 * Global stats
 * --------------------------------------------------------------------- */
typedef struct vxlan_stats {
    uint64_t    rx_pkts;
    uint64_t    rx_bytes;
    uint64_t    rx_decap_ok;
    uint64_t    rx_decap_err;
    uint64_t    rx_drop_vni;        /* unknown VNI */
    uint64_t    rx_drop_short;      /* too short */
    uint64_t    tx_pkts;
    uint64_t    tx_bytes;
    uint64_t    tx_encap_ok;
    uint64_t    tx_encap_err;
    uint64_t    tx_drop_notunnel;
    pthread_rwlock_t lock;
} vxlan_stats_t;

/* -----------------------------------------------------------------------
 * Module context
 * --------------------------------------------------------------------- */
typedef struct vxlan_ctx {
    /* Tables */
    vxlan_tunnel_table_t tunnel_table;
    vxlan_vni_table_t    vni_table;

    /* Local VTEP */
    vxlan_addr_t    local_ip;
    uint32_t        local_ifindex;
    uint16_t        listen_port;    /* UDP port to bind (default 4789) */

    /* UDP receive socket (IPv4 and IPv6) */
    int             sock_v4;
    int             sock_v6;

    /* Receive thread */
    pthread_t       rx_thread;
    bool            rx_running;

    /* Rx callback (set before evpn_init) */
    vxlan_rx_cb_t   rx_cb;
    void           *rx_cb_user;

    /* Tx raw socket (SOCK_DGRAM, one per AF) */
    int             tx_sock_v4;
    int             tx_sock_v6;

    /* Stats */
    vxlan_stats_t   stats;

    /* IPC */
    char            sock_path[256];
    int             ipc_fd;
    pthread_t       ipc_thread;
    bool            running;
} vxlan_ctx_t;

/* -----------------------------------------------------------------------
 * IPC command names
 * --------------------------------------------------------------------- */
#define VXLAN_CMD_ADD_VNI           "add_vni"
#define VXLAN_CMD_DEL_VNI           "del_vni"
#define VXLAN_CMD_LIST_VNIS         "list_vnis"
#define VXLAN_CMD_GET_VNI           "get_vni"
#define VXLAN_CMD_SET_VNI_FLOOD     "set_vni_flood"

#define VXLAN_CMD_ADD_TUNNEL        "add_tunnel"
#define VXLAN_CMD_DEL_TUNNEL        "del_tunnel"
#define VXLAN_CMD_LIST_TUNNELS      "list_tunnels"
#define VXLAN_CMD_GET_TUNNEL        "get_tunnel"

#define VXLAN_CMD_ADD_FDB           "add_fdb"
#define VXLAN_CMD_DEL_FDB           "del_fdb"
#define VXLAN_CMD_LIST_FDB          "list_fdb"
#define VXLAN_CMD_LOOKUP_FDB        "lookup_fdb"
#define VXLAN_CMD_FLUSH_FDB         "flush_fdb"

#define VXLAN_CMD_ADD_FLOOD         "add_flood"
#define VXLAN_CMD_DEL_FLOOD         "del_flood"
#define VXLAN_CMD_LIST_FLOOD        "list_flood"

#define VXLAN_CMD_SEND_FRAME        "send_frame"
#define VXLAN_CMD_GET_STATS         "get_stats"
#define VXLAN_CMD_CLEAR_STATS       "clear_stats"
#define VXLAN_CMD_DUMP_CONFIG       "dump_config"
#define VXLAN_CMD_LOAD_CONFIG       "load_config"

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

/* Lifecycle */
vxlan_ctx_t *vxlan_ctx_create(void);
void         vxlan_ctx_destroy(vxlan_ctx_t *ctx);
int          vxlan_init(vxlan_ctx_t *ctx, const char *sock_path,
                        const vxlan_addr_t *local_ip,
                        uint32_t local_ifindex, uint16_t listen_port);
void         vxlan_shutdown(vxlan_ctx_t *ctx);

/* Set receive callback before calling vxlan_init */
void         vxlan_set_rx_cb(vxlan_ctx_t *ctx, vxlan_rx_cb_t cb, void *user);

/* VNI management */
int          vxlan_vni_add(vxlan_ctx_t *ctx, uint32_t vni, uint32_t bd_ifindex,
                           uint32_t flags, uint16_t mtu);
int          vxlan_vni_del(vxlan_ctx_t *ctx, uint32_t vni);
vxlan_vni_t *vxlan_vni_find(vxlan_ctx_t *ctx, uint32_t vni);
int          vxlan_vni_set_mcast(vxlan_ctx_t *ctx, uint32_t vni,
                                 const vxlan_addr_t *mcast_group,
                                 uint32_t mcast_ifindex);

/* Flood list (head-end replication) */
int          vxlan_flood_add(vxlan_ctx_t *ctx, uint32_t vni,
                             const vxlan_addr_t *remote_ip);
int          vxlan_flood_del(vxlan_ctx_t *ctx, uint32_t vni,
                             const vxlan_addr_t *remote_ip);

/* Tunnel management */
int              vxlan_tunnel_add(vxlan_ctx_t *ctx,
                                  const vxlan_addr_t *remote_ip,
                                  uint32_t vni, uint32_t flags,
                                  uint16_t dst_port, uint8_t ttl);
int              vxlan_tunnel_del(vxlan_ctx_t *ctx,
                                  const vxlan_addr_t *remote_ip, uint32_t vni);
vxlan_tunnel_t  *vxlan_tunnel_find(vxlan_ctx_t *ctx,
                                   const vxlan_addr_t *remote_ip, uint32_t vni);

/* FDB (per-VNI MAC table) */
int               vxlan_fdb_add(vxlan_ctx_t *ctx, uint32_t vni,
                                const vxlan_mac_t *mac,
                                const vxlan_addr_t *remote_ip,
                                uint32_t out_ifindex, uint32_t flags);
int               vxlan_fdb_del(vxlan_ctx_t *ctx, uint32_t vni,
                                const vxlan_mac_t *mac);
vxlan_fdb_entry_t *vxlan_fdb_lookup(vxlan_ctx_t *ctx, uint32_t vni,
                                    const vxlan_mac_t *mac);
int               vxlan_fdb_learn(vxlan_ctx_t *ctx, uint32_t vni,
                                  const vxlan_mac_t *mac,
                                  const vxlan_addr_t *remote_ip,
                                  uint32_t in_ifindex);
int               vxlan_fdb_flush(vxlan_ctx_t *ctx, uint32_t vni,
                                  const vxlan_addr_t *remote_ip); /* NULL=all */

/* Data-plane: encapsulate and transmit one inner Ethernet frame */
int  vxlan_encap_send(vxlan_ctx_t *ctx, uint32_t vni,
                      const vxlan_addr_t *remote_ip,
                      const uint8_t *inner_frame, size_t inner_len);

/* Data-plane: decapsulate one received UDP payload into vxlan_pkt_t */
int  vxlan_decap(const uint8_t *udp_payload, size_t udp_len,
                 const vxlan_addr_t *src_ip, const vxlan_addr_t *dst_ip,
                 uint16_t src_port, uint16_t dst_port,
                 vxlan_pkt_t *out);

/* Flood one inner frame to all remote VTEPs in a VNI's flood list */
int  vxlan_flood(vxlan_ctx_t *ctx, uint32_t vni,
                 const uint8_t *inner_frame, size_t inner_len,
                 const vxlan_addr_t *exclude_vtep); /* NULL = flood all */

/* Stats */
void vxlan_stats_get(vxlan_ctx_t *ctx, vxlan_stats_t *out);
void vxlan_stats_clear(vxlan_ctx_t *ctx);

/* Persistence */
int  vxlan_save_config(vxlan_ctx_t *ctx, const char *path);
int  vxlan_load_config(vxlan_ctx_t *ctx, const char *path);

/* Helpers */
int      vxlan_addr_parse(const char *str, vxlan_addr_t *out);
void     vxlan_addr_to_str(const vxlan_addr_t *a, char *buf, size_t len);
int      vxlan_mac_parse(const char *str, vxlan_mac_t *out);
void     vxlan_mac_to_str(const vxlan_mac_t *mac, char *buf, size_t len);
bool     vxlan_addr_eq(const vxlan_addr_t *a, const vxlan_addr_t *b);

/* Low-level header helpers (exposed for testing) */
void     vxlan_hdr_encode(vxlan_hdr_t *hdr, uint32_t vni);
int      vxlan_hdr_decode(const vxlan_hdr_t *hdr, uint32_t *vni_out);

#endif /* VXLAN_H */
