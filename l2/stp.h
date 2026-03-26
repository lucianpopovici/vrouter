#ifndef STP_H
#define STP_H

#include <stdint.h>
#include <stddef.h>

/* ─── Protocol modes ─────────────────────────────────────────── */
typedef enum {
    STP_MODE_STP  = 0,   /* IEEE 802.1D classic                   */
    STP_MODE_RSTP = 1,   /* IEEE 802.1w rapid                     */
    STP_MODE_MST  = 2,   /* IEEE 802.1s multiple spanning tree    */
} stp_mode_t;

/* ─── Port states ────────────────────────────────────────────── */
typedef enum {
    STP_PS_DISABLED   = 0,
    STP_PS_BLOCKING   = 1,   /* STP only                          */
    STP_PS_LISTENING  = 2,   /* STP only                          */
    STP_PS_LEARNING   = 3,
    STP_PS_FORWARDING = 4,
    STP_PS_DISCARDING = 5,   /* RSTP/MST (replaces BLK+LST)       */
} stp_port_state_t;

/* ─── Port roles ─────────────────────────────────────────────── */
typedef enum {
    STP_PR_DISABLED   = 0,
    STP_PR_ROOT       = 1,   /* best path to root bridge          */
    STP_PR_DESIGNATED = 2,   /* best path on this LAN segment     */
    STP_PR_ALTERNATE  = 3,   /* RSTP/MST: backup path to root     */
    STP_PR_BACKUP     = 4,   /* RSTP/MST: backup to segment       */
    STP_PR_MASTER     = 5,   /* MST: connects IST to CIST         */
} stp_port_role_t;

/* ─── Bridge ID (priority 4 bits + sys-id-ext 12 bits + MAC 6B) */
typedef struct {
    uint16_t priority;       /* default 32768, must be mult of 4096 */
    uint8_t  mac[6];
} stp_bridge_id_t;

/* ─── BPDU types ─────────────────────────────────────────────── */
#define BPDU_TYPE_CONFIG  0x00   /* STP config BPDU               */
#define BPDU_TYPE_TCN     0x80   /* topology change notification  */
#define BPDU_TYPE_RSTP    0x02   /* RST/MST BPDU                  */

/* ─── Config BPDU (STP/RSTP, 35 bytes on wire) ──────────────── */
typedef struct __attribute__((packed)) {
    uint16_t        proto_id;        /* 0x0000                    */
    uint8_t         version;         /* 0=STP, 2=RSTP, 3=MST     */
    uint8_t         bpdu_type;
    uint8_t         flags;
    stp_bridge_id_t root_id;
    uint32_t        root_path_cost;
    stp_bridge_id_t bridge_id;
    uint16_t        port_id;         /* priority(4b)+port_num(12b)*/
    uint16_t        message_age;     /* in 1/256 seconds          */
    uint16_t        max_age;
    uint16_t        hello_time;
    uint16_t        fwd_delay;
} stp_bpdu_t;

/* BPDU flags */
#define BPDU_FL_TC         (1 << 0)   /* topology change          */
#define BPDU_FL_PROPOSAL   (1 << 1)   /* RSTP proposal            */
#define BPDU_FL_ROLE_SHIFT 2          /* port role bits [3:2]     */
#define BPDU_FL_LEARNING   (1 << 4)
#define BPDU_FL_FORWARDING (1 << 5)
#define BPDU_FL_AGREEMENT  (1 << 6)   /* RSTP agreement           */
#define BPDU_FL_TCA        (1 << 7)   /* TC acknowledgement       */

/* ─── MST constants ──────────────────────────────────────────── */
#define MST_MAX_INSTANCES   16        /* MSTI 0 (IST) + 1..15     */
#define MST_MAX_VLANS       4094
#define MST_REGION_NAME_LEN 32

/* ─── Per-port per-instance state (used by MST) ─────────────── */
typedef struct {
    stp_port_state_t state;
    stp_port_role_t  role;
    uint32_t         path_cost;
    uint32_t         root_path_cost;
    stp_bridge_id_t  designated_root;
    stp_bridge_id_t  designated_bridge;
    uint16_t         designated_port;
    uint8_t          tc_while;         /* topology change timer    */
    uint8_t          flags;
} stp_port_msti_t;

/* ─── Port ───────────────────────────────────────────────────── */
#define STP_MAX_PORTS  64

typedef struct {
    char             name[16];
    uint16_t         port_id;          /* priority(4b)+num(12b)   */
    int              enabled;
    int              link_up;
    int              edge;             /* RSTP edge port (no BPDU) */
    int              point_to_point;   /* RSTP P2P link           */
    uint32_t         path_cost;        /* default by speed        */

    /* per-port STP state (shared across STP/RSTP, per IST for MST) */
    stp_port_state_t state;
    stp_port_role_t  role;
    uint32_t         root_path_cost;
    stp_bridge_id_t  designated_root;
    stp_bridge_id_t  designated_bridge;
    uint16_t         designated_port;

    /* RSTP rapid convergence */
    int              proposing;
    int              proposed;
    int              agreed;
    int              synced;
    int              sync;
    int              reroot;

    /* timers (in hello-time units) */
    int              forward_delay_timer;
    int              message_age_timer;
    int              hold_timer;
    int              tc_while_timer;

    /* MST per-instance state */
    stp_port_msti_t  msti[MST_MAX_INSTANCES];

    /* stats */
    uint64_t         bpdu_rx;
    uint64_t         bpdu_tx;
    uint64_t         tc_rx;
} stp_port_t;

/* ─── MST instance ───────────────────────────────────────────── */
typedef struct {
    int              active;
    uint8_t          id;               /* 0 = IST/CIST, 1-15 = MSTI */
    uint16_t         vlan_map[MST_MAX_VLANS + 1]; /* vlan → instance */
    stp_bridge_id_t  regional_root;
    uint32_t         internal_root_path_cost;
    uint16_t bridge_priority;  /* per-instance priority    */
    uint64_t         tc_count;
} stp_msti_t;

/* ─── Bridge / STP instance ──────────────────────────────────── */
typedef struct {
    stp_mode_t       mode;
    stp_bridge_id_t  bridge_id;
    stp_bridge_id_t  root_id;
    uint32_t         root_path_cost;
    uint16_t         root_port_id;     /* 0 = we are root          */

    /* timers (seconds) */
    uint16_t         hello_time;       /* default 2                */
    uint16_t         max_age;          /* default 20               */
    uint16_t         fwd_delay;        /* default 15               */

    /* topology change */
    int              tc_active;
    uint64_t         tc_count;
    uint64_t         tc_last;          /* unix time of last TC     */

    /* ports */
    stp_port_t       ports[STP_MAX_PORTS];
    int              n_ports;

    /* MST region */
    char             mst_region[MST_REGION_NAME_LEN];
    uint32_t         mst_revision;
    stp_msti_t       mstis[MST_MAX_INSTANCES];

} stp_bridge_t;

/* ─── API ───────────────────────────────────────────────────── */
void stp_init(stp_bridge_t *br, const uint8_t mac[6], stp_mode_t mode);

/* Port management */
int  stp_port_add(stp_bridge_t *br, const char *name,
                  uint16_t port_num, uint32_t path_cost);
stp_port_t *stp_port_find(stp_bridge_t *br, const char *name);

/* Events */
void stp_port_up(stp_bridge_t *br, stp_port_t *p);
void stp_port_down(stp_bridge_t *br, stp_port_t *p);
void stp_receive_bpdu(stp_bridge_t *br, stp_port_t *p,
                      const stp_bpdu_t *bpdu);
void stp_tick(stp_bridge_t *br);   /* call every hello_time seconds */

/* MST */
int  mst_map_vlan(stp_bridge_t *br, uint16_t vlan, uint8_t instance);
int  mst_instance_active(const stp_bridge_t *br, uint8_t inst);
int  mst_vlan_instance(const stp_bridge_t *br, uint16_t vlan);

/* Helpers */
int  stp_bridge_id_cmp(const stp_bridge_id_t *a, const stp_bridge_id_t *b);
int  stp_is_root(const stp_bridge_t *br);
const char *stp_state_str(stp_port_state_t s);
const char *stp_role_str(stp_port_role_t r);
const char *stp_mode_str(stp_mode_t m);
void stp_bridge_id_str(const stp_bridge_id_t *id, char *buf, size_t sz);

/* Generate BPDU for transmission */
void stp_build_bpdu(const stp_bridge_t *br, const stp_port_t *p,
                    stp_bpdu_t *out);

#endif /* STP_H */
void recalculate_roles(stp_bridge_t *br);
