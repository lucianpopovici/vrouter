#ifndef LACP_H
#define LACP_H

#include <stdint.h>
#include "fdb.h"

#define LACP_MAX_LAGS      32
#define LACP_MAX_MEMBERS   16     /* ports per LAG                 */
#define LACP_FAST_TIMER    1      /* seconds between PDUs (fast)   */
#define LACP_SLOW_TIMER    30     /* seconds between PDUs (slow)   */
#define LACP_SHORT_TIMEOUT 3      /* fast: expire after 3 PDUs     */
#define LACP_LONG_TIMEOUT  90     /* slow: expire after 3 PDUs     */

/* LACP port state bits (in LACPDU) */
#define LACP_ST_ACTIVITY   (1<<0) /* 1=active, 0=passive           */
#define LACP_ST_TIMEOUT    (1<<1) /* 1=short, 0=long               */
#define LACP_ST_AGGREGATION  (1<<2)
#define LACP_ST_SYNC         (1<<3)
#define LACP_ST_COLLECTING   (1<<4)
#define LACP_ST_DISTRIBUTING (1<<5)
#define LACP_ST_DEFAULTED  (1<<6)
#define LACP_ST_EXPIRED    (1<<7)

typedef enum {
    LACP_MODE_OFF     = 0,
    LACP_MODE_PASSIVE = 1,   /* respond but don't initiate     */
    LACP_MODE_ACTIVE  = 2,   /* always send LACPDUs            */
    LACP_MODE_STATIC  = 3,   /* no LACP, forced aggregation    */
} lacp_mode_t;

/* ─── System/port ID (6-byte MAC + 2-byte priority) ─────────── */
typedef struct {
    uint16_t priority;
    uint8_t  mac[6];
} lacp_sysid_t;

typedef struct {
    uint16_t priority;
    uint16_t number;
} lacp_portid_t;

/* ─── LACPDU (simplified, key fields only) ───────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t      subtype;          /* 0x01 */
    uint8_t      version;          /* 0x01 */
    /* actor */
    uint8_t      actor_tag;        /* 0x01 */
    uint8_t      actor_len;        /* 20   */
    lacp_sysid_t actor_sys;
    uint16_t     actor_key;
    lacp_portid_t actor_port;
    uint8_t      actor_state;
    uint8_t      _pad1[3];
    /* partner */
    uint8_t      partner_tag;      /* 0x02 */
    uint8_t      partner_len;      /* 20   */
    lacp_sysid_t partner_sys;
    uint16_t     partner_key;
    lacp_portid_t partner_port;
    uint8_t      partner_state;
    uint8_t      _pad2[3];
} lacp_pdu_t;

/* ─── Per-member port state ──────────────────────────────────── */
typedef enum {
    LACP_MBR_DETACHED    = 0,
    LACP_MBR_WAITING     = 1,
    LACP_MBR_ATTACHED    = 2,
    LACP_MBR_COLLECTING  = 3,
    LACP_MBR_DISTRIBUTING= 4,
} lacp_mstate_t;

typedef struct {
    char          port[FDB_IFNAME_LEN];
    int           enabled;
    lacp_mode_t   mode;
    lacp_portid_t actor_port;
    uint16_t      actor_key;
    uint8_t       actor_state;
    lacp_sysid_t  partner_sys;
    lacp_portid_t partner_port;
    uint16_t      partner_key;
    uint8_t       partner_state;
    lacp_mstate_t mux_state;
    int           selected;       /* selected for aggregation       */
    int           fast_timer;     /* 1=fast PDU rate                */
    int           pdu_timer;      /* countdown to next PDU          */
    int           expire_timer;   /* countdown to partner timeout   */
    uint64_t      pdu_rx;
    uint64_t      pdu_tx;
} lacp_member_t;

/* ─── LAG (Link Aggregation Group) ──────────────────────────── */
typedef struct {
    char         name[FDB_IFNAME_LEN];   /* e.g. "bond0", "lag1"   */
    int          active;
    uint16_t     key;                     /* aggregation key        */
    lacp_sysid_t system;
    int          n_members;
    lacp_member_t members[LACP_MAX_MEMBERS];
    int          n_active;               /* in distributing state   */
    uint64_t     tx_hash_seed;           /* for LAG hash            */
} lacp_lag_t;

/* ─── LACP table ─────────────────────────────────────────────── */
typedef struct {
    lacp_lag_t   lags[LACP_MAX_LAGS];
    int          n_lags;
    lacp_sysid_t system;               /* bridge system ID          */
} lacp_table_t;

/* ─── API ────────────────────────────────────────────────────── */
void  lacp_init(lacp_table_t *lt, const uint8_t sys_mac[6]);

lacp_lag_t    *lacp_lag_add(lacp_table_t *lt, const char *name, uint16_t key);
lacp_lag_t    *lacp_lag_find(lacp_table_t *lt, const char *name);
int            lacp_lag_del(lacp_table_t *lt, const char *name);

lacp_member_t *lacp_member_add(lacp_lag_t *lag, const char *port,
                                lacp_mode_t mode);
lacp_member_t *lacp_member_find(lacp_lag_t *lag, const char *port);
int            lacp_member_del(lacp_lag_t *lag, const char *port);

/* Process incoming LACPDU on a port */
void  lacp_receive(lacp_table_t *lt, lacp_lag_t *lag,
                    lacp_member_t *mbr, const lacp_pdu_t *pdu);

/* Tick: advance timers, trigger state transitions */
void  lacp_tick(lacp_table_t *lt);

/* Build outgoing LACPDU for a member */
void  lacp_build_pdu(const lacp_lag_t *lag,
                      const lacp_member_t *mbr, lacp_pdu_t *out);

/* Hash a frame to a member index for TX distribution */
int   lacp_select_member(const lacp_lag_t *lag,
                          const uint8_t src_mac[6],
                          const uint8_t dst_mac[6]);

const char *lacp_mode_str(lacp_mode_t m);
const char *lacp_mstate_str(lacp_mstate_t s);

#endif /* LACP_H */
