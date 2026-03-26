#ifndef VLAN_H
#define VLAN_H

#include <stdint.h>
#include "fdb.h"

#define VLAN_MAX          4094
#define VLAN_NAME_LEN     32
#define VLAN_BITMAP_WORDS ((VLAN_MAX + 1 + 63) / 64)

/* ─── VLAN entry ─────────────────────────────────────────────── */
typedef struct {
    uint16_t vid;
    char     name[VLAN_NAME_LEN];
    int      active;
    uint64_t rx_frames;
    uint64_t tx_frames;
} vlan_entry_t;

/* ─── Port VLAN mode ─────────────────────────────────────────── */
typedef enum {
    VLAN_PORT_ACCESS = 0,   /* single untagged VLAN              */
    VLAN_PORT_TRUNK  = 1,   /* tagged, multiple VLANs            */
    VLAN_PORT_HYBRID = 2,   /* tagged + one untagged             */
} vlan_port_mode_t;

/* ─── Per-port VLAN config ───────────────────────────────────── */
typedef struct {
    char              name[FDB_IFNAME_LEN];
    vlan_port_mode_t  mode;
    uint16_t          pvid;                    /* native/untagged VLAN */
    uint64_t          allowed[VLAN_BITMAP_WORDS]; /* bitmask of allowed VIDs */
    int               in_use;
} vlan_port_t;

/* ─── VLAN database ──────────────────────────────────────────── */
#define VLAN_MAX_PORTS 256

typedef struct {
    vlan_entry_t vlans[VLAN_MAX + 1];   /* indexed by VID            */
    vlan_port_t  ports[VLAN_MAX_PORTS];
    int          n_ports;
    int          vlan_count;
} vlan_db_t;

/* ─── Bitmap helpers ─────────────────────────────────────────── */
static inline void vlan_bmp_set(uint64_t *bmp, uint16_t vid) {
    bmp[vid / 64] |= (1ULL << (vid % 64));
}
static inline void vlan_bmp_clr(uint64_t *bmp, uint16_t vid) {
    bmp[vid / 64] &= ~(1ULL << (vid % 64));
}
static inline int vlan_bmp_test(const uint64_t *bmp, uint16_t vid) {
    return (bmp[vid / 64] >> (vid % 64)) & 1;
}

/* ─── API ────────────────────────────────────────────────────── */
void  vlan_db_init(vlan_db_t *db);
int   vlan_add(vlan_db_t *db, uint16_t vid, const char *name);
int   vlan_del(vlan_db_t *db, uint16_t vid);
vlan_entry_t *vlan_find(vlan_db_t *db, uint16_t vid);

vlan_port_t *vlan_port_get(vlan_db_t *db, const char *port);
vlan_port_t *vlan_port_add(vlan_db_t *db, const char *port);
int   vlan_port_set_mode(vlan_db_t *db, const char *port,
                          vlan_port_mode_t mode, uint16_t pvid);
int   vlan_port_allow(vlan_db_t *db, const char *port,
                       uint16_t vid_lo, uint16_t vid_hi);
int   vlan_port_deny(vlan_db_t *db, const char *port,
                      uint16_t vid_lo, uint16_t vid_hi);

/* Returns 1 if port is allowed to carry vid, 0 if not */
int   vlan_port_admits(const vlan_db_t *db, const char *port, uint16_t vid);

const char *vlan_mode_str(vlan_port_mode_t m);

#endif /* VLAN_H */
