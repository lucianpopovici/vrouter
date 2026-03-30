#ifndef L2_PERSIST_H
#define L2_PERSIST_H

/*
 * l2_persist.h / l2_persist.c — dump and restore L2 state
 *
 * Saves: static/EVPN FDB entries, VLAN DB, STP timers,
 *        LACP LAG definitions.
 *
 * Format: newline-delimited JSON sections, one object per line:
 *   {"type":"fdb",  "mac":"aa:bb:cc:dd:ee:ff","vlan":10,"port":"eth0","flags":1}
 *   {"type":"vlan", "vid":100,"name":"prod"}
 *   {"type":"vlan_port","port":"eth0","mode":"access","pvid":100}
 *   {"type":"stp",  "priority":32768,"hello":2,"max_age":20,"fwd_delay":15,"mode":"rstp"}
 *   {"type":"lacp_lag","lag":"bond0","key":1}
 *   {"type":"lacp_member","lag":"bond0","port":"eth0","mode":"active"}
 */

#include "fdb.h"
#include "vlan.h"
#include "stp.h"
#include "lacp.h"

#define L2_DUMP_FILE "vrouter_l2.json"

/* Dump all persistent state. Returns 0 on success. */
int l2_persist_dump(const fdb_table_t   *fdb,
                     const vlan_db_t     *vlan,
                     const stp_bridge_t  *br,
                     const lacp_table_t  *lacp,
                     const char          *path);

/* Restore state. Returns number of objects restored, or -1 on error. */
int l2_persist_restore(fdb_table_t   *fdb,
                        vlan_db_t     *vlan,
                        stp_bridge_t  *br,
                        lacp_table_t  *lacp,
                        const char    *path);

#endif /* L2_PERSIST_H */
