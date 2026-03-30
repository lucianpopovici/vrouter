#ifndef IGMP_H
#define IGMP_H

#include <stdint.h>
#include "fdb.h"

#define IGMP_MAX_GROUPS    1024
#define IGMP_MAX_PORTS_GRP 64
#define IGMP_QUERY_INTERVAL  125   /* seconds                     */
#define IGMP_MEMBER_TIMEOUT  260   /* seconds before group expires*/

/* IGMP message types */
#define IGMP_MEMBERSHIP_QUERY   0x11
#define IGMP_V1_MEMBERSHIP_RPT  0x12
#define IGMP_V2_MEMBERSHIP_RPT  0x16
#define IGMP_V2_LEAVE_GROUP     0x17
#define IGMP_V3_MEMBERSHIP_RPT  0x22

/* ─── One multicast group membership ────────────────────────── */
typedef struct {
    char     port[FDB_IFNAME_LEN];
    time_t   last_seen;
    uint8_t  version;   /* 1, 2, or 3 */
} igmp_member_t;

typedef struct {
    uint32_t    group;              /* IPv4 multicast addr (host order) */
    uint16_t    vlan;
    int         active;
    int         n_members;
    igmp_member_t members[IGMP_MAX_PORTS_GRP];
    char        querier_port[FDB_IFNAME_LEN]; /* port toward querier */
    uint64_t    report_count;
    uint64_t    leave_count;
} igmp_group_t;

/* ─── IGMP snooping table ────────────────────────────────────── */
typedef struct {
    igmp_group_t groups[IGMP_MAX_GROUPS];
    int          n_groups;
    int          enabled;
    uint32_t     member_timeout;
    uint64_t     total_reports;
    uint64_t     total_leaves;
    uint64_t     total_queries;
} igmp_table_t;

/* ─── API ────────────────────────────────────────────────────── */
void  igmp_init(igmp_table_t *tbl);

/* Process an IGMP frame received on port/vlan */
void  igmp_process(igmp_table_t *tbl, uint16_t vlan,
                    const char *port, uint8_t type,
                    uint32_t group_addr);

/* Is this port in the group? Used to decide flood vs selective fwd */
int   igmp_port_in_group(const igmp_table_t *tbl,
                          uint32_t group, uint16_t vlan,
                          const char *port);

/* Age sweep - remove timed-out members */
int   igmp_age_sweep(igmp_table_t *tbl);

/* Helpers */
void  igmp_group_str(uint32_t group, char *buf, size_t sz);
igmp_group_t *igmp_group_find(igmp_table_t *tbl,
                               uint32_t group, uint16_t vlan);

#endif /* IGMP_H */
