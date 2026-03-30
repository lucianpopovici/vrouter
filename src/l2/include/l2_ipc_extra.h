#ifndef L2_IPC_EXTRA_H
#define L2_IPC_EXTRA_H

#include "vlan.h"
#include "portsec.h"
#include "storm.h"
#include "igmp.h"
#include "arpsnoop.h"
#include "lacp.h"

/* Default socket basenames */
#define VLAN_SOCK_NAME     "vlan.sock"
#define PORTSEC_SOCK_NAME  "portsec.sock"
#define STORM_SOCK_NAME    "storm.sock"
#define IGMP_SOCK_NAME     "igmp.sock"
#define ARP_SOCK_NAME      "arp.sock"
#define LACP_SOCK_NAME     "lacp.sock"

/* Runtime paths (filled in at startup from sock_dir) */
typedef struct {
    char vlan[256];
    char portsec[256];
    char storm[256];
    char igmp[256];
    char arp[256];
    char lacp[256];
} l2_extra_paths_t;

int l2_extra_serve(vlan_db_t *vlan, portsec_table_t *ps,
                    storm_table_t *storm, igmp_table_t *igmp,
                    arpsnoop_table_t *arp, lacp_table_t *lacp,
                    const l2_extra_paths_t *paths,
                    volatile int *running);

#endif
