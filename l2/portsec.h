#ifndef PORTSEC_H
#define PORTSEC_H

#include <stdint.h>
#include "fdb.h"

#define PORTSEC_MAX_PORTS      256
#define PORTSEC_MAX_MACS_PORT  128  /* hard ceiling per port       */

typedef enum {
    PORTSEC_VIOL_DROP     = 0,  /* silently drop offending frame  */
    PORTSEC_VIOL_RESTRICT = 1,  /* drop + increment counter       */
    PORTSEC_VIOL_SHUTDOWN = 2,  /* err-disable the port           */
} portsec_violation_t;

typedef struct {
    char     mac[6];
    uint16_t vlan;
    int      sticky;   /* survives topology change, saved as static */
} portsec_mac_t;

typedef struct {
    char                name[FDB_IFNAME_LEN];
    int                 enabled;
    int                 err_disabled;
    uint32_t            max_macs;          /* 0 = disabled          */
    portsec_violation_t violation;
    int                 n_learned;
    portsec_mac_t       macs[PORTSEC_MAX_MACS_PORT];
    uint64_t            viol_count;
    uint64_t            viol_last;         /* unix time             */
} portsec_port_t;

typedef struct {
    portsec_port_t ports[PORTSEC_MAX_PORTS];
    int            n_ports;
    uint64_t       total_violations;
} portsec_table_t;

void  portsec_init(portsec_table_t *ps);

portsec_port_t *portsec_port_get(portsec_table_t *ps, const char *port);
portsec_port_t *portsec_port_add(portsec_table_t *ps, const char *port);

/* Configure a port */
int   portsec_configure(portsec_table_t *ps, const char *port,
                         uint32_t max_macs, portsec_violation_t viol);

/* Check/learn a new MAC on arrival; returns 0=permit, -1=violate */
int   portsec_check(portsec_table_t *ps, const char *port,
                     const uint8_t mac[6], uint16_t vlan);

/* Promote a dynamic entry to sticky */
int   portsec_make_sticky(portsec_table_t *ps, const char *port,
                           const uint8_t mac[6], uint16_t vlan);

/* Clear learned MACs on a port (on link-down) */
void  portsec_clear_dynamic(portsec_table_t *ps, const char *port);
void  portsec_errdisable_recover(portsec_table_t *ps, const char *port);

const char *portsec_viol_str(portsec_violation_t v);

#endif /* PORTSEC_H */
