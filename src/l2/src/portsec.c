#include "portsec.h"
#include <string.h>
#include <time.h>
#include <errno.h>

const char *portsec_viol_str(portsec_violation_t v) {
    switch(v) {
    case PORTSEC_VIOL_DROP:     return "drop";
    case PORTSEC_VIOL_RESTRICT: return "restrict";
    case PORTSEC_VIOL_SHUTDOWN: return "shutdown";
    default:                    return "unknown";
    }
}

void portsec_init(portsec_table_t *ps) { memset(ps, 0, sizeof(*ps)); }

portsec_port_t *portsec_port_get(portsec_table_t *ps, const char *port) {
    for (int i = 0; i < ps->n_ports; i++)
        if (strncmp(ps->ports[i].name, port, FDB_IFNAME_LEN) == 0)
            return &ps->ports[i];
    return NULL;
}

portsec_port_t *portsec_port_add(portsec_table_t *ps, const char *port) {
    portsec_port_t *p = portsec_port_get(ps, port);
    if (p) return p;
    if (ps->n_ports >= PORTSEC_MAX_PORTS) return NULL;
    p = &ps->ports[ps->n_ports++];
    memset(p, 0, sizeof(*p));
    strncpy(p->name, port, FDB_IFNAME_LEN-1);
    p->max_macs = 1;
    p->violation = PORTSEC_VIOL_DROP;
    return p;
}

int portsec_configure(portsec_table_t *ps, const char *port,
                       uint32_t max_macs, portsec_violation_t viol) {
    portsec_port_t *p = portsec_port_add(ps, port);
    if (!p) return -ENOMEM;
    p->max_macs  = max_macs;
    p->violation = viol;
    p->enabled   = 1;
    return 0;
}

int portsec_check(portsec_table_t *ps, const char *port,
                   const uint8_t mac[6], uint16_t vlan) {
    portsec_port_t *p = portsec_port_get(ps, port);
    if (!p || !p->enabled || p->err_disabled) return -1;

    /* already known? */
    for (int i = 0; i < p->n_learned; i++)
        if (memcmp(p->macs[i].mac, mac, 6) == 0 &&
            p->macs[i].vlan == vlan) return 0;

    /* room for new MAC? */
    if ((uint32_t)p->n_learned < p->max_macs &&
        p->n_learned < PORTSEC_MAX_MACS_PORT) {
        memcpy(p->macs[p->n_learned].mac, mac, 6);
        p->macs[p->n_learned].vlan   = vlan;
        p->macs[p->n_learned].sticky = 0;
        p->n_learned++;
        return 0;
    }

    /* violation */
    p->viol_count++;
    p->viol_last = (uint64_t)time(NULL);
    ps->total_violations++;
    if (p->violation == PORTSEC_VIOL_SHUTDOWN)
        p->err_disabled = 1;
    return -1;
}

int portsec_make_sticky(portsec_table_t *ps, const char *port,
                         const uint8_t mac[6], uint16_t vlan) {
    portsec_port_t *p = portsec_port_get(ps, port);
    if (!p) return -ENOENT;
    for (int i = 0; i < p->n_learned; i++)
        if (memcmp(p->macs[i].mac, mac, 6) == 0 &&
            p->macs[i].vlan == vlan) {
            p->macs[i].sticky = 1;
            return 0;
        }
    return -ENOENT;
}

void portsec_clear_dynamic(portsec_table_t *ps, const char *port) {
    portsec_port_t *p = portsec_port_get(ps, port);
    if (!p) return;
    int w = 0;
    for (int i = 0; i < p->n_learned; i++)
        if (p->macs[i].sticky) p->macs[w++] = p->macs[i];
    p->n_learned = w;
}

void portsec_errdisable_recover(portsec_table_t *ps, const char *port) {
    portsec_port_t *p = portsec_port_get(ps, port);
    if (p) { p->err_disabled = 0; p->viol_count = 0; }
}
