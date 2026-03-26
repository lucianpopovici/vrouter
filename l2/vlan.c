#include "vlan.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>

const char *vlan_mode_str(vlan_port_mode_t m) {
    switch(m) {
    case VLAN_PORT_ACCESS: return "access";
    case VLAN_PORT_TRUNK:  return "trunk";
    case VLAN_PORT_HYBRID: return "hybrid";
    default:               return "unknown";
    }
}

void vlan_db_init(vlan_db_t *db) {
    memset(db, 0, sizeof(*db));
    /* VLAN 1 always exists */
    db->vlans[1].vid    = 1;
    db->vlans[1].active = 1;
    strncpy(db->vlans[1].name, "default", VLAN_NAME_LEN-1);
    db->vlan_count = 1;
}

int vlan_add(vlan_db_t *db, uint16_t vid, const char *name) {
    if (vid < 1 || vid > VLAN_MAX) return -EINVAL;
    if (db->vlans[vid].active)     return 0;  /* already exists */
    db->vlans[vid].vid    = vid;
    db->vlans[vid].active = 1;
    if (name && name[0])
        strncpy(db->vlans[vid].name, name, VLAN_NAME_LEN-1);
    else
        snprintf(db->vlans[vid].name, VLAN_NAME_LEN, "vlan%u", vid);
    db->vlan_count++;
    return 0;
}

int vlan_del(vlan_db_t *db, uint16_t vid) {
    if (vid < 1 || vid > VLAN_MAX) return -EINVAL;
    if (vid == 1) return -EPERM;   /* VLAN 1 undeletable */
    if (!db->vlans[vid].active)    return -ENOENT;
    memset(&db->vlans[vid], 0, sizeof(vlan_entry_t));
    db->vlan_count--;
    return 0;
}

vlan_entry_t *vlan_find(vlan_db_t *db, uint16_t vid) {
    if (vid < 1 || vid > VLAN_MAX) return NULL;
    return db->vlans[vid].active ? &db->vlans[vid] : NULL;
}

vlan_port_t *vlan_port_get(vlan_db_t *db, const char *port) {
    for (int i = 0; i < db->n_ports; i++)
        if (strncmp(db->ports[i].name, port, FDB_IFNAME_LEN) == 0)
            return &db->ports[i];
    return NULL;
}

vlan_port_t *vlan_port_add(vlan_db_t *db, const char *port) {
    vlan_port_t *p = vlan_port_get(db, port);
    if (p) return p;
    if (db->n_ports >= VLAN_MAX_PORTS) return NULL;
    p = &db->ports[db->n_ports++];
    memset(p, 0, sizeof(*p));
    strncpy(p->name, port, FDB_IFNAME_LEN-1);
    p->mode   = VLAN_PORT_ACCESS;
    p->pvid   = 1;
    p->in_use = 1;
    vlan_bmp_set(p->allowed, 1);   /* allow VLAN 1 by default */
    return p;
}

int vlan_port_set_mode(vlan_db_t *db, const char *port,
                        vlan_port_mode_t mode, uint16_t pvid) {
    vlan_port_t *p = vlan_port_add(db, port);
    if (!p) return -ENOMEM;
    p->mode = mode;
    if (pvid >= 1 && pvid <= VLAN_MAX) p->pvid = pvid;
    /* trunk default: allow all VLANs that exist in DB */
    if (mode == VLAN_PORT_TRUNK) {
        memset(p->allowed, 0, sizeof(p->allowed));
        for (int v = 1; v <= VLAN_MAX; v++)
            if (db->vlans[v].active) vlan_bmp_set(p->allowed, (uint16_t)v);
    }
    return 0;
}

int vlan_port_allow(vlan_db_t *db, const char *port,
                     uint16_t lo, uint16_t hi) {
    vlan_port_t *p = vlan_port_add(db, port);
    if (!p) return -ENOMEM;
    for (uint16_t v = lo; v <= hi; v++) vlan_bmp_set(p->allowed, v);
    return 0;
}

int vlan_port_deny(vlan_db_t *db, const char *port,
                    uint16_t lo, uint16_t hi) {
    vlan_port_t *p = vlan_port_get(db, port);
    if (!p) return -ENOENT;
    for (uint16_t v = lo; v <= hi; v++) vlan_bmp_clr(p->allowed, v);
    return 0;
}

int vlan_port_admits(const vlan_db_t *db, const char *port, uint16_t vid) {
    const vlan_port_t *p = vlan_port_get((vlan_db_t*)db, port);
    if (!p) return 1;   /* unknown port: permissive */
    return vlan_bmp_test(p->allowed, vid);
}
