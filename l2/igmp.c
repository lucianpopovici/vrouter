#include "igmp.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>

void igmp_init(igmp_table_t *tbl) {
    memset(tbl, 0, sizeof(*tbl));
    tbl->enabled        = 1;
    tbl->member_timeout = IGMP_MEMBER_TIMEOUT;
}

void igmp_group_str(uint32_t group, char *buf, size_t sz) {
    struct in_addr a = { htonl(group) };
    inet_ntop(AF_INET, &a, buf, (socklen_t)sz);
}

igmp_group_t *igmp_group_find(igmp_table_t *tbl,
                               uint32_t group, uint16_t vlan) {
    for (int i = 0; i < tbl->n_groups; i++)
        if (tbl->groups[i].active &&
            tbl->groups[i].group == group &&
            tbl->groups[i].vlan  == vlan)
            return &tbl->groups[i];
    return NULL;
}

static igmp_group_t *group_get_or_create(igmp_table_t *tbl,
                                          uint32_t group, uint16_t vlan) {
    igmp_group_t *g = igmp_group_find(tbl, group, vlan);
    if (g) return g;
    if (tbl->n_groups >= IGMP_MAX_GROUPS) return NULL;
    g = &tbl->groups[tbl->n_groups++];
    memset(g, 0, sizeof(*g));
    g->group  = group;
    g->vlan   = vlan;
    g->active = 1;
    return g;
}

static void add_member(igmp_group_t *g, const char *port, uint8_t ver) {
    time_t now = time(NULL);
    /* refresh existing */
    for (int i = 0; i < g->n_members; i++) {
        if (strncmp(g->members[i].port, port, FDB_IFNAME_LEN) == 0) {
            g->members[i].last_seen = now;
            g->members[i].version   = ver;
            return;
        }
    }
    if (g->n_members >= IGMP_MAX_PORTS_GRP) return;
    strncpy(g->members[g->n_members].port, port, FDB_IFNAME_LEN-1);
    g->members[g->n_members].last_seen = now;
    g->members[g->n_members].version   = ver;
    g->n_members++;
}

static void remove_member(igmp_group_t *g, const char *port) {
    for (int i = 0; i < g->n_members; i++) {
        if (strncmp(g->members[i].port, port, FDB_IFNAME_LEN) == 0) {
            g->members[i] = g->members[--g->n_members];
            return;
        }
    }
}

void igmp_process(igmp_table_t *tbl, uint16_t vlan,
                   const char *port, uint8_t type, uint32_t group_addr) {
    if (!tbl->enabled) return;

    switch (type) {
    case IGMP_MEMBERSHIP_QUERY:
        tbl->total_queries++;
        /* track querier port per group/vlan */
        if (group_addr) {
            igmp_group_t *g = igmp_group_find(tbl, group_addr, vlan);
            if (g) strncpy(g->querier_port, port, FDB_IFNAME_LEN-1);
        }
        break;

    case IGMP_V1_MEMBERSHIP_RPT:
    case IGMP_V2_MEMBERSHIP_RPT:
    case IGMP_V3_MEMBERSHIP_RPT: {
        tbl->total_reports++;
        igmp_group_t *g = group_get_or_create(tbl, group_addr, vlan);
        if (!g) break;
        uint8_t ver = (type == IGMP_V1_MEMBERSHIP_RPT) ? 1 :
                      (type == IGMP_V3_MEMBERSHIP_RPT) ? 3 : 2;
        add_member(g, port, ver);
        g->report_count++;
        break;
    }

    case IGMP_V2_LEAVE_GROUP: {
        tbl->total_leaves++;
        igmp_group_t *g = igmp_group_find(tbl, group_addr, vlan);
        if (!g) break;
        remove_member(g, port);
        g->leave_count++;
        /* deactivate if no members left */
        if (g->n_members == 0) g->active = 0;
        break;
    }
    }
}

int igmp_port_in_group(const igmp_table_t *tbl,
                        uint32_t group, uint16_t vlan,
                        const char *port) {
    const igmp_group_t *g = igmp_group_find((igmp_table_t*)tbl, group, vlan);
    if (!g) return 0;
    for (int i = 0; i < g->n_members; i++)
        if (strncmp(g->members[i].port, port, FDB_IFNAME_LEN) == 0)
            return 1;
    return 0;
}

int igmp_age_sweep(igmp_table_t *tbl) {
    time_t now = time(NULL);
    int removed = 0;
    for (int i = 0; i < tbl->n_groups; i++) {
        igmp_group_t *g = &tbl->groups[i];
        if (!g->active) continue;
        /* remove timed-out members */
        int w = 0;
        for (int j = 0; j < g->n_members; j++) {
            if ((now - g->members[j].last_seen) <
                (time_t)tbl->member_timeout)
                g->members[w++] = g->members[j];
            else removed++;
        }
        g->n_members = w;
        if (w == 0) g->active = 0;
    }
    return removed;
}
