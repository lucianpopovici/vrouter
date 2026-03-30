#include "l2_persist.h"
#include "lacp.h"
#include "../l3/json_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


/* ═══════════════════════════════════════════════════════════════
 * DUMP
 * ═══════════════════════════════════════════════════════════════ */
int l2_persist_dump(const fdb_table_t  *fdb,
                     const vlan_db_t    *vlan,
                     const stp_bridge_t *br,
                     const lacp_table_t *lacp,
                     const char         *path)
{
    if (!path) path = L2_DUMP_FILE;

    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -errno;

    int written = 0;

    /* ── FDB: only static and EVPN entries survive restart ──── */
    for (int b = 0; b < FDB_BUCKETS; b++) {
        const fdb_entry_t *e = fdb->buckets[b];
        while (e) {
            if (e->flags & (FDB_FLAG_STATIC | FDB_FLAG_EVPN)) {
                char ms[24]; fdb_mac_str(e->mac, ms, sizeof(ms));
                fprintf(f,
                    "{\"type\":\"fdb\","
                    "\"mac\":\"%s\",\"vlan\":%u,"
                    "\"port\":\"%s\",\"flags\":%u}\n",
                    ms, e->vlan, e->port, e->flags);
                written++;
            }
            e = e->next;
        }
    }

    /* ── VLAN database ──────────────────────────────────────── */
    for (int v = 2; v <= VLAN_MAX; v++) {   /* skip VLAN 1 (always exists) */
        if (!vlan->vlans[v].active) continue;
        fprintf(f,
            "{\"type\":\"vlan\","
            "\"vid\":%u,\"name\":\"%s\"}\n",
            vlan->vlans[v].vid, vlan->vlans[v].name);
        written++;
    }

    /* ── VLAN port configs ──────────────────────────────────── */
    for (int i = 0; i < vlan->n_ports; i++) {
        const vlan_port_t *p = &vlan->ports[i];
        if (!p->in_use) continue;
        fprintf(f,
            "{\"type\":\"vlan_port\","
            "\"port\":\"%s\",\"mode\":\"%s\",\"pvid\":%u}\n",
            p->name, vlan_mode_str(p->mode), p->pvid);
        written++;
    }

    /* ── STP bridge config ──────────────────────────────────── */
    fprintf(f,
        "{\"type\":\"stp\","
        "\"priority\":%u,"
        "\"hello\":%u,"
        "\"max_age\":%u,"
        "\"fwd_delay\":%u,"
        "\"mode\":\"%s\","
        "\"mst_region\":\"%s\","
        "\"mst_revision\":%u}\n",
        br->bridge_id.priority,
        br->hello_time, br->max_age, br->fwd_delay,
        stp_mode_str(br->mode),
        br->mst_region, br->mst_revision);
    written++;

    /* ── LACP LAGs and members ──────────────────────────────── */
    for (int i = 0; i < lacp->n_lags; i++) {
        const lacp_lag_t *lag = &lacp->lags[i];
        if (!lag->active) continue;
        fprintf(f,
            "{\"type\":\"lacp_lag\","
            "\"lag\":\"%s\",\"key\":%u}\n",
            lag->name, lag->key);
        written++;
        for (int j = 0; j < lag->n_members; j++) {
            const lacp_member_t *m = &lag->members[j];
            fprintf(f,
                "{\"type\":\"lacp_member\","
                "\"lag\":\"%s\",\"port\":\"%s\",\"mode\":\"%s\"}\n",
                lag->name, m->port, lacp_mode_str(m->mode));
            written++;
        }
    }

    fclose(f);
    if (rename(tmp, path) != 0) {
        int err = errno; remove(tmp); return -err;
    }
    fprintf(stderr, "[l2_persist] dumped %d objects to %s\n", written, path);
    return written;
}

/* ═══════════════════════════════════════════════════════════════
 * RESTORE
 * ═══════════════════════════════════════════════════════════════ */
int l2_persist_restore(fdb_table_t   *fdb,
                        vlan_db_t     *vlan,
                        stp_bridge_t  *br,
                        lacp_table_t  *lacp,
                        const char    *path)
{
    if (!path) path = L2_DUMP_FILE;

    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 0;
        return -errno;
    }

    char line[512];
    int  restored = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t ln = strlen(line);
        while (ln > 0 && (line[ln-1]=='\n'||line[ln-1]=='\r')) line[--ln]='\0';
        if (!ln || line[0] != '{') continue;

        char type[20]={0};
        if (jget(line, "type", type, sizeof(type)) != 0) continue;

        /* ── FDB entry ──────────────────────────────────────── */
        if (strcmp(type, "fdb") == 0) {
            char mac_s[24]={0}, port[16]={0}, vlan_s[8]={0}, flags_s[12]={0};
            jget(line,"mac",  mac_s,  sizeof(mac_s));
            jget(line,"port", port,   sizeof(port));
            jget(line,"vlan", vlan_s, sizeof(vlan_s));
            jget(line,"flags",flags_s,sizeof(flags_s));
            if (!mac_s[0] || !port[0]) continue;
            uint8_t  mac[6]; fdb_mac_parse(mac_s, mac);
            uint16_t v   = vlan_s[0]  ? (uint16_t)atoi(vlan_s)  : 1;
            uint32_t flg = flags_s[0] ? (uint32_t)atoi(flags_s) : FDB_FLAG_STATIC;
            fdb_learn(fdb, mac, v, port, flg, 0);
            restored++;

        /* ── VLAN entry ─────────────────────────────────────── */
        } else if (strcmp(type, "vlan") == 0) {
            char vid_s[8]={0}, name[VLAN_NAME_LEN]={0};
            jget(line,"vid", vid_s,sizeof(vid_s));
            jget(line,"name",name, sizeof(name));
            if (vid_s[0]) { vlan_add(vlan,(uint16_t)atoi(vid_s),name); restored++; }

        /* ── VLAN port config ───────────────────────────────── */
        } else if (strcmp(type, "vlan_port") == 0) {
            char port[16]={0}, mode_s[12]={0}, pvid_s[8]={0};
            jget(line,"port", port,  sizeof(port));
            jget(line,"mode", mode_s,sizeof(mode_s));
            jget(line,"pvid", pvid_s,sizeof(pvid_s));
            if (!port[0]) continue;
            vlan_port_mode_t mode = VLAN_PORT_ACCESS;
            if (strcmp(mode_s,"trunk" )==0) mode=VLAN_PORT_TRUNK;
            if (strcmp(mode_s,"hybrid")==0) mode=VLAN_PORT_HYBRID;
            uint16_t pvid = pvid_s[0] ? (uint16_t)atoi(pvid_s) : 1;
            vlan_port_set_mode(vlan, port, mode, pvid);
            restored++;

        /* ── STP config ─────────────────────────────────────── */
        } else if (strcmp(type, "stp") == 0) {
            char prio_s[8]={0}, hello_s[8]={0}, age_s[8]={0};
            char delay_s[8]={0}, mode_s[8]={0}, region[32]={0}, rev_s[8]={0};
            jget(line,"priority",  prio_s, sizeof(prio_s));
            jget(line,"hello",     hello_s,sizeof(hello_s));
            jget(line,"max_age",   age_s,  sizeof(age_s));
            jget(line,"fwd_delay", delay_s,sizeof(delay_s));
            jget(line,"mode",      mode_s, sizeof(mode_s));
            jget(line,"mst_region",region, sizeof(region));
            jget(line,"mst_revision",rev_s,sizeof(rev_s));
            if (prio_s[0])  br->bridge_id.priority = (uint16_t)atoi(prio_s);
            if (hello_s[0]) br->hello_time  = (uint16_t)atoi(hello_s);
            if (age_s[0])   br->max_age     = (uint16_t)atoi(age_s);
            if (delay_s[0]) br->fwd_delay   = (uint16_t)atoi(delay_s);
            if (region[0])  snprintf(br->mst_region, sizeof(br->mst_region), "%s", region);
            if (rev_s[0])   br->mst_revision = (uint32_t)atoi(rev_s);
            if (mode_s[0]) {
                if      (strcmp(mode_s,"stp" )==0) br->mode=STP_MODE_STP;
                else if (strcmp(mode_s,"rstp")==0) br->mode=STP_MODE_RSTP;
                else if (strcmp(mode_s,"mst" )==0) br->mode=STP_MODE_MST;
            }
            restored++;

        /* ── LACP LAG ───────────────────────────────────────── */
        } else if (strcmp(type, "lacp_lag") == 0) {
            char lag_s[16]={0}, key_s[8]={0};
            jget(line,"lag",lag_s,sizeof(lag_s));
            jget(line,"key",key_s,sizeof(key_s));
            if (!lag_s[0]) continue;
            uint16_t key = key_s[0] ? (uint16_t)atoi(key_s) : 1;
            lacp_lag_add(lacp, lag_s, key);
            restored++;

        /* ── LACP member ────────────────────────────────────── */
        } else if (strcmp(type, "lacp_member") == 0) {
            char lag_s[16]={0}, port[16]={0}, mode_s[12]={0};
            jget(line,"lag", lag_s, sizeof(lag_s));
            jget(line,"port",port,  sizeof(port));
            jget(line,"mode",mode_s,sizeof(mode_s));
            if (!lag_s[0] || !port[0]) continue;
            lacp_lag_t *lag = lacp_lag_find(lacp, lag_s);
            if (!lag) continue;
            lacp_mode_t mode = LACP_MODE_ACTIVE;
            if (strcmp(mode_s,"passive")==0) mode=LACP_MODE_PASSIVE;
            if (strcmp(mode_s,"static" )==0) mode=LACP_MODE_STATIC;
            lacp_member_add(lag, port, mode);
            restored++;
        }
    }

    fclose(f);
    fprintf(stderr, "[l2_persist] restored %d objects from %s\n", restored, path);
    return restored;
}
