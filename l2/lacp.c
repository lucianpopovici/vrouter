#include "lacp.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

const char *lacp_mode_str(lacp_mode_t m) {
    switch(m) {
    case LACP_MODE_OFF:     return "off";
    case LACP_MODE_PASSIVE: return "passive";
    case LACP_MODE_ACTIVE:  return "active";
    case LACP_MODE_STATIC:  return "static";
    default:                return "unknown";
    }
}
const char *lacp_mstate_str(lacp_mstate_t s) {
    switch(s) {
    case LACP_MBR_DETACHED:     return "detached";
    case LACP_MBR_WAITING:      return "waiting";
    case LACP_MBR_ATTACHED:     return "attached";
    case LACP_MBR_COLLECTING:   return "collecting";
    case LACP_MBR_DISTRIBUTING: return "distributing";
    default:                     return "unknown";
    }
}

void lacp_init(lacp_table_t *lt, const uint8_t sys_mac[6]) {
    memset(lt, 0, sizeof(*lt));
    lt->system.priority = 32768;
    memcpy(lt->system.mac, sys_mac, 6);
}

lacp_lag_t *lacp_lag_find(lacp_table_t *lt, const char *name) {
    for (int i = 0; i < lt->n_lags; i++)
        if (lt->lags[i].active &&
            strncmp(lt->lags[i].name, name, FDB_IFNAME_LEN) == 0)
            return &lt->lags[i];
    return NULL;
}

lacp_lag_t *lacp_lag_add(lacp_table_t *lt, const char *name, uint16_t key) {
    lacp_lag_t *l = lacp_lag_find(lt, name);
    if (l) return l;
    if (lt->n_lags >= LACP_MAX_LAGS) return NULL;
    l = &lt->lags[lt->n_lags++];
    memset(l, 0, sizeof(*l));
    strncpy(l->name, name, FDB_IFNAME_LEN-1);
    l->key    = key;
    l->system = lt->system;
    l->active = 1;
    return l;
}

int lacp_lag_del(lacp_table_t *lt, const char *name) {
    for (int i = 0; i < lt->n_lags; i++) {
        if (lt->lags[i].active &&
            strncmp(lt->lags[i].name, name, FDB_IFNAME_LEN) == 0) {
            lt->lags[i].active = 0;
            return 0;
        }
    }
    return -ENOENT;
}

lacp_member_t *lacp_member_find(lacp_lag_t *lag, const char *port) {
    for (int i = 0; i < lag->n_members; i++)
        if (strncmp(lag->members[i].port, port, FDB_IFNAME_LEN) == 0)
            return &lag->members[i];
    return NULL;
}

lacp_member_t *lacp_member_add(lacp_lag_t *lag, const char *port,
                                 lacp_mode_t mode) {
    lacp_member_t *m = lacp_member_find(lag, port);
    if (m) return m;
    if (lag->n_members >= LACP_MAX_MEMBERS) return NULL;
    m = &lag->members[lag->n_members];
    memset(m, 0, sizeof(*m));
    strncpy(m->port, port, FDB_IFNAME_LEN-1);
    m->mode         = mode;
    m->actor_key    = lag->key;
    m->actor_port.number   = (uint16_t)(lag->n_members + 1);
    m->actor_port.priority = 128;
    m->mux_state    = LACP_MBR_DETACHED;
    m->enabled      = 1;
    m->fast_timer   = 1;

    /* static mode: immediately distributing */
    if (mode == LACP_MODE_STATIC) {
        m->mux_state = LACP_MBR_DISTRIBUTING;
        m->selected  = 1;
        lag->n_active++;
    } else {
        m->pdu_timer    = LACP_FAST_TIMER;
        m->expire_timer = LACP_SHORT_TIMEOUT;
        m->actor_state  = LACP_ST_ACTIVITY | LACP_ST_AGGREGATION |
                          LACP_ST_TIMEOUT;
    }
    lag->n_members++;
    return m;
}

int lacp_member_del(lacp_lag_t *lag, const char *port) {
    for (int i = 0; i < lag->n_members; i++) {
        if (strncmp(lag->members[i].port, port, FDB_IFNAME_LEN) == 0) {
            if (lag->members[i].mux_state == LACP_MBR_DISTRIBUTING &&
                lag->n_active > 0) lag->n_active--;
            lag->members[i] = lag->members[--lag->n_members];
            return 0;
        }
    }
    return -ENOENT;
}

/* ─── MUX state machine ──────────────────────────────────────── */
static void mux_advance(lacp_lag_t *lag, lacp_member_t *m) {
    switch (m->mux_state) {
    case LACP_MBR_DETACHED:
        if (m->selected) {
            m->mux_state = LACP_MBR_WAITING;
        }
        break;
    case LACP_MBR_WAITING:
        /* simplified: go to attached immediately if selected */
        if (m->selected) {
            m->mux_state   = LACP_MBR_ATTACHED;
            m->actor_state |= LACP_ST_SYNC;
        }
        break;
    case LACP_MBR_ATTACHED:
        /* partner in sync → collecting */
        if (m->partner_state & LACP_ST_SYNC) {
            m->mux_state    = LACP_MBR_COLLECTING;
            m->actor_state |= LACP_ST_COLLECTING;
        }
        break;
    case LACP_MBR_COLLECTING:
        /* partner collecting → distributing */
        if (m->partner_state & LACP_ST_COLLECTING) {
            m->mux_state    = LACP_MBR_DISTRIBUTING;
            m->actor_state |= LACP_ST_DISTRIBUTING;
            lag->n_active++;
        }
        break;
    case LACP_MBR_DISTRIBUTING:
        /* de-select */
        if (!m->selected) {
            m->mux_state    = LACP_MBR_ATTACHED;
            m->actor_state &= (uint8_t)~(LACP_ST_DISTRIBUTING |
                                          LACP_ST_COLLECTING);
            if (lag->n_active > 0) lag->n_active--;
        }
        break;
    }
}

/* ─── Receive LACPDU ─────────────────────────────────────────── */
void lacp_receive(lacp_table_t *lt, lacp_lag_t *lag,
                   lacp_member_t *m, const lacp_pdu_t *pdu) {
    (void)lt;
    m->pdu_rx++;
    m->partner_sys   = pdu->actor_sys;
    m->partner_port  = pdu->actor_port;
    m->partner_key   = pdu->actor_key;
    m->partner_state = pdu->actor_state;

    /* reset expire timer */
    m->expire_timer = (m->fast_timer) ? LACP_SHORT_TIMEOUT
                                      : LACP_LONG_TIMEOUT;
    m->actor_state &= (uint8_t)~(LACP_ST_DEFAULTED | LACP_ST_EXPIRED);

    /* select if partner is aggregatable and keys match */
    m->selected = (pdu->actor_state & LACP_ST_AGGREGATION) ? 0 : 1;
    if (pdu->actor_key != lag->key) m->selected = 0;

    mux_advance(lag, m);
}

/* ─── Tick ───────────────────────────────────────────────────── */
void lacp_tick(lacp_table_t *lt) {
    for (int i = 0; i < lt->n_lags; i++) {
        lacp_lag_t *lag = &lt->lags[i];
        if (!lag->active) continue;
        for (int j = 0; j < lag->n_members; j++) {
            lacp_member_t *m = &lag->members[j];
            if (!m->enabled || m->mode == LACP_MODE_STATIC) continue;

            /* PDU transmit timer */
            if (m->mode == LACP_MODE_ACTIVE && --m->pdu_timer <= 0) {
                m->pdu_tx++;
                m->pdu_timer = m->fast_timer ? LACP_FAST_TIMER
                                             : LACP_SLOW_TIMER;
            }

            /* partner expire timer */
            if (m->expire_timer > 0 && --m->expire_timer == 0) {
                /* partner timed out */
                m->actor_state |= LACP_ST_EXPIRED;
                m->selected     = 0;
                if (m->mux_state == LACP_MBR_DISTRIBUTING &&
                    lag->n_active > 0) lag->n_active--;
                m->mux_state = LACP_MBR_DETACHED;
            }

            mux_advance(lag, m);
        }
    }
}

/* ─── Build outgoing LACPDU ──────────────────────────────────── */
void lacp_build_pdu(const lacp_lag_t *lag,
                     const lacp_member_t *m, lacp_pdu_t *out) {
    memset(out, 0, sizeof(*out));
    out->subtype     = 1;
    out->version     = 1;
    out->actor_tag   = 1;
    out->actor_len   = 20;
    out->actor_sys   = lag->system;
    out->actor_key   = lag->key;
    out->actor_port  = m->actor_port;
    out->actor_state = m->actor_state;
    out->partner_tag = 2;
    out->partner_len = 20;
    out->partner_sys   = m->partner_sys;
    out->partner_key   = m->partner_key;
    out->partner_port  = m->partner_port;
    out->partner_state = m->partner_state;
}

/* ─── TX hash (XOR-based, like Linux bonding xmit_hash_policy=0) */
int lacp_select_member(const lacp_lag_t *lag,
                        const uint8_t src_mac[6],
                        const uint8_t dst_mac[6]) {
    if (lag->n_active == 0) return -1;
    uint32_t h = 0;
    for (int i = 0; i < 6; i++) h ^= ((uint32_t)src_mac[i] ^ dst_mac[i]);
    /* collect active members */
    int active[LACP_MAX_MEMBERS], na = 0;
    for (int i = 0; i < lag->n_members; i++)
        if (lag->members[i].mux_state == LACP_MBR_DISTRIBUTING)
            active[na++] = i;
    if (na == 0) return -1;
    return active[h % (uint32_t)na];
}
