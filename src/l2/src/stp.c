#include "stp.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ─── String tables ──────────────────────────────────────────── */
const char *stp_state_str(stp_port_state_t s) {
    switch (s) {
    case STP_PS_DISABLED:   return "disabled";
    case STP_PS_BLOCKING:   return "blocking";
    case STP_PS_LISTENING:  return "listening";
    case STP_PS_LEARNING:   return "learning";
    case STP_PS_FORWARDING: return "forwarding";
    case STP_PS_DISCARDING: return "discarding";
    default:                return "unknown";
    }
}
const char *stp_role_str(stp_port_role_t r) {
    switch (r) {
    case STP_PR_DISABLED:   return "disabled";
    case STP_PR_ROOT:       return "root";
    case STP_PR_DESIGNATED: return "designated";
    case STP_PR_ALTERNATE:  return "alternate";
    case STP_PR_BACKUP:     return "backup";
    case STP_PR_MASTER:     return "master";
    default:                return "unknown";
    }
}
const char *stp_mode_str(stp_mode_t m) {
    switch (m) {
    case STP_MODE_STP:  return "stp";
    case STP_MODE_RSTP: return "rstp";
    case STP_MODE_MST:  return "mst";
    default:            return "unknown";
    }
}
void stp_bridge_id_str(const stp_bridge_id_t *id, char *buf, size_t sz) {
    snprintf(buf, sz, "%04x.%02x%02x%02x%02x%02x%02x",
             id->priority,
             id->mac[0], id->mac[1], id->mac[2],
             id->mac[3], id->mac[4], id->mac[5]);
}

/* ─── Bridge ID comparison ───────────────────────────────────── *
 * Returns <0 if a < b (a is better), 0 if equal, >0 if a > b   */
int stp_bridge_id_cmp(const stp_bridge_id_t *a, const stp_bridge_id_t *b)
{
    if (a->priority != b->priority)
        return (int)a->priority - (int)b->priority;
    return memcmp(a->mac, b->mac, 6);
}

int stp_is_root(const stp_bridge_t *br) {
    return stp_bridge_id_cmp(&br->bridge_id, &br->root_id) == 0;
}

/* ─── Default path cost by speed (802.1D-2004 table) ─────────── */
static uint32_t default_path_cost(uint32_t speed_mbps)
{
    if (speed_mbps >= 10000) return 2;
    if (speed_mbps >= 1000)  return 4;
    if (speed_mbps >= 100)   return 19;
    if (speed_mbps >= 10)    return 100;
    return 200;
}

/* ─── Init ──────────────────────────────────────────────────── */
void stp_init(stp_bridge_t *br, const uint8_t mac[6], stp_mode_t mode)
{
    memset(br, 0, sizeof(*br));
    br->mode              = mode;
    br->bridge_id.priority = 32768;
    memcpy(br->bridge_id.mac, mac, 6);
    br->root_id           = br->bridge_id;   /* assume we are root */
    br->hello_time        = 2;
    br->max_age           = 20;
    br->fwd_delay         = 15;

    /* MST: MSTI 0 (IST) always active */
    if (mode == STP_MODE_MST) {
        br->mstis[0].active = 1;
        br->mstis[0].id     = 0;
        br->mstis[0].bridge_priority = 32768;
        br->mstis[0].regional_root = br->bridge_id;
        /* default: all VLANs in instance 0 */
        for (int v = 1; v <= MST_MAX_VLANS; v++)
            br->mstis[0].vlan_map[v] = 0;
    }
}

/* ─── Port add ───────────────────────────────────────────────── */
int stp_port_add(stp_bridge_t *br, const char *name,
                 uint16_t port_num, uint32_t path_cost)
{
    if (br->n_ports >= STP_MAX_PORTS) return -1;
    stp_port_t *p = &br->ports[br->n_ports++];
    memset(p, 0, sizeof(*p));
    strncpy(p->name, name, sizeof(p->name) - 1);
    p->port_id       = (uint16_t)((128 << 8) | (port_num & 0xFF));
    p->path_cost     = path_cost ? path_cost : default_path_cost(1000);
    p->point_to_point= 1;           /* assume P2P by default       */
    p->state         = STP_PS_DISABLED;
    p->role          = STP_PR_DISABLED;

    /* MST: init per-instance state */
    for (int i = 0; i < MST_MAX_INSTANCES; i++) {
        p->msti[i].state = STP_PS_DISCARDING;
        p->msti[i].role  = STP_PR_DISABLED;
        p->msti[i].path_cost = p->path_cost;
    }
    return 0;
}

stp_port_t *stp_port_find(stp_bridge_t *br, const char *name)
{
    for (int i = 0; i < br->n_ports; i++)
        if (strncmp(br->ports[i].name, name, 16) == 0)
            return &br->ports[i];
    return NULL;
}

/* ─── Best port selection ─────────────────────────────────────── *
 * Find the port with the best path to root (lowest root_path_cost,
 * then bridge_id, then port_id).                                  */
static stp_port_t *best_root_port(stp_bridge_t *br)
{
    stp_port_t *best = NULL;
    for (int i = 0; i < br->n_ports; i++) {
        stp_port_t *p = &br->ports[i];
        if (!p->link_up || p->role == STP_PR_DISABLED) continue;
        if (!best) { best = p; continue; }
        if (p->root_path_cost < best->root_path_cost) { best = p; continue; }
        if (p->root_path_cost == best->root_path_cost) {
            int r = stp_bridge_id_cmp(&p->designated_bridge,
                                      &best->designated_bridge);
            if (r < 0) { best = p; continue; }
            if (r == 0 && p->designated_port < best->designated_port)
                best = p;
        }
    }
    return best;
}

/* ─── Recalculate port roles (STP/RSTP) ─────────────────────── */
void recalculate_roles(stp_bridge_t *br)
{
    /* find best root info across all ports */
    stp_bridge_id_t best_root   = br->bridge_id;
    uint32_t        best_cost   = 0;
    stp_port_t     *root_port   = NULL;

    for (int i = 0; i < br->n_ports; i++) {
        stp_port_t *p = &br->ports[i];
        if (!p->link_up) continue;
        int r = stp_bridge_id_cmp(&p->designated_root, &best_root);
        if (r < 0 ||
            (r == 0 && p->root_path_cost < best_cost)) {
            best_root  = p->designated_root;
            best_cost  = p->root_path_cost;
            root_port  = p;
        }
    }

    br->root_id       = best_root;
    br->root_path_cost= root_port ? root_port->root_path_cost : 0;
    br->root_port_id  = root_port ? root_port->port_id : 0;

    int we_are_root = stp_is_root(br);

    for (int i = 0; i < br->n_ports; i++) {
        stp_port_t *p = &br->ports[i];
        if (!p->link_up) {
            p->role  = STP_PR_DISABLED;
            p->state = STP_PS_DISABLED;
            continue;
        }

        if (root_port && p == root_port) {
            p->role = STP_PR_ROOT;
            continue;
        }

        /* designated? we offer a better path on this segment */
        int is_designated = 0;
        if (we_are_root) {
            is_designated = 1;
        } else {
            int r = stp_bridge_id_cmp(&br->root_id,
                                      &p->designated_root);
            if (r < 0) is_designated = 1;
            else if (r == 0) {
                uint32_t our_cost = br->root_path_cost + p->path_cost;
                if (our_cost < p->root_path_cost) is_designated = 1;
                else if (our_cost == p->root_path_cost) {
                    int s = stp_bridge_id_cmp(&br->bridge_id,
                                              &p->designated_bridge);
                    if (s < 0) is_designated = 1;
                    else if (s == 0 && p->port_id < p->designated_port)
                        is_designated = 1;
                }
            }
        }

        if (is_designated) {
            p->role = STP_PR_DESIGNATED;
        } else {
            /* RSTP: alternate vs backup */
            if (br->mode != STP_MODE_STP) {
                if (stp_bridge_id_cmp(&p->designated_bridge,
                                      &br->bridge_id) == 0)
                    p->role = STP_PR_BACKUP;
                else
                    p->role = STP_PR_ALTERNATE;
            } else {
                p->role = STP_PR_ALTERNATE; /* STP just blocks it */
            }
        }
    }
}

/* ─── Update port state from role ───────────────────────────── */
static void apply_state_from_role(stp_bridge_t *br, stp_port_t *p)
{
    switch (p->role) {
    case STP_PR_ROOT:
    case STP_PR_DESIGNATED:
        if (br->mode == STP_MODE_STP) {
            /* STP: must pass through Listening → Learning → Forwarding */
            if (p->state == STP_PS_DISABLED ||
                p->state == STP_PS_BLOCKING)
                p->state = STP_PS_LISTENING;
            /* transitions driven by forward_delay_timer in tick() */
        } else {
            /* RSTP/MST: rapid transition if P2P edge or agreed */
            if (p->edge || (p->point_to_point && p->agreed))
                p->state = STP_PS_FORWARDING;
            else if (p->state == STP_PS_DISCARDING)
                p->state = STP_PS_LEARNING;
        }
        break;

    case STP_PR_ALTERNATE:
    case STP_PR_BACKUP:
    case STP_PR_DISABLED:
        p->state = (br->mode == STP_MODE_STP)
                 ? STP_PS_BLOCKING : STP_PS_DISCARDING;
        p->agreed    = 0;
        p->proposing = 0;
        break;

    default: break;
    }
}

/* ─── Port up ────────────────────────────────────────────────── */
void stp_port_up(stp_bridge_t *br, stp_port_t *p)
{
    p->link_up = 1;
    p->agreed  = 0;
    p->synced  = 0;

    if (br->mode == STP_MODE_STP) {
        p->state = STP_PS_LISTENING;
        p->forward_delay_timer = br->fwd_delay;
    } else {
        p->state = STP_PS_DISCARDING;
        /* RSTP edge ports go directly to forwarding */
        if (p->edge) p->state = STP_PS_FORWARDING;
    }

    recalculate_roles(br);
    apply_state_from_role(br, p);

    /* If we're root, immediately mark designated */
    if (stp_is_root(br)) {
        p->designated_root   = br->bridge_id;
        p->designated_bridge = br->bridge_id;
        p->root_path_cost    = 0;
        p->designated_port   = p->port_id;
    }
}

/* ─── Port down ──────────────────────────────────────────────── */
void stp_port_down(stp_bridge_t *br, stp_port_t *p)
{
    p->link_up = 0;
    p->state   = STP_PS_DISABLED;
    p->role    = STP_PR_DISABLED;
    p->agreed  = 0;

    /* clear stored info */
    memset(&p->designated_root,   0, sizeof(p->designated_root));
    memset(&p->designated_bridge, 0, sizeof(p->designated_bridge));
    p->root_path_cost = 0;

    recalculate_roles(br);
    for (int i = 0; i < br->n_ports; i++)
        apply_state_from_role(br, &br->ports[i]);
}

/* ─── Receive BPDU ───────────────────────────────────────────── */
void stp_receive_bpdu(stp_bridge_t *br, stp_port_t *p,
                      const stp_bpdu_t *bpdu)
{
    p->bpdu_rx++;
    p->message_age_timer = br->max_age;

    /* Store the superior info from BPDU */
    p->designated_root   = bpdu->root_id;
    p->root_path_cost    = bpdu->root_path_cost + p->path_cost;
    p->designated_bridge = bpdu->bridge_id;
    p->designated_port   = bpdu->port_id;

    /* Topology change handling */
    if (bpdu->flags & BPDU_FL_TC) {
        p->tc_rx++;
        br->tc_count++;
        br->tc_last   = (uint64_t)time(NULL);
        br->tc_active = 1;
    }

    /* ── RSTP proposal/agreement mechanism ───────────────────── */
    if (br->mode != STP_MODE_STP && bpdu->version >= 2) {
        if (bpdu->flags & BPDU_FL_PROPOSAL) {
            /* Superior BPDU with proposal: sync all other ports,
               then send agreement back */
            p->proposed = 1;
            for (int i = 0; i < br->n_ports; i++) {
                stp_port_t *q = &br->ports[i];
                if (q == p) continue;
                if (q->role == STP_PR_DESIGNATED)
                    q->state = (br->mode == STP_MODE_STP)
                             ? STP_PS_BLOCKING : STP_PS_DISCARDING;
            }
            p->agreed   = 1;
            p->proposed = 0;
        }
        if (bpdu->flags & BPDU_FL_AGREEMENT) {
            p->agreed     = 1;
            p->proposing  = 0;
            p->state      = STP_PS_FORWARDING;
        }
    }

    recalculate_roles(br);
    apply_state_from_role(br, p);
}

/* ─── Tick (call every hello_time seconds) ───────────────────── */
void stp_tick(stp_bridge_t *br)
{
    for (int i = 0; i < br->n_ports; i++) {
        stp_port_t *p = &br->ports[i];
        if (!p->link_up) continue;

        /* message age: if superior info expires, we may become root */
        if (p->role == STP_PR_ROOT && p->message_age_timer > 0) {
            if (--p->message_age_timer == 0) {
                /* superior info aged out */
                memset(&p->designated_root, 0, sizeof(p->designated_root));
                p->root_path_cost = 0;
                recalculate_roles(br);
            }
        }

        /* STP forward delay state machine */
        if (br->mode == STP_MODE_STP) {
            if (p->state == STP_PS_LISTENING ||
                p->state == STP_PS_LEARNING) {
                if (p->forward_delay_timer > 0) {
                    if (--p->forward_delay_timer == 0) {
                        if (p->state == STP_PS_LISTENING) {
                            p->state = STP_PS_LEARNING;
                            p->forward_delay_timer = br->fwd_delay;
                        } else {
                            p->state = STP_PS_FORWARDING;
                        }
                    }
                }
            }
        } else {
            /* RSTP: if learning, transition to forwarding after fwd_delay */
            if (p->state == STP_PS_LEARNING && !p->agreed) {
                if (p->forward_delay_timer > 0) {
                    if (--p->forward_delay_timer == 0)
                        p->state = STP_PS_FORWARDING;
                } else {
                    p->forward_delay_timer = br->fwd_delay;
                }
            }
        }

        /* TC while timer */
        if (p->tc_while_timer > 0) {
            if (--p->tc_while_timer == 0)
                br->tc_active = 0;
        }

        p->bpdu_tx++;  /* assume we transmit hello every tick */
    }
}

/* ─── Build outgoing BPDU ────────────────────────────────────── */
void stp_build_bpdu(const stp_bridge_t *br, const stp_port_t *p,
                    stp_bpdu_t *out)
{
    memset(out, 0, sizeof(*out));
    out->proto_id      = 0;
    out->version       = (br->mode == STP_MODE_STP) ? 0 :
                         (br->mode == STP_MODE_RSTP) ? 2 : 3;
    out->bpdu_type     = BPDU_TYPE_RSTP;
    out->root_id       = br->root_id;
    out->root_path_cost= br->root_path_cost;
    out->bridge_id     = br->bridge_id;
    out->port_id       = p->port_id;
    out->message_age   = 0;
    out->max_age       = (uint16_t)(br->max_age   * 256);
    out->hello_time    = (uint16_t)(br->hello_time * 256);
    out->fwd_delay     = (uint16_t)(br->fwd_delay  * 256);

    /* flags */
    if (p->state == STP_PS_LEARNING)   out->flags |= BPDU_FL_LEARNING;
    if (p->state == STP_PS_FORWARDING) out->flags |= BPDU_FL_FORWARDING;
    if (br->mode != STP_MODE_STP) {
        if (p->proposing) out->flags |= BPDU_FL_PROPOSAL;
        if (p->agreed)    out->flags |= BPDU_FL_AGREEMENT;
        /* encode role in bits [3:2] */
        uint8_t role_enc = 0;
        switch (p->role) {
        case STP_PR_ALTERNATE:
        case STP_PR_BACKUP:     role_enc = 1; break;
        case STP_PR_ROOT:       role_enc = 2; break;
        case STP_PR_DESIGNATED: role_enc = 3; break;
        default:                role_enc = 0; break;
        }
        out->flags |= (uint8_t)(role_enc << BPDU_FL_ROLE_SHIFT);
    }
    if (br->tc_active) out->flags |= BPDU_FL_TC;
}

/* ─── MST: VLAN → instance mapping ──────────────────────────── */
int mst_map_vlan(stp_bridge_t *br, uint16_t vlan, uint8_t instance)
{
    if (vlan < 1 || vlan > MST_MAX_VLANS) return -1;
    if (instance >= MST_MAX_INSTANCES)     return -1;
    if (!br->mstis[instance].active && instance != 0) {
        br->mstis[instance].active            = 1;
        br->mstis[instance].id                = instance;
        br->mstis[instance].bridge_priority   = 32768;
        br->mstis[instance].regional_root     = br->bridge_id;
    }
    /* remove from old instance */
    for (int i = 0; i < MST_MAX_INSTANCES; i++)
        if (br->mstis[i].vlan_map[vlan] == i) {
            br->mstis[i].vlan_map[vlan] = 0;
            break;
        }
    br->mstis[instance].vlan_map[vlan] = instance;
    return 0;
}

int mst_instance_active(const stp_bridge_t *br, uint8_t inst)
{
    return (inst < MST_MAX_INSTANCES) && br->mstis[inst].active;
}

int mst_vlan_instance(const stp_bridge_t *br, uint16_t vlan)
{
    if (vlan < 1 || vlan > MST_MAX_VLANS) return 0;
    for (int i = 0; i < MST_MAX_INSTANCES; i++)
        if (br->mstis[i].active && br->mstis[i].vlan_map[vlan] == i)
            return i;
    return 0;   /* default: IST */
}
