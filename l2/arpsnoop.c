#include "arpsnoop.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>

void arpsnoop_ip_str(const uint8_t ip[16], int is_ipv6,
                      char *buf, size_t sz) {
    if (is_ipv6) inet_ntop(AF_INET6, ip, buf, (socklen_t)sz);
    else {
        struct in_addr a; memcpy(&a, ip, 4);
        inet_ntop(AF_INET, &a, buf, (socklen_t)sz);
    }
}

static uint32_t arp_hash(const uint8_t ip[16], int is_ipv6, uint16_t vlan) {
    uint32_t h = 2166136261u;
    int len = is_ipv6 ? 16 : 4;
    for (int i = 0; i < len; i++) { h ^= ip[i]; h *= 16777619u; }
    h ^= vlan; h *= 16777619u;
    return h & (ARPSNOOP_BUCKETS - 1);
}

void arpsnoop_init(arpsnoop_table_t *tbl) {
    memset(tbl, 0, sizeof(*tbl));
    tbl->enabled  = 1;
    tbl->age_sec  = ARPSNOOP_DEFAULT_AGE;
}

static arpsnoop_entry_t *pool_alloc(arpsnoop_table_t *tbl) {
    if (tbl->pool_used >= ARPSNOOP_MAX_BINDINGS) return NULL;
    arpsnoop_entry_t *e = &tbl->pool[tbl->pool_used++];
    memset(e, 0, sizeof(*e));
    return e;
}

int arpsnoop_learn(arpsnoop_table_t *tbl,
                    const uint8_t mac[6], const uint8_t ip[16],
                    int is_ipv6, uint16_t vlan, const char *port,
                    arpsnoop_type_t type) {
    if (!tbl->enabled) return 0;
    uint32_t idx = arp_hash(ip, is_ipv6, vlan);
    int iplen = is_ipv6 ? 16 : 4;
    time_t now = time(NULL);

    /* search for existing */
    arpsnoop_entry_t *e = tbl->buckets[idx];
    while (e) {
        if (e->is_ipv6 == is_ipv6 && e->vlan == vlan &&
            memcmp(e->ip, ip, (size_t)iplen) == 0) {
            /* check for ARP spoofing: same IP, different port */
            if (strncmp(e->port, port, FDB_IFNAME_LEN) != 0 &&
                type != ARPSNOOP_TYPE_STATIC) {
                tbl->total_violations++;
                return -1;
            }
            memcpy(e->mac, mac, 6);
            strncpy(e->port, port, FDB_IFNAME_LEN-1);
            e->last_seen = now;
            e->type      = type;
            return 0;
        }
        e = e->next;
    }
    /* new entry */
    e = pool_alloc(tbl);
    if (!e) return -ENOMEM;
    memcpy(e->mac,  mac, 6);
    memcpy(e->ip,   ip, (size_t)iplen);
    e->is_ipv6   = is_ipv6;
    e->vlan      = vlan;
    strncpy(e->port, port, FDB_IFNAME_LEN-1);
    e->type      = type;
    e->last_seen = now;
    e->age_sec   = tbl->age_sec;
    e->next      = tbl->buckets[idx];
    tbl->buckets[idx] = e;
    tbl->count++;
    tbl->total_learned++;
    return 0;
}

const arpsnoop_entry_t *arpsnoop_lookup_ip(arpsnoop_table_t *tbl,
                                            const uint8_t ip[16],
                                            int is_ipv6, uint16_t vlan) {
    uint32_t idx = arp_hash(ip, is_ipv6, vlan);
    int iplen = is_ipv6 ? 16 : 4;
    arpsnoop_entry_t *e = tbl->buckets[idx];
    while (e) {
        if (e->is_ipv6 == is_ipv6 && e->vlan == vlan &&
            memcmp(e->ip, ip, (size_t)iplen) == 0) {
            e->hit_count++;
            return e;
        }
        e = e->next;
    }
    return NULL;
}

const arpsnoop_entry_t *arpsnoop_lookup_mac(arpsnoop_table_t *tbl,
                                             const uint8_t mac[6],
                                             uint16_t vlan) {
    for (int b = 0; b < ARPSNOOP_BUCKETS; b++) {
        arpsnoop_entry_t *e = tbl->buckets[b];
        while (e) {
            if (e->vlan == vlan && memcmp(e->mac, mac, 6) == 0) {
                e->hit_count++;
                return e;
            }
            e = e->next;
        }
    }
    return NULL;
}

int arpsnoop_delete(arpsnoop_table_t *tbl,
                     const uint8_t ip[16], int is_ipv6, uint16_t vlan) {
    uint32_t idx = arp_hash(ip, is_ipv6, vlan);
    int iplen = is_ipv6 ? 16 : 4;
    arpsnoop_entry_t **pp = &tbl->buckets[idx];
    while (*pp) {
        arpsnoop_entry_t *e = *pp;
        if (e->is_ipv6 == is_ipv6 && e->vlan == vlan &&
            memcmp(e->ip, ip, (size_t)iplen) == 0) {
            *pp = e->next;
            memset(e, 0, sizeof(*e));
            tbl->count--;
            return 0;
        }
        pp = &e->next;
    }
    return -ENOENT;
}

int arpsnoop_flush_port(arpsnoop_table_t *tbl, const char *port) {
    int removed = 0;
    for (int b = 0; b < ARPSNOOP_BUCKETS; b++) {
        arpsnoop_entry_t **pp = &tbl->buckets[b];
        while (*pp) {
            if (strncmp((*pp)->port, port, FDB_IFNAME_LEN) == 0) {
                arpsnoop_entry_t *e = *pp;
                *pp = e->next;
                memset(e, 0, sizeof(*e));
                tbl->count--;
                removed++;
            } else pp = &(*pp)->next;
        }
    }
    return removed;
}

int arpsnoop_age_sweep(arpsnoop_table_t *tbl) {
    time_t now = time(NULL);
    int removed = 0;
    for (int b = 0; b < ARPSNOOP_BUCKETS; b++) {
        arpsnoop_entry_t **pp = &tbl->buckets[b];
        while (*pp) {
            arpsnoop_entry_t *e = *pp;
            if (e->type != ARPSNOOP_TYPE_STATIC &&
                (now - e->last_seen) >= (time_t)e->age_sec) {
                *pp = e->next;
                memset(e, 0, sizeof(*e));
                tbl->count--;
                tbl->total_aged++;
                removed++;
            } else pp = &e->next;
        }
    }
    return removed;
}
