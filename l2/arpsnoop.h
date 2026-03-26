#ifndef ARPSNOOP_H
#define ARPSNOOP_H

#include <stdint.h>
#include <time.h>
#include "fdb.h"

#define ARPSNOOP_MAX_BINDINGS  8192
#define ARPSNOOP_DEFAULT_AGE   3600   /* 1 hour */
#define ARPSNOOP_BUCKETS       4096   /* power of 2 */

typedef enum {
    ARPSNOOP_TYPE_ARP  = 0,  /* IPv4 ARP                        */
    ARPSNOOP_TYPE_ND   = 1,  /* IPv6 Neighbor Discovery         */
    ARPSNOOP_TYPE_DHCP = 2,  /* learned from DHCP snooping      */
    ARPSNOOP_TYPE_STATIC = 3,
} arpsnoop_type_t;

/* ─── One binding: MAC + IP + port + VLAN ───────────────────── */
typedef struct arpsnoop_entry {
    uint8_t  mac[6];
    uint8_t  ip[16];          /* IPv4 in first 4 bytes; IPv6 full */
    int      is_ipv6;
    uint16_t vlan;
    char     port[FDB_IFNAME_LEN];
    arpsnoop_type_t type;
    time_t   last_seen;
    uint32_t age_sec;
    uint64_t hit_count;
    struct arpsnoop_entry *next;  /* hash chain */
} arpsnoop_entry_t;

/* ─── Snooping table ─────────────────────────────────────────── */
typedef struct {
    arpsnoop_entry_t *buckets[ARPSNOOP_BUCKETS];
    int               count;
    int               enabled;
    uint32_t          age_sec;
    uint64_t          total_learned;
    uint64_t          total_aged;
    uint64_t          total_violations;  /* ARP poisoning attempts  */
    arpsnoop_entry_t  pool[ARPSNOOP_MAX_BINDINGS];
    int               pool_used;
} arpsnoop_table_t;

/* ─── API ────────────────────────────────────────────────────── */
void  arpsnoop_init(arpsnoop_table_t *tbl);

/* Learn/refresh a binding; returns 0=ok, -1=violation (IP moved port) */
int   arpsnoop_learn(arpsnoop_table_t *tbl,
                      const uint8_t mac[6],
                      const uint8_t ip[16], int is_ipv6,
                      uint16_t vlan, const char *port,
                      arpsnoop_type_t type);

/* Lookup by IP; returns entry or NULL */
const arpsnoop_entry_t *arpsnoop_lookup_ip(arpsnoop_table_t *tbl,
                                            const uint8_t ip[16],
                                            int is_ipv6, uint16_t vlan);

/* Lookup by MAC */
const arpsnoop_entry_t *arpsnoop_lookup_mac(arpsnoop_table_t *tbl,
                                             const uint8_t mac[6],
                                             uint16_t vlan);

int   arpsnoop_delete(arpsnoop_table_t *tbl,
                       const uint8_t ip[16], int is_ipv6, uint16_t vlan);
int   arpsnoop_flush_port(arpsnoop_table_t *tbl, const char *port);
int   arpsnoop_age_sweep(arpsnoop_table_t *tbl);

void  arpsnoop_ip_str(const uint8_t ip[16], int is_ipv6,
                       char *buf, size_t sz);

#endif /* ARPSNOOP_H */
