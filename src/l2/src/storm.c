#include "storm.h"
#include <string.h>
#include <errno.h>

const char *storm_type_str(storm_type_t t) {
    switch(t) {
    case STORM_BROADCAST:       return "broadcast";
    case STORM_UNKNOWN_UNICAST: return "unknown-unicast";
    case STORM_MULTICAST:       return "multicast";
    default:                    return "unknown";
    }
}
const char *storm_action_str(storm_action_t a) {
    return a == STORM_ACTION_DROP ? "drop" : "shutdown";
}

void storm_init(storm_table_t *st) { memset(st, 0, sizeof(*st)); }

storm_port_t *storm_port_get(storm_table_t *st, const char *port) {
    for (int i = 0; i < st->n_ports; i++)
        if (strncmp(st->ports[i].name, port, FDB_IFNAME_LEN) == 0)
            return &st->ports[i];
    return NULL;
}

storm_port_t *storm_port_add(storm_table_t *st, const char *port) {
    storm_port_t *p = storm_port_get(st, port);
    if (p) return p;
    if (st->n_ports >= STORM_MAX_PORTS) return NULL;
    p = &st->ports[st->n_ports++];
    memset(p, 0, sizeof(*p));
    strncpy(p->name, port, FDB_IFNAME_LEN-1);
    p->in_use = 1;
    p->action = STORM_ACTION_DROP;
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    for (int i = 0; i < STORM_TYPE_COUNT; i++) {
        p->buckets[i].last_refill = now;
        p->buckets[i].tokens      = 0;
    }
    return p;
}

int storm_set_rate(storm_table_t *st, const char *port,
                    storm_type_t type, uint64_t pps, uint64_t burst) {
    if (type >= STORM_TYPE_COUNT) return -EINVAL;
    storm_port_t *p = storm_port_add(st, port);
    if (!p) return -ENOMEM;
    storm_bucket_t *b = &p->buckets[type];
    b->rate_pps = pps;
    b->burst    = burst ? burst : pps;  /* default burst = 1s of rate */
    b->tokens   = b->burst;
    b->enabled  = (pps > 0);
    return 0;
}

int storm_enable(storm_table_t *st, const char *port,
                  storm_type_t type, int enable) {
    if (type >= STORM_TYPE_COUNT) return -EINVAL;
    storm_port_t *p = storm_port_get(st, port);
    if (!p) return -ENOENT;
    p->buckets[type].enabled = enable;
    return 0;
}

int storm_check(storm_table_t *st, const char *port, storm_type_t type) {
    if (type >= STORM_TYPE_COUNT) return 0;
    storm_port_t *p = storm_port_get(st, port);
    if (!p || p->err_disabled) return -1;

    storm_bucket_t *b = &p->buckets[type];
    if (!b->enabled || b->rate_pps == 0) return 0;

    /* refill tokens based on elapsed time */
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    uint64_t elapsed_ns = now - b->last_refill;
    uint64_t new_tokens = (elapsed_ns * b->rate_pps) / 1000000000ULL;
    if (new_tokens > 0) {
        b->tokens += new_tokens;
        if (b->tokens > b->burst) b->tokens = b->burst;
        b->last_refill = now;
    }

    if (b->tokens >= 1) {
        b->tokens--;
        b->passed++;
        return 0;  /* pass */
    }

    /* drop */
    b->dropped++;
    p->total_dropped++;
    if (p->action == STORM_ACTION_SHUTDOWN)
        p->err_disabled = 1;
    return -1;
}

void storm_clear_counters(storm_table_t *st, const char *port) {
    storm_port_t *p = storm_port_get(st, port);
    if (!p) return;
    p->total_dropped = 0;
    for (int i = 0; i < STORM_TYPE_COUNT; i++) {
        p->buckets[i].dropped = 0;
        p->buckets[i].passed  = 0;
    }
}
