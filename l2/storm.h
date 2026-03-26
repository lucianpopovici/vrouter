#ifndef STORM_H
#define STORM_H

#include <stdint.h>
#include <time.h>
#include "fdb.h"

#define STORM_MAX_PORTS 256

/* Traffic types subject to storm control */
typedef enum {
    STORM_BROADCAST        = 0,
    STORM_UNKNOWN_UNICAST  = 1,
    STORM_MULTICAST        = 2,
    STORM_TYPE_COUNT       = 3,
} storm_type_t;

typedef enum {
    STORM_ACTION_DROP     = 0,  /* drop excess frames          */
    STORM_ACTION_SHUTDOWN = 1,  /* err-disable port            */
} storm_action_t;

/* Token bucket per type per port */
typedef struct {
    int      enabled;
    uint64_t rate_pps;        /* tokens/second (frames/sec)  */
    uint64_t burst;           /* max bucket depth            */
    uint64_t tokens;          /* current tokens              */
    uint64_t last_refill;     /* unix time ns (clock_gettime)*/
    uint64_t dropped;         /* frames dropped              */
    uint64_t passed;
} storm_bucket_t;

typedef struct {
    char          name[FDB_IFNAME_LEN];
    int           in_use;
    int           err_disabled;
    storm_action_t action;
    storm_bucket_t buckets[STORM_TYPE_COUNT];
    uint64_t      total_dropped;
} storm_port_t;

typedef struct {
    storm_port_t ports[STORM_MAX_PORTS];
    int          n_ports;
} storm_table_t;

void  storm_init(storm_table_t *st);
storm_port_t *storm_port_get(storm_table_t *st, const char *port);
storm_port_t *storm_port_add(storm_table_t *st, const char *port);

/* Configure rate limit for one type on a port */
int   storm_set_rate(storm_table_t *st, const char *port,
                      storm_type_t type, uint64_t pps, uint64_t burst);
int   storm_enable(storm_table_t *st, const char *port,
                    storm_type_t type, int enable);

/* Call on each frame: returns 0=pass, -1=drop */
int   storm_check(storm_table_t *st, const char *port, storm_type_t type);

void  storm_clear_counters(storm_table_t *st, const char *port);

const char *storm_type_str(storm_type_t t);
const char *storm_action_str(storm_action_t a);

#endif /* STORM_H */
