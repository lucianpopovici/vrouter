#ifndef PERSIST_H
#define PERSIST_H

/*
 * persist.h / persist.c — dump and restore RIB + FIB state
 *
 * Format: newline-delimited JSON, one route per line:
 *   {"prefix":"10.0.0.0/8","nexthop":"1.1.1.1","iface":"eth0",
 *    "metric":100,"source":"ospf","ad":110}
 *
 * Used for both startup restore and SIGHUP-triggered checkpoint.
 */

#include "rib.h"
#include "fib.h"

#define L3_DUMP_FILE  "vrouter_routes.json"

/* Save all RIB candidates to file. Returns 0 on success. */
int  persist_dump(const rib_table_t *rib, const char *path);

/* Restore RIB from file, pushing best routes into FIB via callback.
 * Returns number of routes restored, or -1 on error. */
int  persist_restore(rib_table_t *rib, rib_fib_cb cb, void *cb_ctx,
                     const char *path);

#endif /* PERSIST_H */
