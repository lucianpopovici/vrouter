#ifndef L2_CLI_H
#define L2_CLI_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "fdb_ipc.h"
#include "l2rib_ipc.h"
#include "stp_ipc.h"

#define L2_SCHEMA_FILE   "l2d_schema.json"
#define L2_RUNTIME_FILE  "l2d_runtime_config.json"

#define L2_DEFAULT_FDB_AGE  300
#define L2_DEFAULT_SOCK_DIR  "/tmp"
#define L2_DEFAULT_FDB_MAX  65536

/* ─── Shared live config (single source of truth) ───────────── *
 * Owned by main; pointers to fdb/stp passed in for apply().    */
typedef struct {
    /* Sockets */
    char      sock_dir[128];       /* directory for all sockets    */
    /* FDB */
    uint32_t  fdb_age_sec;
    uint32_t  fdb_max_entries;
    /* STP */
    char      stp_mode[8];        /* "stp" | "rstp" | "mst"      */
    uint16_t  stp_priority;
    uint16_t  stp_hello;
    uint16_t  stp_max_age;
    uint16_t  stp_fwd_delay;
    /* MST */
    char      mst_region[32];
    uint32_t  mst_revision;
} l2_config_t;

int  l2_cli_write_schema(void);
int  l2_cli_load_config(l2_config_t *cfg);
int  l2_cli_save_key(const char *key, const char *value);
void l2_config_defaults(l2_config_t *cfg);

#endif /* L2_CLI_H */
