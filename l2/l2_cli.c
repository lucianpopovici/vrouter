#include "l2_cli.h"
#include "l2_ipc_extra.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ─── Write schema.json ─────────────────────────────────────── */
int l2_cli_write_schema(void)
{
    FILE *f = fopen(L2_SCHEMA_FILE, "w");
    if (!f) return -errno;

    fprintf(f,
        "{\n"
        "  \"module\": \"l2d\",\n"
        "  \"version\": \"1.0.0\",\n"
        "  \"description\": \"L2 forwarding daemon (FDB + L2RIB + STP/RSTP/MST)\",\n"
        "  \"socket_names\": {\n"
        "    \"fdb\":     \"" FDB_SOCK_NAME     "\",\n"
        "    \"l2rib\":   \"" L2RIB_SOCK_NAME   "\",\n"
        "    \"stp\":     \"" STP_SOCK_NAME     "\",\n"
        "    \"vlan\":    \"" VLAN_SOCK_NAME    "\",\n"
        "    \"portsec\": \"" PORTSEC_SOCK_NAME "\",\n"
        "    \"storm\":   \"" STORM_SOCK_NAME   "\",\n"
        "    \"igmp\":    \"" IGMP_SOCK_NAME    "\",\n"
        "    \"arp\":     \"" ARP_SOCK_NAME     "\",\n"
        "    \"lacp\":    \"" LACP_SOCK_NAME    "\"\n"
        "  },\n"
        "  \"keys\": {\n"
        /* FDB group */
        "    \"FDB_AGE_SEC\": {\n"
        "      \"type\": \"int\", \"default\": %d,\n"
        "      \"min\": 10, \"max\": 86400,\n"
        "      \"description\": \"Dynamic FDB entry lifetime in seconds\",\n"
        "      \"mandatory\": false, \"group\": \"FDB\"\n"
        "    },\n"
        "    \"FDB_MAX_ENTRIES\": {\n"
        "      \"type\": \"int\", \"default\": %d,\n"
        "      \"min\": 100, \"max\": 524288,\n"
        "      \"description\": \"Maximum FDB table size\",\n"
        "      \"mandatory\": false, \"group\": \"FDB\"\n"
        "    },\n"
        /* STP group */
        "    \"STP_MODE\": {\n"
        "      \"type\": \"str\", \"default\": \"rstp\",\n"
        "      \"choices\": [\"stp\", \"rstp\", \"mst\"],\n"
        "      \"description\": \"Spanning tree protocol variant\",\n"
        "      \"mandatory\": false, \"group\": \"STP\"\n"
        "    },\n"
        "    \"STP_PRIORITY\": {\n"
        "      \"type\": \"int\", \"default\": 32768,\n"
        "      \"min\": 0, \"max\": 61440,\n"
        "      \"description\": \"Bridge priority (must be multiple of 4096)\",\n"
        "      \"mandatory\": false, \"group\": \"STP\"\n"
        "    },\n"
        "    \"STP_HELLO\": {\n"
        "      \"type\": \"int\", \"default\": 2,\n"
        "      \"min\": 1, \"max\": 10,\n"
        "      \"description\": \"Hello time in seconds\",\n"
        "      \"mandatory\": false, \"group\": \"STP\"\n"
        "    },\n"
        "    \"STP_MAX_AGE\": {\n"
        "      \"type\": \"int\", \"default\": 20,\n"
        "      \"min\": 6, \"max\": 40,\n"
        "      \"description\": \"Max age for BPDU info in seconds\",\n"
        "      \"mandatory\": false, \"group\": \"STP\"\n"
        "    },\n"
        "    \"STP_FWD_DELAY\": {\n"
        "      \"type\": \"int\", \"default\": 15,\n"
        "      \"min\": 4, \"max\": 30,\n"
        "      \"description\": \"Forward delay timer in seconds\",\n"
        "      \"mandatory\": false, \"group\": \"STP\"\n"
        "    },\n"
        /* MST group */
        "    \"MST_REGION\": {\n"
        "      \"type\": \"str\", \"default\": \"\",\n"
        "      \"description\": \"MST region name (must match on all bridges)\",\n"
        "      \"mandatory\": false, \"group\": \"MST\"\n"
        "    },\n"
        "    \"MST_REVISION\": {\n"
        "      \"type\": \"int\", \"default\": 0,\n"
        "      \"min\": 0, \"max\": 65535,\n"
        "      \"description\": \"MST configuration revision number\",\n"
        "      \"mandatory\": false, \"group\": \"MST\"\n"
        "    }\n"
        "  }\n"
        "}\n",
        L2_DEFAULT_FDB_AGE, L2_DEFAULT_FDB_MAX);

    fclose(f);
    return 0;
}

/* ─── Tiny JSON value extractor ─────────────────────────────── */
static int jget(const char *json, const char *key, char *buf, size_t sz)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p == '"') {
        p++; size_t i = 0;
        while (*p && *p != '"' && i < sz-1) buf[i++] = *p++;
        buf[i] = '\0';
    } else {
        size_t i = 0;
        while (*p && *p != ',' && *p != '\n' && *p != '}' && i < sz-1)
            buf[i++] = *p++;
        buf[i] = '\0';
        while (i > 0 && (buf[i-1]==' '||buf[i-1]=='\r')) buf[--i] = '\0';
    }
    return 0;
}

/* ─── Load runtime_config.json → apply to live state ────────── */
int l2_cli_load_config(l2_config_t *cfg)
{
    FILE *f = fopen(L2_RUNTIME_FILE, "r");
    if (!f) return -ENOENT;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f); rewind(f);
    if (sz <= 0 || sz > 65536) { fclose(f); return -EINVAL; }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -ENOMEM; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -EIO;
    }
    buf[sz] = '\0';
    fclose(f);

    char val[64];

    if (jget(buf, "FDB_AGE_SEC",    val, sizeof(val)) == 0) {
        int v = atoi(val);
        if (v >= 10 && v <= 86400) cfg->fdb_age_sec = (uint32_t)v;
    }
    if (jget(buf, "FDB_MAX_ENTRIES", val, sizeof(val)) == 0) {
        int v = atoi(val);
        if (v >= 100 && v <= 524288) cfg->fdb_max_entries = (uint32_t)v;
    }
    if (jget(buf, "STP_MODE",        val, sizeof(val)) == 0) {
        /* jget already null-terminated val; clamp to field width */
        strncpy(cfg->stp_mode, val, sizeof(cfg->stp_mode));
        cfg->stp_mode[sizeof(cfg->stp_mode)-1] = '\0';
    }
    if (jget(buf, "STP_PRIORITY",    val, sizeof(val)) == 0) {
        int v = atoi(val);
        if (v >= 0 && v <= 61440 && v % 4096 == 0)
            cfg->stp_priority = (uint16_t)v;
    }
    if (jget(buf, "STP_HELLO",       val, sizeof(val)) == 0) {
        int v = atoi(val);
        if (v >= 1 && v <= 10) cfg->stp_hello = (uint16_t)v;
    }
    if (jget(buf, "STP_MAX_AGE",     val, sizeof(val)) == 0) {
        int v = atoi(val);
        if (v >= 6 && v <= 40) cfg->stp_max_age = (uint16_t)v;
    }
    if (jget(buf, "STP_FWD_DELAY",   val, sizeof(val)) == 0) {
        int v = atoi(val);
        if (v >= 4 && v <= 30) cfg->stp_fwd_delay = (uint16_t)v;
    }
    if (jget(buf, "MST_REGION",      val, sizeof(val)) == 0) {
        strncpy(cfg->mst_region, val, sizeof(cfg->mst_region));
        cfg->mst_region[sizeof(cfg->mst_region)-1] = '\0';
    }
    if (jget(buf, "MST_REVISION",    val, sizeof(val)) == 0) {
        int v = atoi(val);
        if (v >= 0 && v <= 65535) cfg->mst_revision = (uint32_t)v;
    }

    if (jget(buf, "SOCK_DIR", val, sizeof(val)) == 0 && val[0])
        strncpy(cfg->sock_dir, val, sizeof(cfg->sock_dir)-1);

    free(buf);
    return 0;
}

/* ─── Persist one key to runtime_config.json ────────────────── */
int l2_cli_save_key(const char *key, const char *value)
{
    char existing[8192] = "{}";
    FILE *f = fopen(L2_RUNTIME_FILE, "r");
    if (f) {
        size_t n = fread(existing, 1, sizeof(existing)-1, f);
        existing[n] = '\0';
        fclose(f);
    }

    /* find and replace or inject */
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    char *pos = strstr(existing, needle);
    char updated[8192];
    int is_num = (value[0]=='-' || (value[0]>='0' && value[0]<='9'));

    if (pos) {
        char *colon = strchr(pos, ':');
        if (!colon) return -EINVAL;
        colon++;
        while (*colon == ' ') colon++;
        char *end = colon;
        if (*end == '"') { end++; while (*end && *end != '"') end++; if (*end) end++; }
        else { while (*end && *end != ',' && *end != '\n' && *end != '}') end++; }
        size_t pre = (size_t)(colon - existing);
        if (is_num)
            snprintf(updated, sizeof(updated), "%.*s%s%s", (int)pre, existing, value, end);
        else
            snprintf(updated, sizeof(updated), "%.*s\"%s\"%s", (int)pre, existing, value, end);
    } else {
        char *close = strrchr(existing, '}');
        if (!close) return -EINVAL;
        int has = (close > existing + strspn(existing, " \t\n{"));
        if (is_num)
            snprintf(updated, sizeof(updated), "%.*s%s\"%s\": %s\n}",
                     (int)(close-existing), existing, has?",\n  ":"\n  ", key, value);
        else
            snprintf(updated, sizeof(updated), "%.*s%s\"%s\": \"%s\"\n}",
                     (int)(close-existing), existing, has?",\n  ":"\n  ", key, value);
    }

    f = fopen(L2_RUNTIME_FILE, "w");
    if (!f) return -errno;
    fputs(updated, f);
    fclose(f);
    return 0;
}

/* ─── Default config values ─────────────────────────────────── */
void l2_config_defaults(l2_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->fdb_age_sec      = L2_DEFAULT_FDB_AGE;
    cfg->fdb_max_entries  = (uint32_t)L2_DEFAULT_FDB_MAX;
    cfg->stp_priority     = 32768;
    cfg->stp_hello        = 2;
    cfg->stp_max_age      = 20;
    cfg->stp_fwd_delay    = 15;
    cfg->mst_revision     = 0;
    strncpy(cfg->stp_mode, "rstp", sizeof(cfg->stp_mode)-1);
    strncpy(cfg->sock_dir, L2_DEFAULT_SOCK_DIR, sizeof(cfg->sock_dir)-1);
}
