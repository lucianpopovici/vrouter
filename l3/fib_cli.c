#include "fib_cli.h"
#include "fib.h"
#include "rib_ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define SCHEMA_FILE         "schema.json"
#define RUNTIME_CONFIG_FILE "runtime_config.json"

/* ─── Write schema.json (tier-3 file-based mode) ───────────── */
int cli_write_schema(void)
{
    FILE *f = fopen(SCHEMA_FILE, "w");
    if (!f) return -errno;

    fprintf(f,
        "{\n"
        "  \"module\": \"fib\",\n"
        "  \"version\": \"1.0.0\",\n"
        "  \"description\": \"Forwarding Information Base daemon\",\n"
        "  \"socket_names\": {\"fib\": \"" FIB_SOCK_NAME "\", \"rib\": \"" RIB_SOCK_NAME "\"},\n"
        "  \"keys\": {\n"
        "    \"MAX_ROUTES\": {\n"
        "      \"type\": \"int\",\n"
        "      \"description\": \"Maximum number of FIB entries\",\n"
        "      \"default\": %d,\n"
        "      \"min\": 10,\n"
        "      \"max\": 524288,\n"
        "      \"mandatory\": false,\n"
        "      \"group\": \"Capacity\"\n"
        "    },\n"
        "    \"DEFAULT_METRIC\": {\n"
        "      \"type\": \"int\",\n"
        "      \"description\": \"Default route metric when none specified\",\n"
        "      \"default\": %d,\n"
        "      \"min\": 1,\n"
        "      \"max\": 65535,\n"
        "      \"mandatory\": false,\n"
        "      \"group\": \"Routing\"\n"
        "    },\n"
        "    \"LOG_LEVEL\": {\n"
        "      \"type\": \"str\",\n"
        "      \"description\": \"Logging verbosity\",\n"
        "      \"default\": \"info\",\n"
        "      \"choices\": [\"debug\", \"info\", \"warn\", \"error\"],\n"
        "      \"mandatory\": false,\n"
        "      \"group\": \"Logging\"\n"
        "    }\n"
        "  }\n"
        "}\n",
        FIB_POOL_DEFAULT, FIB_DEFAULT_METRIC);

    fclose(f);
    return 0;
}

/* ─── Tiny JSON value extractor (no external deps) ─────────── *
 * Looks for  "key": <value>  and copies value into buf.        *
 * Handles strings and numbers; not a full parser.              */
static int json_get(const char *json, const char *key, char *buf, size_t sz)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < sz - 1) buf[i++] = *p++;
        buf[i] = '\0';
    } else {
        size_t i = 0;
        while (*p && *p != ',' && *p != '\n' && *p != '}' && i < sz - 1)
            buf[i++] = *p++;
        buf[i] = '\0';
        /* trim trailing spaces */
        while (i > 0 && (buf[i-1] == ' ' || buf[i-1] == '\r')) buf[--i] = '\0';
    }
    return 0;
}

/* ─── Load runtime_config.json ─────────────────────────────── */
int cli_load_runtime_config(fib_table_t *fib)
{
    FILE *f = fopen(RUNTIME_CONFIG_FILE, "r");
    if (!f) return -ENOENT;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 65536) { fclose(f); return -EINVAL; }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -ENOMEM; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -EIO;
    }
    buf[sz] = '\0';
    fclose(f);

    char val[64];

    if (json_get(buf, "MAX_ROUTES", val, sizeof(val)) == 0) {
        int v = atoi(val);
        if (v >= 10 && v <= 524288)
            fib->max_routes = (uint32_t)v;
    }

    free(buf);
    return 0;
}

/* ─── Save a single key to runtime_config.json ─────────────── */
int cli_save_runtime_key(const char *key, const char *value)
{
    /* read existing */
    char existing[4096] = "{}";
    FILE *f = fopen(RUNTIME_CONFIG_FILE, "r");
    if (f) {
        size_t n = fread(existing, 1, sizeof(existing)-1, f);
        existing[n] = '\0';
        fclose(f);
    }

    /* check if key already present */
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    char *pos = strstr(existing, needle);

    char updated[4096];
    if (pos) {
        /* replace value in-place (naive: rebuild around the key) */
        char *colon = strchr(pos, ':');
        if (!colon) return -EINVAL;
        colon++;
        while (*colon == ' ') colon++;
        /* find end of value */
        char *end = colon;
        if (*end == '"') {
            end++;
            while (*end && *end != '"') end++;
            if (*end) end++;
        } else {
            while (*end && *end != ',' && *end != '\n' && *end != '}') end++;
        }
        /* rebuild: everything before colon, new value, rest */
        size_t pre  = (size_t)(colon - existing);
        int is_str  = (value[0] != '-' && (value[0] < '0' || value[0] > '9'));
        if (is_str)
            snprintf(updated, sizeof(updated), "%.*s\"%s\"%s",
                     (int)pre, existing, value, end);
        else
            snprintf(updated, sizeof(updated), "%.*s%s%s",
                     (int)pre, existing, value, end);
    } else {
        /* inject before closing brace */
        char *close = strrchr(existing, '}');
        if (!close) return -EINVAL;
        int is_str = (value[0] != '-' && (value[0] < '0' || value[0] > '9'));
        int has_content = (close != existing + strspn(existing, " \t\n{"));
        if (is_str)
            snprintf(updated, sizeof(updated), "%.*s%s\"%s\": \"%s\"\n}",
                     (int)(close - existing), existing,
                     has_content ? ",\n  " : "\n  ", key, value);
        else
            snprintf(updated, sizeof(updated), "%.*s%s\"%s\": %s\n}",
                     (int)(close - existing), existing,
                     has_content ? ",\n  " : "\n  ", key, value);
    }

    f = fopen(RUNTIME_CONFIG_FILE, "w");
    if (!f) return -errno;
    fputs(updated, f);
    fclose(f);
    return 0;
}
