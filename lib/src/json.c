#include <vrouter/json.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int vr_json_get_str(const char *json, const char *key, char *buf, size_t sz)
{
    if (!json || !key || !buf || sz == 0) return -1;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t') p++;
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
        while (i > 0 && (buf[i-1] == ' ' || buf[i-1] == '\r')) buf[--i] = '\0';
    }
    return 0;
}

long vr_json_get_int(const char *json, const char *key, long fallback)
{
    char buf[32];
    if (vr_json_get_str(json, key, buf, sizeof(buf)) != 0) return fallback;
    if (buf[0] == '\0') return fallback;
    char *end;
    long val = strtol(buf, &end, 10);
    if (end == buf) return fallback;
    return val;
}

bool vr_json_get_bool(const char *json, const char *key)
{
    if (!json || !key) return false;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":true", key);
    return strstr(json, needle) != NULL;
}
