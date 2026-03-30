#include "json_util.h"
#include <stdio.h>
#include <string.h>

int jget(const char *json, const char *key, char *buf, size_t sz)
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
        while (i > 0 && (buf[i-1]==' '||buf[i-1]=='\r')) buf[--i]='\0';
    }
    return 0;
}
