#ifndef JSON_UTIL_H
#define JSON_UTIL_H
#include <stddef.h>
/* Extract a string or numeric field from a flat JSON object.
 * Returns 0 on success, -1 if key not found.
 * Does NOT handle nested objects, arrays, or escaped quotes. */
int jget(const char *json, const char *key, char *buf, size_t sz);
#endif
