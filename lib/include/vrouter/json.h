#ifndef VROUTER_JSON_H
#define VROUTER_JSON_H

#include <stddef.h>
#include <stdbool.h>

/*
 * Flat JSON parser helpers — no support for nested objects, arrays, or
 * escaped quotes. Sufficient for the simple command/response JSON used
 * throughout vrouter's IPC layer.
 */

/* Extract string value for "key" from flat JSON.
 * Returns 0 on success, -1 if key not found. */
int  vr_json_get_str(const char *json, const char *key, char *buf, size_t sz);

/* Extract integer value. Returns the value, or fallback if key not found. */
long vr_json_get_int(const char *json, const char *key, long fallback);

/* Extract boolean value (looks for "key":true). Returns false if not found. */
bool vr_json_get_bool(const char *json, const char *key);

#endif /* VROUTER_JSON_H */
