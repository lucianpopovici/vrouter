#ifndef VROUTER_HASH_H
#define VROUTER_HASH_H

#include <stdint.h>
#include <stddef.h>

#define VR_FNV_OFFSET 2166136261u
#define VR_FNV_PRIME  16777619u

/* Generic FNV-1a over arbitrary bytes. Returns raw hash (caller does % n). */
static inline uint32_t vr_fnv1a(const uint8_t *data, size_t len)
{
    uint32_t h = VR_FNV_OFFSET;
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= VR_FNV_PRIME; }
    return h;
}

/* Hash + modulo a bucket count in one call. */
static inline uint32_t vr_fnv1a_mod(const uint8_t *data, size_t len, uint32_t n)
{
    return n ? vr_fnv1a(data, len) % n : 0;
}

#endif /* VROUTER_HASH_H */
