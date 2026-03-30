#include <vrouter/net_parse.h>
#include <vrouter/net_types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int vr_addr_parse(const char *str, vr_addr_t *out)
{
    if (!str || !out) return -1;
    if (inet_pton(AF_INET,  str, &out->u.v4) == 1) { out->af = AF_INET;  return 0; }
    if (inet_pton(AF_INET6, str, &out->u.v6) == 1) { out->af = AF_INET6; return 0; }
    return -1;
}

int vr_prefix_parse(const char *str, vr_prefix_t *out)
{
    if (!str || !out) return -1;
    char buf[INET6_ADDRSTRLEN + 4];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    int plen = -1;
    if (slash) { *slash = '\0'; plen = atoi(slash + 1); }
    if (vr_addr_parse(buf, &out->addr) != 0) return -1;
    uint8_t maxp = (out->addr.af == AF_INET) ? 32 : 128;
    if (plen < 0 || plen > maxp) plen = maxp;
    out->plen = (uint8_t)plen;
    return 0;
}

int vr_mac_parse(const char *str, vr_mac_t *out)
{
    if (!str || !out) return -1;
    if (sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &out->b[0], &out->b[1], &out->b[2],
               &out->b[3], &out->b[4], &out->b[5]) == 6)
        return 0;
    return -1;
}

void vr_addr_to_str(const vr_addr_t *addr, char *buf, size_t len)
{
    if (addr->af == AF_INET) inet_ntop(AF_INET,  &addr->u.v4, buf, len);
    else                     inet_ntop(AF_INET6, &addr->u.v6, buf, len);
}

void vr_prefix_to_str(const vr_prefix_t *pfx, char *buf, size_t len)
{
    char ab[INET6_ADDRSTRLEN];
    vr_addr_to_str(&pfx->addr, ab, sizeof(ab));
    snprintf(buf, len, "%s/%u", ab, pfx->plen);
}

void vr_mac_to_str(const vr_mac_t *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->b[0], mac->b[1], mac->b[2],
             mac->b[3], mac->b[4], mac->b[5]);
}

bool vr_addr_eq(const vr_addr_t *a, const vr_addr_t *b)
{
    if (a->af != b->af) return false;
    if (a->af == AF_INET)  return a->u.v4.s_addr == b->u.v4.s_addr;
    return memcmp(&a->u.v6, &b->u.v6, sizeof(struct in6_addr)) == 0;
}

bool vr_prefix_contains(const vr_prefix_t *pfx, const vr_addr_t *addr)
{
    if (pfx->addr.af != addr->af) return false;
    uint8_t plen = pfx->plen;
    if (addr->af == AF_INET) {
        uint32_t mask = plen ? htonl(~0u << (32 - plen)) : 0;
        return (addr->u.v4.s_addr & mask) == (pfx->addr.u.v4.s_addr & mask);
    }
    uint8_t full = plen / 8, rem = plen % 8;
    const uint8_t *a = addr->u.v6.s6_addr, *p = pfx->addr.u.v6.s6_addr;
    if (memcmp(a, p, full) != 0) return false;
    if (!rem) return true;
    uint8_t mask = (uint8_t)(0xffu << (8 - rem));
    return (a[full] & mask) == (p[full] & mask);
}

bool vr_is_martian_v4(const struct in_addr *addr)
{
    uint32_t a = ntohl(addr->s_addr);
    if ((a >> 24) == 0)      return true;   /* 0.0.0.0/8 */
    if ((a >> 24) == 127)    return true;   /* 127.0.0.0/8 loopback */
    if ((a >> 16) == 0xa9fe) return true;   /* 169.254.0.0/16 link-local */
    if ((a >> 8)  == (0xc0000200u >> 8)) return true; /* 192.0.2.0/24 TEST-NET-1 */
    if ((a >> 8)  == (0xc6336400u >> 8)) return true; /* 198.51.100.0/24 TEST-NET-2 */
    if ((a >> 8)  == (0xcb007100u >> 8)) return true; /* 203.0.113.0/24 TEST-NET-3 */
    if ((a >> 28) == 0xf)    return true;   /* 240.0.0.0/4 reserved */
    return false;
}

bool vr_is_martian_v6(const struct in6_addr *addr)
{
    static const uint8_t lo[16]  = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    static const uint8_t any[16] = {0};
    if (memcmp(addr->s6_addr, lo,  16) == 0) return true;  /* ::1 */
    if (memcmp(addr->s6_addr, any, 16) == 0) return true;  /* :: */
    /* 2001:db8::/32 documentation prefix */
    if (addr->s6_addr[0] == 0x20 && addr->s6_addr[1] == 0x01 &&
        addr->s6_addr[2] == 0x0d && addr->s6_addr[3] == 0xb8) return true;
    return false;
}
