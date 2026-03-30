#ifndef VROUTER_NET_TYPES_H
#define VROUTER_NET_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* Unified address type (IPv4 or IPv6). */
typedef struct vr_addr {
    sa_family_t af;
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } u;
} vr_addr_t;

/* Unified prefix type. */
typedef struct vr_prefix {
    vr_addr_t addr;
    uint8_t   plen;
} vr_prefix_t;

/* MAC address. */
typedef struct vr_mac {
    uint8_t b[6];
} vr_mac_t;

#endif /* VROUTER_NET_TYPES_H */
