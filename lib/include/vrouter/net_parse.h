#ifndef VROUTER_NET_PARSE_H
#define VROUTER_NET_PARSE_H

#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <vrouter/net_types.h>

/* Parse a dotted-decimal or colon-hex address string.
 * Returns 0 on success, -1 on failure. */
int  vr_addr_parse(const char *str, vr_addr_t *out);

/* Parse a CIDR prefix string ("1.2.3.0/24" or "2001:db8::/32").
 * Returns 0 on success, -1 on failure. */
int  vr_prefix_parse(const char *str, vr_prefix_t *out);

/* Parse a colon-separated MAC address string ("aa:bb:cc:dd:ee:ff").
 * Returns 0 on success, -1 on failure. */
int  vr_mac_parse(const char *str, vr_mac_t *out);

/* Format address/prefix/MAC into a caller-supplied buffer. */
void vr_addr_to_str(const vr_addr_t *addr, char *buf, size_t len);
void vr_prefix_to_str(const vr_prefix_t *pfx, char *buf, size_t len);
void vr_mac_to_str(const vr_mac_t *mac, char *buf, size_t len);

/* Address equality. */
bool vr_addr_eq(const vr_addr_t *a, const vr_addr_t *b);

/* Returns true if addr falls within pfx. */
bool vr_prefix_contains(const vr_prefix_t *pfx, const vr_addr_t *addr);

/* Martian checks. */
bool vr_is_martian_v4(const struct in_addr *addr);
bool vr_is_martian_v6(const struct in6_addr *addr);

#endif /* VROUTER_NET_PARSE_H */
