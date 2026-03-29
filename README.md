# Network Stack — C Implementation

## Structure

```
l3/    — Layer 3: RIB + FIB with project-cli integration
l2/    — Layer 2: 9-module L2 daemon with project-cli integration
ip/    — IP addressing + ECMP forwarding (IPv4/IPv6)
vrf/   — VRF instances with ECMP + inter-VRF route leaking
evpn/  — BGP EVPN (Type 2/3/5, EVI, VTEP, Ethernet Segment)
vxlan/ — VXLAN tunnelling (VNI, FDB, flood lists)
```

---

## Build

```bash
make          # build all daemons
make l3       # L3 only
make l2       # L2 only
make ip       # IP only
make vrf      # VRF only
make evpn     # EVPN only
make vxlan    # VXLAN only
make clean
make install  # installs to /usr/local/bin
```

### Run / Stop

```bash
make run      # start all daemons (background)
make stop     # kill all daemons
make status   # show processes + socket health
```

Individual daemons:

```bash
make run-l3   make run-l2   make run-ip
make run-vrf  make run-evpn make run-vxlan
```

---

## L3 (l3/)

Daemon: `fibd`

### Sockets
| Socket | Module |
|--------|--------|
| `$SOCK_DIR/ribd.sock` | RIB — route add/del with AD & source selection |
| `$SOCK_DIR/fibd.sock` | FIB — LPM lookup, fast forwarding plane |

### project-cli integration
- Writes `schema.json` at startup (tier-3)
- Reads/writes `runtime_config.json` for `MAX_ROUTES` (up to 524288), `DEFAULT_METRIC`
- `get`/`set` commands on both sockets

---

## L2 (l2/)

Daemon: `l2d`

```bash
./l2d -m rstp   # stp | rstp | mst
```

### Modules & Sockets
| Socket | Module | Key commands |
|--------|--------|-------------|
| `$SOCK_DIR/fdb.sock`     | FDB (hash table)    | learn, lookup, flush, age, show, stats, get/set |
| `$SOCK_DIR/rib.sock`     | L2 RIB              | add, del, show, stats, get/set |
| `$SOCK_DIR/stp.sock`     | STP/RSTP/MST        | port_up/down, bpdu, tick, mst_map, set_priority, get/set |
| `$SOCK_DIR/vlan.sock`    | VLAN DB (802.1Q)    | add, del, port_set, port_allow/deny, show |
| `$SOCK_DIR/portsec.sock` | Port Security       | configure, check, sticky, recover, show |
| `$SOCK_DIR/storm.sock`   | Storm Control       | set_rate, check, clear, show |
| `$SOCK_DIR/igmp.sock`    | IGMP Snooping       | report, leave, query, age, show, stats |
| `$SOCK_DIR/arp.sock`     | ARP/ND Snooping     | learn, lookup, age, show, stats |
| `$SOCK_DIR/lacp.sock`    | LACP (802.3ad)      | lag_add/del, member_add/del, bpdu, tick, hash, show |

### project-cli integration
- Writes `l2d_schema.json` at startup (tier-3, 9 config keys)
- Reads/writes `l2d_runtime_config.json`
- `get`/`set` on fdb, rib, stp sockets (FDB_AGE_SEC, FDB_MAX_ENTRIES, STP_MODE, STP_PRIORITY, STP_HELLO, STP_MAX_AGE, STP_FWD_DELAY, MST_REGION, MST_REVISION)

---

## IP (ip/)

Daemon: `ip_daemon`
Socket: `$SOCK_DIR/ip.sock`

IPv4/IPv6 address management and ECMP forwarding. Each forwarding entry holds up to 64 ECMP paths with weighted FNV-1a flow hashing.

### Commands
| Command | Description |
|---------|-------------|
| `add_addr` / `del_addr` / `list_addrs` | Interface address management |
| `get_interface` / `list_interfaces` / `set_if_fwd` | Interface operations |
| `add_route` / `del_route` / `list_routes` | Route management |
| `add_nexthop` / `del_nexthop` | Per-path ECMP manipulation |
| `lookup` | ECMP-aware FIB lookup (optional flow key) |
| `set_forwarding` / `get_forwarding` | Global IPv4/IPv6 forwarding toggle |
| `set_ecmp_hash` | Per-prefix hash mode (src_ip, dst_ip, src_port, dst_port, proto) |
| `get_stats` / `clear_stats` | Per-AF counters |
| `dump_config` / `load_config` | Persistence |

```bash
echo '{"cmd":"add_route","prefix":"10.0.0.0/8","nexthop":"192.168.1.1","ifindex":2}' | nc -U /tmp/ip.sock
echo '{"cmd":"lookup","dst":"10.1.2.3","src":"1.2.3.4","proto":6}' | nc -U /tmp/ip.sock
echo '{"cmd":"set_ecmp_hash","prefix":"10.0.0.0/8","mode":3}' | nc -U /tmp/ip.sock
```

---

## VRF (vrf/)

Daemon: `vrf_daemon`
Socket: `$SOCK_DIR/vrf.sock`

VRF instances with per-VRF ECMP forwarding tables and inter-VRF route leaking.

### Commands
| Command | Description |
|---------|-------------|
| `create_vrf` / `delete_vrf` / `list_vrfs` / `get_vrf` | VRF lifecycle |
| `bind_interface` / `unbind_interface` / `list_interfaces` / `get_if_vrf` | Interface binding |
| `add_route` / `del_route` / `list_routes` | Per-VRF route management |
| `add_nexthop` / `del_nexthop` | ECMP path manipulation |
| `lookup` | VRF-aware ECMP lookup |
| `set_ecmp_hash` | Per-prefix hash mode override |
| `leak_route` / `unleak_route` / `list_leaks` | Inter-VRF route leaking |
| `get_stats` / `clear_stats` | Per-VRF counters |
| `dump_config` / `load_config` | Persistence |

```bash
echo '{"cmd":"create_vrf","vrf_id":10,"name":"mgmt"}' | nc -U /tmp/vrf.sock
echo '{"cmd":"bind_interface","vrf_id":10,"ifindex":3}' | nc -U /tmp/vrf.sock
echo '{"cmd":"leak_route","src_vrf":10,"dst_vrf":1,"prefix":"192.168.0.0/24"}' | nc -U /tmp/vrf.sock
```

---

## EVPN (evpn/)

Daemon: `evpn_daemon`
Socket: `$SOCK_DIR/evpn.sock`

BGP EVPN control plane. Manages EVIs (EVI = per-VLAN service instance), VTEPs, MAC/IP bindings (Type 2), IMET routes (Type 3), IP prefixes (Type 5), and Ethernet Segments (Type 4).

### Commands
| Command | Description |
|---------|-------------|
| `create_evi` / `delete_evi` / `list_evis` / `get_evi` | EVI lifecycle |
| `set_evi_rd` / `add_evi_rt` / `del_evi_rt` | RD/RT configuration |
| `set_irb` | IRB interface binding |
| `add_vtep` / `del_vtep` / `list_vteps` | VTEP management |
| `add_mac` / `del_mac` / `learn_mac` / `list_macs` / `lookup_mac` / `flush_mac` | Type 2 MAC/IP routes |
| `add_imet` / `del_imet` / `list_imet` | Type 3 IMET routes |
| `add_prefix` / `del_prefix` / `list_prefixes` / `lookup_prefix` | Type 5 IP prefix routes |
| `add_es` / `del_es` / `list_es` | Type 4 Ethernet Segments |
| `get_stats` / `clear_stats` | Counters |
| `dump_config` / `load_config` | Persistence |

```bash
echo '{"cmd":"create_evi","evi":100,"vni":10100}' | nc -U /tmp/evpn.sock
echo '{"cmd":"add_vtep","evi":100,"vtep_ip":"10.0.0.1"}' | nc -U /tmp/evpn.sock
echo '{"cmd":"learn_mac","evi":100,"mac":"aa:bb:cc:dd:ee:ff","vtep_ip":"10.0.0.1"}' | nc -U /tmp/evpn.sock
```

---

## VXLAN (vxlan/)

Daemon: `vxlan_daemon`
Socket: `$SOCK_DIR/vxlan.sock`

VXLAN data plane. Manages VNIs, tunnels (src/dst VTEP pairs), per-VNI FDB (MAC→VTEP), and flood lists.

### Commands
| Command | Description |
|---------|-------------|
| `add_vni` / `del_vni` / `list_vnis` / `get_vni` | VNI management |
| `set_vni_flood` | Flood mode (head-end replication / multicast) |
| `add_tunnel` / `del_tunnel` / `list_tunnels` / `get_tunnel` | Tunnel management |
| `add_fdb` / `del_fdb` / `list_fdb` / `lookup_fdb` / `flush_fdb` | Per-VNI FDB |
| `add_flood` / `del_flood` / `list_flood` | Flood list entries |
| `send_frame` | Inject an encapsulated frame |
| `get_stats` / `clear_stats` | Counters |
| `dump_config` / `load_config` | Persistence |

```bash
echo '{"cmd":"add_vni","vni":10100,"local_vtep":"10.0.0.1"}' | nc -U /tmp/vxlan.sock
echo '{"cmd":"add_fdb","vni":10100,"mac":"aa:bb:cc:dd:ee:ff","remote_vtep":"10.0.0.2"}' | nc -U /tmp/vxlan.sock
echo '{"cmd":"add_flood","vni":10100,"remote_vtep":"10.0.0.2"}' | nc -U /tmp/vxlan.sock
```

---

## Common notes

- All commands use **JSON over Unix socket** (`SOCK_DIR` defaults to `/tmp`, override with `make SOCK_DIR=/var/run/vrouter`)
- All daemons respond to `{"cmd":"ping"}` on their socket
- Config persistence: each daemon writes a schema JSON at startup and supports `dump_config`/`load_config`
