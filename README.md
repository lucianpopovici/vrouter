# Network Stack — C Implementation

## Structure

```
l3/   — Layer 3: RIB + FIB with project-cli integration
l2/   — Layer 2: 9-module L2 daemon with project-cli integration
```

---

## L3 (l3/)

### Build
```bash
cd l3 && make
./fibd          # starts RIB+FIB daemon
```

### Sockets
| Socket | Module |
|--------|--------|
| `/tmp/ribd.sock` | RIB — route add/del with AD & source selection |
| `/tmp/fibd.sock` | FIB — LPM lookup, fast forwarding plane |

### project-cli integration
- Writes `schema.json` at startup (tier-3)
- Reads/writes `runtime_config.json` for `MAX_ROUTES`, `DEFAULT_METRIC`
- `get`/`set` commands on both sockets

---

## L2 (l2/)

### Build
```bash
cd l2 && make
./l2d -m rstp   # stp | rstp | mst
```

### Modules & Sockets (9 total)
| Socket | Module | Key commands |
|--------|--------|-------------|
| `/tmp/l2fdb.sock`     | FDB (hash table)    | learn, lookup, flush, age, show, stats, get/set |
| `/tmp/l2rib.sock`     | L2 RIB              | add, del, show, stats, get/set |
| `/tmp/l2stp.sock`     | STP/RSTP/MST        | port_up/down, bpdu, tick, mst_map, set_priority, get/set |
| `/tmp/l2vlan.sock`    | VLAN DB (802.1Q)    | add, del, port_set, port_allow/deny, show |
| `/tmp/l2portsec.sock` | Port Security       | configure, check, sticky, recover, show |
| `/tmp/l2storm.sock`   | Storm Control       | set_rate, check, clear, show |
| `/tmp/l2igmp.sock`    | IGMP Snooping       | report, leave, query, age, show, stats |
| `/tmp/l2arp.sock`     | ARP/ND Snooping     | learn, lookup, age, show, stats |
| `/tmp/l2lacp.sock`    | LACP (802.3ad)      | lag_add/del, member_add/del, bpdu, tick, hash, show |

### project-cli integration
- Writes `l2d_schema.json` at startup (tier-3, 9 config keys)
- Reads/writes `l2d_runtime_config.json`
- `get`/`set` on fdb, l2rib, stp sockets (FDB_AGE_SEC, FDB_MAX_ENTRIES, STP_MODE, STP_PRIORITY, STP_HELLO, STP_MAX_AGE, STP_FWD_DELAY, MST_REGION, MST_REVISION)

### All commands use JSON over Unix socket
```bash
echo '{"cmd":"ping"}' | nc -U /tmp/l2fdb.sock
echo '{"cmd":"learn","mac":"aa:bb:cc:dd:ee:ff","vlan":"10","port":"eth0","flags":"dynamic"}' | nc -U /tmp/l2fdb.sock
echo '{"cmd":"lag_add","lag":"bond0","key":"1"}' | nc -U /tmp/l2lacp.sock
echo '{"cmd":"member_add","lag":"bond0","port":"eth0","mode":"active"}' | nc -U /tmp/l2lacp.sock
```
