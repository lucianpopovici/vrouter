# vrouter — Network Stack (C Implementation)

A multi-daemon network stack with L2 (FDB, STP, LACP, VLAN, port-security) and L3 (RIB, FIB, IP, VRF, EVPN, VXLAN) support, controlled via Unix-domain socket IPC.

---

## Directory layout

```
vrouter/
├── lib/                  # Shared C library (libvrouter.a)
│   ├── include/vrouter/  # hash.h, json.h, net_types.h, net_parse.h, ipc_server.h
│   └── src/              # json.c, net_parse.c, ipc_server.c
│
├── src/                  # Daemon modules
│   ├── l2/               # L2 daemon (l2d): FDB, STP, LACP, VLAN, port-security, storms, IGMP
│   ├── l3/               # L3 daemon (fibd): RIB + FIB
│   ├── ip/               # IP daemon: IPv4/IPv6 addressing + ECMP forwarding
│   ├── vrf/              # VRF daemon: VRF instances + inter-VRF route leaking
│   ├── evpn/             # EVPN daemon: BGP EVPN (Type 2/3/5, EVI, VTEP, ES)
│   └── vxlan/            # VXLAN daemon: VNI, FDB, flood lists
│
├── python/               # Python control plane
│   ├── bfd/              # BFD session management
│   ├── lldp/             # LLDP
│   ├── modules/          # Orchestrator modules
│   ├── main.py           # Control plane entry point
│   └── project-cli       # CLI tool
│
├── tests/
│   ├── unit/             # C unit tests (test_ip, test_vrf, test_evpn, test_vxlan)
│   ├── integration/      # Shell integration tests (test_l3.sh, test_l2.sh, test_persist.sh)
│   ├── python/           # Python unit tests (pytest)
│   └── bench/            # Benchmark (bench_thread.c)
│
├── config/               # Schema + default config files
├── build/                # All build output (gitignored)
│   ├── bin/              # Daemon binaries
│   ├── lib/              # libvrouter.a
│   ├── obj/              # Object files
│   └── tests/            # Test binaries
│
├── Makefile              # Root: orchestrates everything
└── common.mk             # Shared compiler flags + paths
```

---

## Build

```bash
make              # build lib + all daemons + tests
make lib          # shared library only
make daemons      # all daemon binaries
make MODE=debug   # build with ASan + UBSan + debug symbols
make clean        # remove build/
make install      # install binaries to /usr/sbin (DESTDIR supported)
```

All output lands in `build/`:
- `build/bin/fibd`, `l2d`, `ip_daemon`, `vrf_daemon`, `evpn_daemon`, `vxlan_daemon`
- `build/lib/libvrouter.a`
- `build/tests/test_ip`, `test_vrf`, `test_evpn`, `test_vxlan`

---

## Run / Stop

```bash
make run            # start all daemons (sockets in /tmp/vrouter/)
make stop           # kill all daemons
make status         # list active sockets

# Or individually:
build/bin/fibd      -S /tmp/vrouter &
build/bin/l2d       -m rstp -S /tmp/vrouter &
build/bin/ip_daemon -S /tmp/vrouter &
```

---

## Tests

```bash
make test-c             # run C unit test binaries
make test-py            # run Python tests via pytest
make test-integration   # run shell integration tests
make test-all           # run everything
```

Individual tests:
```bash
bash tests/integration/test_l3.sh
bash tests/integration/test_l2.sh
bash tests/integration/test_persist.sh
cd tests && python -m pytest python/ -v
```

---

## IPC protocol

Each daemon listens on a Unix-domain socket. Commands are flat JSON objects; responses are flat JSON objects.

Example (L3 FIB):
```bash
echo '{"cmd":"add","prefix":"10.0.0.0/8","nexthop":"1.2.3.4","iface":"eth0"}' \
  | nc -U /tmp/vrouter/fibd.sock
# → {"status": "ok", "msg": "route 10.0.0.0/8 added"}

echo '{"cmd":"lookup","addr":"10.1.2.3"}' | nc -U /tmp/vrouter/fibd.sock
# → {"status": "ok", "prefix": "10.0.0.0/8", "nexthop": "1.2.3.4", ...}
```

---

## Shared library (`lib/`)

`libvrouter.a` provides utilities shared by all modules:

| Header | Purpose |
|--------|---------|
| `<vrouter/hash.h>` | FNV-1a hash (`vr_fnv1a`, `vr_fnv1a_mod`) — header-only |
| `<vrouter/json.h>` | Flat JSON parser (`vr_json_get_str/int/bool`) |
| `<vrouter/net_types.h>` | Shared types: `vr_addr_t`, `vr_prefix_t`, `vr_mac_t` |
| `<vrouter/net_parse.h>` | Address/prefix/MAC parse + format + compare |
| `<vrouter/ipc_server.h>` | Generic Unix-socket accept loop |
