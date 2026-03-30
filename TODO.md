# vrouter — Bug Fix TODO

All tasks completed. See `CLAUDE.md` for full details on each fix.

## Status

| # | Description | Status |
|---|-------------|--------|
| 1 | FIB data race — atomics for `hit_count`, `total_lookups`, `total_hits` | ✅ Done |
| 2 | FIB use-after-free — `fib_lookup` copy-out before releasing lock | ✅ Done |
| 3 | FIB pool leak — free-list reclaim in `pool_alloc` / `fib_del` | ✅ Done |
| 4 | RIB use-after-free — `rib_find` copy-out before releasing lock | ✅ Done |
| 5 | RIB pool leak — free-list reclaim in `pool_alloc` / `rib_del` | ✅ Done |
| 6 | RIB IPC flush handler — wrap in write lock | ✅ Done |
| 7 | FDB data race — atomics for all FDB counters | ✅ Done |
| 8 | FDB use-after-free — `fdb_lookup` copy-out before releasing lock | ✅ Done |
| 9 | FDB pool leak — free-list reclaim in all delete paths | ✅ Done |
| 10 | `static const` arrays duplicated per TU — change to `extern` in `rib.h` | ✅ Done |
| 11 | Duplicated `jget` — extracted to `l3/json_util.c` shared utility | ✅ Done |
| 12 | Add ASan + UBSan CI job; bump to `-std=c11` | ✅ Done |
| 13 | Add missing daemon binaries to CI artifact upload | ✅ Done |
