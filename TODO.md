# vrouter — High-Priority Bug Fixes

Code review findings ranked by severity. Each task is self-contained.
Build with `make all` after each task to verify. Existing tests: `pytest && bash tests/test_l3.sh && bash tests/test_l2.sh`.

---

## Task 1: FIB data race — writes under read lock

**Bug:** `fib_lookup()` in `l3/fib.c` increments `fib->total_lookups`, `fib->total_hits`, and `entry->hit_count` while holding only a **read** lock. Multiple concurrent lookup threads will race on these counters.

**Files:** `l3/fib.h`, `l3/fib.c`, `l3/fib_ipc.c`, `tests/bench_thread.c`

**Fix:**
1. In `l3/fib.h`, add `#include <stdatomic.h>`.
2. In `fib_entry_t`, change `uint64_t hit_count` → `atomic_uint_fast64_t hit_count`.
3. In `fib_table_t`, change `uint64_t total_lookups` → `atomic_uint_fast64_t total_lookups` and same for `total_hits`.
4. In `l3/fib.c` `fib_lookup()`, replace the three direct increments with `atomic_fetch_add_explicit(&..., 1, memory_order_relaxed)`.
5. In `l3/fib.c` `fib_flush()`, use `atomic_store_explicit(&..., 0, memory_order_relaxed)` for the two counter resets.
6. In `l3/fib.c` `fib_entry_to_str()`, read `hit_count` with `atomic_load_explicit(&e->hit_count, memory_order_relaxed)`.
7. In `l3/fib_ipc.c`, every place that reads `fib->total_lookups`, `fib->total_hits`, or `e->hit_count` must use `atomic_load_explicit(... memory_order_relaxed)`. There are reads on lines 138, 158, 159.
8. In `tests/bench_thread.c`, update the `fib_lookup` call site (line 80) for the new signature from Task 2.

**Verify:** `make all` compiles clean. `bash tests/test_l3.sh` passes.

---

## Task 2: FIB use-after-free — `fib_lookup` returns pointer after releasing lock

**Bug:** `fib_lookup()` releases the rwlock, then returns a raw pointer into the pool. A concurrent `fib_del` or `fib_flush` can invalidate that pointer before the caller reads from it.

**Files:** `l3/fib.h`, `l3/fib.c`, `l3/fib_ipc.c`, `tests/bench_thread.c`

**Fix:**
1. In `l3/fib.h`, change the signature:
   ```c
   /* Old: */  const fib_entry_t *fib_lookup(fib_table_t *fib, const char *addr_str);
   /* New: */  int fib_lookup(fib_table_t *fib, const char *addr_str, fib_entry_t *out);
   ```
   Returns 0 on hit (result copied into `*out`), -1 on miss.
2. In `l3/fib.c`, rewrite `fib_lookup` to copy the found entry into `*out` **before** releasing the lock. Return 0 or -1 instead of a pointer.
3. In `l3/fib_ipc.c` (around line 99), update the caller:
   ```c
   fib_entry_t entry;
   if (fib_lookup(fib, addr, &entry) == 0) {
       /* use entry.nexthop, entry.prefix, etc. */
   ```
4. In `tests/bench_thread.c` (line 80), update:
   ```c
   fib_entry_t tmp;
   fib_lookup(&g_fib, pfx, &tmp);
   ```

---

## Task 3: FIB pool leak — deleted entries never reclaimed

**Bug:** `pool_alloc()` is a bump allocator (`pool_used++`). When `fib_del()` removes an entry, it `memset`s it to zero but the pool slot is never reused. Under route churn, `pool_used` only grows until the pool is exhausted, even if `count` is low.

**Files:** `l3/fib.h`, `l3/fib.c`

**Fix:**
1. In `fib_table_t` (in `l3/fib.h`), add a free-list head pointer:
   ```c
   fib_entry_t *free_list;    /* singly-linked reclaim list */
   ```
2. In `l3/fib.c`, rewrite `pool_alloc` to check the free-list first:
   ```c
   static fib_entry_t *pool_alloc(fib_table_t *fib)
   {
       fib_entry_t *e = NULL;
       if (fib->free_list) {
           e = fib->free_list;
           fib->free_list = e->next;
       } else if (fib->pool && fib->pool_used < fib->pool_size) {
           e = &fib->pool[fib->pool_used++];
       }
       if (e) memset(e, 0, sizeof(*e));
       return e;
   }
   ```
3. In `fib_del()`, after unlinking the entry from the bucket chain, push it onto the free-list instead of just zeroing it:
   ```c
   *pp = e->next;
   memset(e, 0, sizeof(*e));
   e->next = fib->free_list;
   fib->free_list = e;
   fib->count--;
   ```
4. In `fib_flush()`, reset `fib->free_list = NULL` (the pool memset already clears the entries).
5. In `fib_init()`, ensure `fib->free_list` starts as NULL (the `memset(fib, 0, ...)` already does this, but be explicit).

---

## Task 4: RIB use-after-free — `rib_find` returns pointer after releasing lock

**Bug:** Same pattern as Task 2 but in the RIB. `rib_find()` in `l3/rib.c` acquires rdlock, finds entry, releases lock, returns pointer. Caller in `rib_ipc.c` line 176 dereferences the pointer without any lock held.

**Files:** `l3/rib.h`, `l3/rib.c`, `l3/rib_ipc.c`

**Fix:**
1. In `l3/rib.h`, change:
   ```c
   /* Old: */  const rib_entry_t *rib_find(const rib_table_t *rib, const char *prefix_cidr);
   /* New: */  int rib_find(const rib_table_t *rib, const char *prefix_cidr, rib_entry_t *out);
   ```
   Returns 0 on hit, -1 on miss.
2. In `l3/rib.c`, rewrite `rib_find` to copy the entry into `*out` under the lock:
   ```c
   int rib_find(const rib_table_t *rib, const char *prefix_cidr, rib_entry_t *out)
   {
       uint32_t pfx; uint8_t len;
       if (fib_parse_cidr(prefix_cidr, &pfx, &len) != 0) return -1;
       pthread_rwlock_rdlock((pthread_rwlock_t *)&rib->lock);
       rib_entry_t *e = entry_find_locked((rib_table_t *)rib, pfx, len);
       int rc = -1;
       if (e && out) { *out = *e; rc = 0; }
       pthread_rwlock_unlock((pthread_rwlock_t *)&rib->lock);
       return rc;
   }
   ```
3. In `l3/rib_ipc.c`, update the `get` handler (around line 176):
   ```c
   rib_entry_t entry;
   if (rib_find(rib, prefix, &entry) != 0) {
       snprintf(resp, rsz, "{\"status\": \"miss\", ...}");
       return;
   }
   /* use entry.prefix, entry.candidates, etc. */
   ```

---

## Task 5: RIB pool leak — same as FIB

**Bug:** Same bump-only allocator as FIB. `rib_del()` unlinks entries but never returns them to the pool. With BGP churn this will exhaust the 1M-entry pool.

**Files:** `l3/rib.h`, `l3/rib.c`

**Fix:** Same free-list pattern as Task 3.
1. Add `rib_entry_t *free_list;` to `rib_table_t` in `l3/rib.h`.
2. Rewrite `pool_alloc` in `l3/rib.c` to try free-list first.
3. In `rib_del()`, when `entry->n_candidates == 0` and the entry is unlinked from the bucket chain, push it onto the free-list:
   ```c
   if (entry->n_candidates == 0) {
       uint32_t idx = rib_hash(pfx, len, rib->n_buckets);
       rib_entry_t **pp = &rib->buckets[idx];
       while (*pp && *pp != entry) pp = &(*pp)->next;
       if (*pp) {
           *pp = entry->next;
           rib->count--;
           /* reclaim to free-list */
           memset(entry, 0, sizeof(*entry));
           entry->next = rib->free_list;
           rib->free_list = entry;
       }
   }
   ```
4. In the flush path (in `rib_ipc.c` handle_cmd or wherever flush resets the table), reset `rib->free_list = NULL`.

---

## Task 6: RIB IPC flush handler — no write lock

**Bug:** The `flush` branch in `handle_cmd()` in `l3/rib_ipc.c` (around line 229) iterates `rib->buckets[]`, calls `push_to_fib()`, then zeroes `rib->pool` and resets `rib->pool_used` — all without holding the RIB write lock. This is a data race with any concurrent `rib_add`/`rib_del`.

**Files:** `l3/rib_ipc.c`

**Fix:** Wrap the entire flush block in `pthread_rwlock_wrlock(&rib->lock)` / `pthread_rwlock_unlock(&rib->lock)`:
```c
} else if (strcmp(cmd, "flush") == 0) {
    pthread_rwlock_wrlock(&rib->lock);
    for (uint32_t _b = 0; _b < rib->n_buckets; _b++) {
        rib_entry_t *e = rib->buckets[_b];
        while (e) {
            const rib_candidate_t *b = rib_best(e);
            if (b) push_to_fib(e, b, 0, fib);
            e = e->next;
        }
        rib->buckets[_b] = NULL;
    }
    memset(rib->pool, 0, rib->pool_used * sizeof(rib_entry_t));
    rib->pool_used = 0;
    rib->count = 0;
    rib->free_list = NULL;   /* after Task 5 adds free_list */
    pthread_rwlock_unlock(&rib->lock);
    snprintf(resp, rsz, "{\"status\": \"ok\", \"msg\": \"rib flushed\"}");
```

**Note:** `push_to_fib()` calls `fib_add`/`fib_del` which acquire the FIB write lock internally. Since the RIB lock and FIB lock are independent, this is safe (no nested same-lock). Just ensure lock ordering is always RIB-then-FIB if both are ever needed.

---

## Task 7: FDB data race — same pattern as FIB

**Bug:** `fdb_lookup()` in `l2/fdb.c` increments `fdb->total_lookups`, `fdb->total_hits`, `fdb->total_misses`, and `e->hit_count` while holding only a **read** lock. Same race as FIB Task 1.

**Files:** `l2/fdb.h`, `l2/fdb.c`, `l2/fdb_ipc.c`, `tests/bench_thread.c`

**Fix:**
1. In `l2/fdb.h`, add `#include <stdatomic.h>`.
2. Change `hit_count` in `fdb_entry_t` to `atomic_uint_fast64_t`.
3. Change `total_lookups`, `total_hits`, `total_misses`, `entries_aged` in `fdb_table_t` to `atomic_uint_fast64_t`.
4. In `l2/fdb.c` `fdb_lookup()`, use `atomic_fetch_add_explicit` for all counter increments.
5. In `l2/fdb.c` `fdb_age_sweep()`, use `atomic_fetch_add_explicit` for `fdb->entries_aged++`.
6. In `l2/fdb_ipc.c`, use `atomic_load_explicit` for all reads of these counters (lines 70, 120, 134-137).
7. In `tests/bench_thread.c` (line 129), update for the new `fdb_lookup` copy-out signature (Task 8).

---

## Task 8: FDB use-after-free — `fdb_lookup` returns pointer after releasing lock

**Bug:** Same pattern as FIB/RIB. `fdb_lookup()` returns a raw pointer after releasing the rwlock.

**Files:** `l2/fdb.h`, `l2/fdb.c`, `l2/fdb_ipc.c`, `tests/bench_thread.c`

**Fix:**
1. In `l2/fdb.h`, change signature:
   ```c
   /* Old: */  const fdb_entry_t *fdb_lookup(fdb_table_t *fdb, const uint8_t mac[6], uint16_t vlan);
   /* New: */  int fdb_lookup(fdb_table_t *fdb, const uint8_t mac[6], uint16_t vlan, fdb_entry_t *out);
   ```
   Returns 0 on hit (copied into `*out`), -1 on miss.
2. In `l2/fdb.c`, rewrite `fdb_lookup` to copy the result into `*out` before releasing the lock.
3. In `l2/fdb_ipc.c` (around line 65), update the caller:
   ```c
   fdb_entry_t entry;
   if (fdb_lookup(fdb, mac, vlan, &entry) == 0) {
       /* use entry.port, entry.hit_count, etc. */
   ```
4. In `tests/bench_thread.c` (line 129), update:
   ```c
   fdb_entry_t tmp;
   fdb_lookup(&g_fdb, mac, vlan, &tmp);
   ```

---

## Task 9: FDB pool leak — deleted entries never reclaimed

**Bug:** Same as FIB/RIB. `fdb_delete()`, `fdb_flush_port()`, `fdb_flush_vlan()`, and `fdb_age_sweep()` all unlink entries and `memset` them but never return them to a free-list. `pool_used` only grows.

**Files:** `l2/fdb.h`, `l2/fdb.c`

**Fix:**
1. Add `fdb_entry_t *free_list;` to `fdb_table_t` in `l2/fdb.h`.
2. Rewrite `pool_alloc` in `l2/fdb.c` to check `fdb->free_list` first, then fall back to bump allocation.
3. In every function that removes entries (`fdb_delete`, `fdb_flush_port`, `fdb_flush_vlan`, `fdb_age_sweep`), after `memset(e, 0, ...)`, push `e` onto `fdb->free_list`:
   ```c
   memset(e, 0, sizeof(*e));
   e->next = fdb->free_list;
   fdb->free_list = e;
   ```
4. In `fdb_flush_all()`, reset `fdb->free_list = NULL` (the full pool memset handles the rest).
5. In `fdb_init()`, ensure `free_list` starts NULL.

---

## Task 10: `static const` arrays duplicated per translation unit

**Bug:** `RIB_DEFAULT_AD[]` and `RIB_SRC_NAME[]` are defined as `static const` in `l3/rib.h`. Every `.c` file that includes `rib.h` gets its own copy of these arrays in its `.rodata` section, wasting memory and potentially confusing debuggers.

**Files:** `l3/rib.h`, `l3/rib.c`

**Fix:**
1. In `l3/rib.h`, change the definitions to `extern` declarations:
   ```c
   extern const uint8_t    RIB_DEFAULT_AD[RIB_SRC_COUNT];
   extern const char *const RIB_SRC_NAME[RIB_SRC_COUNT];
   ```
2. In `l3/rib.c`, add the actual definitions (move the initializer bodies from rib.h):
   ```c
   const uint8_t RIB_DEFAULT_AD[RIB_SRC_COUNT] = {
       [RIB_SRC_CONNECTED] =   0,
       [RIB_SRC_STATIC]    =   1,
       [RIB_SRC_EBGP]      =  20,
       [RIB_SRC_OSPF]      = 110,
       [RIB_SRC_IBGP]      = 200,
       [RIB_SRC_UNKNOWN]   = 255,
   };
   const char *const RIB_SRC_NAME[RIB_SRC_COUNT] = {
       [RIB_SRC_CONNECTED] = "connected",
       [RIB_SRC_STATIC]    = "static",
       [RIB_SRC_EBGP]      = "ebgp",
       [RIB_SRC_OSPF]      = "ospf",
       [RIB_SRC_IBGP]      = "ibgp",
       [RIB_SRC_UNKNOWN]   = "unknown",
   };
   ```

---

## Task 11: Duplicated `jget` JSON parser — extract to shared utility

**Bug:** The same ~20-line `jget()` function is copy-pasted in `l3/rib_ipc.c`, `l3/fib_ipc.c`, `l3/persist.c`, `l2/fdb_ipc.c`, `l2/l2rib_ipc.c`, and several other IPC files. Any bug fix must be applied N times.

**Files:** New `l3/json_util.h` + `l3/json_util.c`, then update all files that define their own `jget`.

**Fix:**
1. Create `l3/json_util.h`:
   ```c
   #ifndef JSON_UTIL_H
   #define JSON_UTIL_H
   #include <stddef.h>
   /* Extract a string or numeric field from a flat JSON object.
    * Returns 0 on success, -1 if key not found.
    * Does NOT handle nested objects, arrays, or escaped quotes. */
   int jget(const char *json, const char *key, char *buf, size_t sz);
   #endif
   ```
2. Create `l3/json_util.c` with the implementation (copy from any of the existing `jget`s).
3. In each file that has its own `static int jget(...)`, remove the local copy and `#include "json_util.h"` instead. Files to update:
   - `l3/rib_ipc.c`
   - `l3/fib_ipc.c`
   - `l3/persist.c`
   - `l2/fdb_ipc.c`
   - `l2/l2rib_ipc.c`
   - `l2/stp_ipc.c` (check if it has one)
   - `l2/l2_ipc_extra.c` (check if it has one)
4. Update `l3/Makefile` and `l2/Makefile` to compile and link `json_util.c`.
   For `l2/`, either symlink or add an include path to `../l3/json_util.h`.

---

## Task 12: Add sanitizer CI job

**Bug:** No AddressSanitizer or UndefinedBehaviorSanitizer builds in CI. The data races and potential use-after-free bugs above would have been caught by ASan/UBSan/TSan.

**Files:** `.github/workflows/ci.yml`

**Fix:** Add a new job after `build-strict`:
```yaml
  build-sanitizers:
    name: Build (ASan + UBSan)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Install dependencies
        run: sudo apt-get update -qq && sudo apt-get install -y gcc make
      - name: Build L3 with sanitizers
        working-directory: l3
        run: make -j$(nproc) CFLAGS="-Wall -Wextra -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L" LDFLAGS="-fsanitize=address,undefined"
      - name: Build L2 with sanitizers
        working-directory: l2
        run: make -j$(nproc) CFLAGS="-Wall -Wextra -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L -Wno-unused-function" LDFLAGS="-fsanitize=address,undefined"
```

**Note:** Tasks 1-9 require `<stdatomic.h>` which is C11. Update the `-std=c99` in `build-strict` to `-std=c11` as well, or use GCC `__atomic` builtins if you want to stay on C99. The sub-Makefiles may also need their default `CFLAGS` bumped to `-std=c11`.

---

## Task 13: Add missing daemon binaries to CI upload

**Bug:** The `upload-artifact` step in CI only uploads `l3/fibd`, `l2/l2d`, `ip/ip_daemon`. The `vrf_daemon`, `evpn_daemon`, and `vxlan_daemon` binaries are built but never tested.

**Files:** `.github/workflows/ci.yml`

**Fix:** In the `build-c` job's upload step, add the missing binaries:
```yaml
      - name: Upload binaries
        uses: actions/upload-artifact@v4
        with:
          name: binaries
          path: |
            l3/fibd
            l2/l2d
            ip/ip_daemon
            vrf/vrf_daemon
            evpn/evpn_daemon
            vxlan/vxlan_daemon
          retention-days: 1
```

---

## Recommended task order

1. **Task 10** (rib.h static const) — trivial, no API changes
2. **Task 6** (rib_ipc flush locking) — trivial, one block
3. **Tasks 1+2+3** (FIB: atomics + copy-out + free-list) — do together, they touch the same files
4. **Tasks 4+5** (RIB: copy-out + free-list) — same pattern as FIB
5. **Tasks 7+8+9** (FDB: atomics + copy-out + free-list) — same pattern
6. **Task 11** (jget dedup) — mechanical refactor
7. **Tasks 12+13** (CI) — independent

After all tasks, run `make clean && make all` and `pytest && bash tests/test_l3.sh && bash tests/test_l2.sh && bash tests/test_persist.sh` to confirm nothing is broken.
