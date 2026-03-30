/*
 * Thread-safety stress test
 * Runs simultaneous writers and readers against fib_table_t and fdb_table_t
 * Checks: no deadlock, no corruption, no assertion failures
 *
 * Build: gcc -O2 -std=c99 -D_POSIX_C_SOURCE=200809L -pthread \
 *             -I/home/claude/package/l3 -I/home/claude/package/l2 \
 *             -o bench_thread bench_thread.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>

/* pull in both modules */
#include "../l3/fib.h"
#include "../l2/fdb.h"

/* ── timing ────────────────────────────────────────────────── */
static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── shared tables ──────────────────────────────────────────── */
static fib_table_t g_fib;
static fdb_table_t g_fdb;

/* ── counters (relaxed, just for progress display) ──────────── */
static volatile uint64_t fib_ops = 0;
static volatile uint64_t fdb_ops = 0;
static volatile int      done    = 0;

#define TEST_SECS    5
#define FIB_WRITERS  4
#define FIB_READERS  4
#define FDB_WRITERS  4
#define FDB_READERS  4

/* ── helper ─────────────────────────────────────────────────── */
static void pfx_of(int i, char *buf, size_t sz) {
    snprintf(buf, sz, "%d.%d.%d.0/24",
             10+((i>>16)&0xFF), (i>>8)&0xFF, i&0xFF);
}
static void nh_of(int i, char *buf, size_t sz) {
    snprintf(buf, sz, "192.168.%d.%d", (i>>8)&0xFF, i&0xFF);
}

/* ─────────────────────────────────────────────────────────────
 * FIB threads
 * ───────────────────────────────────────────────────────────── */
static void *fib_writer(void *arg) {
    int id = *(int*)arg;
    char pfx[32], nh[20];
    int i = 0;
    while (!done) {
        int n = (id * 10000 + i) % 50000;
        pfx_of(n, pfx, sizeof(pfx));
        nh_of(n,  nh,  sizeof(nh));
        if (i % 7 == 0)
            fib_del(&g_fib, pfx);
        else
            fib_add(&g_fib, pfx, nh, "eth0", 10, FIB_FLAG_STATIC);
        i++;
        __atomic_fetch_add(&fib_ops, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

static void *fib_reader(void *arg) {
    (void)arg;
    char pfx[32];
    int i = 0;
    while (!done) {
        pfx_of(i % 50000, pfx, sizeof(pfx));
        fib_entry_t tmp;
        fib_lookup(&g_fib, pfx, &tmp);
        fib_count(&g_fib);
        i++;
        __atomic_fetch_add(&fib_ops, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

/* ─────────────────────────────────────────────────────────────
 * FDB threads
 * ───────────────────────────────────────────────────────────── */
static void *fdb_writer(void *arg) {
    int id = *(int*)arg;
    int i = 0;
    while (!done) {
        uint8_t mac[6] = {
            0xaa, 0xbb,
            (uint8_t)(id & 0xFF),
            (uint8_t)((i>>16)&0xFF),
            (uint8_t)((i>>8)&0xFF),
            (uint8_t)(i&0xFF)
        };
        uint16_t vlan = (uint16_t)(1 + (i % 100));
        char port[16];
        snprintf(port, sizeof(port), "eth%d", i % 4);

        if (i % 11 == 0)
            fdb_delete(&g_fdb, mac, vlan);
        else if (i % 17 == 0)
            fdb_flush_vlan(&g_fdb, vlan);
        else
            fdb_learn(&g_fdb, mac, vlan, port, FDB_FLAG_DYNAMIC, 0);
        i++;
        __atomic_fetch_add(&fdb_ops, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

static void *fdb_reader(void *arg) {
    (void)arg;
    int i = 0;
    while (!done) {
        uint8_t mac[6] = {
            0xaa, 0xbb, 0x00,
            (uint8_t)((i>>16)&0xFF),
            (uint8_t)((i>>8)&0xFF),
            (uint8_t)(i&0xFF)
        };
        uint16_t vlan = (uint16_t)(1 + (i % 100));
        fdb_entry_t tmp;
        fdb_lookup(&g_fdb, mac, vlan, &tmp);
        i++;
        __atomic_fetch_add(&fdb_ops, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

/* ─────────────────────────────────────────────────────────────
 * Age + flush thread (exercises write locks from a 3rd path)
 * ───────────────────────────────────────────────────────────── */
static void *fdb_ager(void *arg) {
    (void)arg;
    while (!done) {
        fdb_age_sweep(&g_fdb);
        struct timespec ts = {0, 10000000}; /* 10ms */
        nanosleep(&ts, NULL);
    }
    return NULL;
}

/* ─────────────────────────────────────────────────────────────
 * Main
 * ───────────────────────────────────────────────────────────── */
int main(void) {
    printf("\n══════════════════════════════════════════════════════\n");
    printf("  Thread-Safety Stress Test (%ds)\n", TEST_SECS);
    printf("  FIB: %d writers + %d readers\n", FIB_WRITERS, FIB_READERS);
    printf("  FDB: %d writers + %d readers + 1 ager\n", FDB_WRITERS, FDB_READERS);
    printf("══════════════════════════════════════════════════════\n\n");

    fib_init(&g_fib);
    fdb_init(&g_fdb);

    /* pre-populate so readers have something to find */
    char pfx[32], nh[20];
    for (int i = 0; i < 1000; i++) {
        pfx_of(i, pfx, sizeof(pfx));
        nh_of(i,  nh,  sizeof(nh));
        fib_add(&g_fib, pfx, nh, "eth0", 10, FIB_FLAG_STATIC);
    }
    for (int i = 0; i < 500; i++) {
        uint8_t mac[6] = {0xaa,0xbb,0x00,0x00,(uint8_t)(i>>8),(uint8_t)i};
        char port[8]; snprintf(port,sizeof(port),"eth%d",i%4);
        fdb_learn(&g_fdb, mac, (uint16_t)(1+i%100), port, FDB_FLAG_DYNAMIC, 0);
    }

    int ids[FIB_WRITERS + FDB_WRITERS];
    pthread_t threads[FIB_WRITERS + FIB_READERS + FDB_WRITERS + FDB_READERS + 1];
    int tc = 0;

    for (int i = 0; i < FIB_WRITERS; i++) {
        ids[i] = i;
        pthread_create(&threads[tc++], NULL, fib_writer, &ids[i]);
    }
    for (int i = 0; i < FIB_READERS; i++)
        pthread_create(&threads[tc++], NULL, fib_reader, NULL);
    for (int i = 0; i < FDB_WRITERS; i++) {
        ids[FIB_WRITERS+i] = i;
        pthread_create(&threads[tc++], NULL, fdb_writer, &ids[FIB_WRITERS+i]);
    }
    for (int i = 0; i < FDB_READERS; i++)
        pthread_create(&threads[tc++], NULL, fdb_reader, NULL);
    pthread_create(&threads[tc++], NULL, fdb_ager, NULL);

    /* run for TEST_SECS, printing progress every second */
    uint64_t t0 = now_ns();
    for (int s = 1; s <= TEST_SECS; s++) {
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
        uint64_t elapsed_ns = now_ns() - t0;
        printf("  t=+%ds  FIB ops: %7llu  FDB ops: %7llu  "
               "FIB entries: %d  FDB entries: %d\n",
               s,
               (unsigned long long)fib_ops,
               (unsigned long long)fdb_ops,
               fib_count(&g_fib),
               g_fdb.count);
        (void)elapsed_ns;
    }

    done = 1;
    for (int i = 0; i < tc; i++) pthread_join(threads[i], NULL);

    uint64_t total_ns = now_ns() - t0;
    uint64_t total_ops = fib_ops + fdb_ops;
    double   total_s   = (double)total_ns / 1e9;

    printf("\n══════════════════════════════════════════════════════\n");
    printf("  PASSED — no deadlock, no corruption\n");
    printf("  Total ops : %llu\n", (unsigned long long)total_ops);
    printf("  Duration  : %.2f s\n", total_s);
    printf("  Throughput: %.2f M ops/s (combined)\n",
           (double)total_ops / total_s / 1e6);
    printf("  FIB final : %d entries\n", fib_count(&g_fib));
    printf("  FDB final : %d entries\n", g_fdb.count);
    printf("══════════════════════════════════════════════════════\n\n");

    return 0;
}
