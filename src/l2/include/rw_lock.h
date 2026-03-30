#ifndef L2_LOCK_H
#define L2_LOCK_H

/*
 * Thin read/write lock wrappers.
 *
 * Use RD_LOCK / RD_UNLOCK for read-only operations (lookup, show, stats).
 * Use WR_LOCK / WR_UNLOCK for any mutation (add, del, flush, age).
 *
 * Multiple concurrent readers are allowed; a writer excludes everyone.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

typedef pthread_rwlock_t rw_lock_t;

static inline void rw_init(rw_lock_t *lk) {
    if (pthread_rwlock_init(lk, NULL) != 0) {
        perror("pthread_rwlock_init"); abort();
    }
}
static inline void rw_destroy(rw_lock_t *lk) {
    pthread_rwlock_destroy(lk);
}

#define RD_LOCK(lk)   pthread_rwlock_rdlock(lk)
#define RD_UNLOCK(lk) pthread_rwlock_unlock(lk)
#define WR_LOCK(lk)   pthread_rwlock_wrlock(lk)
#define WR_UNLOCK(lk) pthread_rwlock_unlock(lk)

#endif /* L2_LOCK_H */
