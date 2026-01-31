#ifndef DATABASE_H
#define DATABASE_H

#include "lmdb.h"
#include "log.h"
#include <string.h>
#include <sys/mount.h>

#if defined (__linux__)
#include <sys/statfs.h>
#include <stdint.h>
#endif

static inline int database_error(const char *label, int rc) {
    if (rc != MDB_SUCCESS)
        LOG_ERROR("%sLMDB error %d: %s", label, rc, mdb_strerror(rc));
    return rc;
}

static inline size_t detect_disk_60percent(const char *path) {
    struct statfs sf;
    if (statfs(path, &sf) != 0) {
        return (size_t)1 << 40;
    }
    uint64_t total_bytes = (uint64_t)sf.f_blocks * sf.f_bsize;
    return (size_t)(total_bytes * 6 / 10);
}

static inline size_t detect_disk_30percent(const char *path) {
    struct statfs sf;
    if (statfs(path, &sf) != 0) {
        return (size_t)1 << 40;
    }
    uint64_t total_bytes = (uint64_t)sf.f_blocks * sf.f_bsize;
    return (size_t)(total_bytes * 3 / 10);
}

static inline int database_init_env(
        const char *label,
        MDB_env **env,
        const char *path,
        size_t mapsize,
        unsigned maxdbs
        )
{
    int rc;
    rc = mdb_env_create(env);
    if (database_error(label, rc)) return rc;
    size_t final_mapsize = mapsize;
    if (final_mapsize == (size_t)-2) {
        final_mapsize = detect_disk_60percent(path);
    }
    if (final_mapsize == (size_t)-1) {
        final_mapsize = detect_disk_30percent(path);
    }
    rc = mdb_env_set_mapsize(*env, final_mapsize);
    if (database_error(label, rc)) return rc;
    rc = mdb_env_set_maxdbs(*env, maxdbs);
    if (database_error(label, rc)) return rc;
    rc = mdb_env_open(*env, path, 0, 0644);
    return database_error(label, rc);
}

static inline void database_deinit_env(
        const char *label,
        MDB_env **env
        )
{
    if (env && *env) {
        mdb_env_close(*env);
        *env = NULL;
        LOG_INFO("%s: LMDB environment closed successfully.", label);
    }
}

static inline int database_open(
        const char *label,
        MDB_env *env,
        MDB_dbi *dbi,
        const char *name,
        unsigned flags
        )
{
    MDB_txn *txn = NULL;
    int rc;

    rc = mdb_txn_begin(env, NULL, 0, &txn);
    if (database_error(label, rc)) return rc;

    rc = mdb_dbi_open(txn, name, MDB_CREATE | flags, dbi);
    if (rc != MDB_SUCCESS) {
        mdb_txn_abort(txn);
        return database_error(label, rc);
    }

    rc = mdb_txn_commit(txn);
    return database_error(label, rc);
}

static inline void database_close(
	    MDB_env *env,
        MDB_dbi dbi
        )
{
    if (env) {
        mdb_dbi_close(env, dbi);
    }
}

static inline int database_txn_begin(
        const char *label,
        MDB_env *env,
        MDB_txn **t
        )
{
    return database_error(
            label,
            mdb_txn_begin(
                env,
                NULL,
                0,
                t
                )
            );
}

static inline int database_txn_commit(
        const char *label,
        MDB_txn **t
        )
{
    MDB_txn *txn = *t;
    *t = NULL;
	int rc = mdb_txn_commit(txn);
    txn = NULL;
    return database_error(label, rc);
}

static inline void database_txn_abort(MDB_txn **t) {
    MDB_txn *txn = *t;
    *t = NULL;
    if (txn) {
        mdb_txn_abort(txn);
        txn = NULL;
    }
}

static inline int database_txn_put(
        const char *label,
        MDB_txn *txn,
        MDB_dbi dbi,
        const void *key, size_t klen,
        const void *val, size_t vlen,
        unsigned flags
        )
{
    MDB_val k = { klen, (void *)key };
    MDB_val v = { vlen, (void *)val };
    return database_error(label, mdb_put(txn, dbi, &k, &v, flags));
}

static inline int database_txn_get(
        MDB_txn *txn,
        MDB_dbi dbi,
        const void *key,
        size_t klen,
        MDB_val *out
        )
{
    MDB_val k = { klen, (void *)key };
    return mdb_get(txn, dbi, &k, out);
}

static inline int database_txn_del(
        const char *label,
        MDB_txn *txn,
        MDB_dbi dbi,
        const void *key,
        size_t klen
        )
{
    MDB_val k = { klen, (void *)key };
    return database_error(label, mdb_del(txn, dbi, &k, NULL));
}

static inline int database_cursor_open(
        const char *label,
        MDB_txn *txn,
        MDB_dbi dbi,
        MDB_cursor **c
        )
{
    return database_error(label, mdb_cursor_open(txn, dbi, c));
}

static inline void database_cursor_close(MDB_cursor **c) {
    MDB_cursor *cur = *c;
    *c = NULL;
    if (cur) {
        mdb_cursor_close(cur);
        cur = NULL;
    }
}

static inline int database_cursor_get_first(MDB_cursor *cur, MDB_val *k, MDB_val *v) {
    return mdb_cursor_get(cur, k, v, MDB_FIRST);
}

static inline int database_cursor_get_last(MDB_cursor *cur, MDB_val *k, MDB_val *v) {
    return mdb_cursor_get(cur, k, v, MDB_LAST);
}

static inline int database_cursor_get_next(MDB_cursor *cur, MDB_val *k, MDB_val *v) {
    return mdb_cursor_get(cur, k, v, MDB_NEXT);
}

static inline int database_cursor_get_prev(MDB_cursor *cur, MDB_val *k, MDB_val *v) {
    return mdb_cursor_get(cur, k, v, MDB_PREV);
}

static inline int database_cursor_find(
        MDB_cursor *cur,
        const void *key,
        size_t klen,
        MDB_val *outk,
        MDB_val *outv
        )
{
    MDB_val k = { klen, (void *)key };
    int rc = mdb_cursor_get(cur, &k, outv, MDB_SET_RANGE);
    if (rc == MDB_SUCCESS)
        *outk = k;
    return rc;
}

static inline int database_cursor_find_prefix(
        MDB_cursor *cur,
        const void *prefix,
        size_t plen,
        MDB_val *outk,
        MDB_val *outv
        )
{
    MDB_val k = { plen, (void *)prefix };
    int rc = mdb_cursor_get(cur, &k, outv, MDB_SET_RANGE);
    if (rc != MDB_SUCCESS)
        return rc;

    *outk = k;

    if (outk->mv_size < plen ||
            memcmp(outk->mv_data, prefix, plen) != 0)
        return MDB_NOTFOUND;

    return MDB_SUCCESS;
}

#endif
