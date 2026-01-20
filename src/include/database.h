#ifndef DATABASE_H
#define DATABASE_H

#include <stdio.h>
#include <string.h>
#include <lmdb.h>
#include <stdint.h>

#if defined(__OpenBSD__) || defined(__NetBSD__)
    #include <sys/errno.h>
	#include <sys/mount.h>
#endif

#include "oritlsf.h"
#include "log.h"

typedef struct {
    MDB_txn *txn;
} database_txn_t;

typedef struct {
    MDB_cursor *cur;
} database_cursor_t;

static inline int database_error(const char *label, int rc) {
    if (rc != MDB_SUCCESS)
        LOG_ERROR("%sLMDB error %d: %s", label, rc, mdb_strerror(rc));
    return rc;
}

static inline size_t detect_disk_80percent(const char *path) {
    struct statfs sf;
    if (statfs(path, &sf) != 0) {
        return (size_t)1 << 40;
    }
    uint64_t total_bytes = (uint64_t)sf.f_blocks * sf.f_bsize;
    return (size_t)(total_bytes * 8 / 10);
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
    if (final_mapsize == (size_t)-1) {
        final_mapsize = detect_disk_80percent(path);
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
    MDB_txn *txn;
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
    database_txn_t *t
) 
{
    return database_error(
        label,
        mdb_txn_begin(
            env,
            NULL,
            0,
            &t->txn
        )
    );
}

static inline int database_txn_commit(
    const char *label,
    database_txn_t *t
) 
{
	int rc = mdb_txn_commit(t->txn);
    t->txn = NULL;
    return database_error(label, rc);
}

static inline void database_txn_abort(database_txn_t *t) {
    if (t && t->txn) {
        mdb_txn_abort(t->txn);
        t->txn = NULL;
    }
}

static inline int database_batch_begin(
    const char *label,
    MDB_env *env,
    database_txn_t *t
) 
{
    return database_txn_begin(label, env, t);
}

static inline int database_batch_commit(
    const char *label,
    database_txn_t *t
) 
{
    return database_txn_commit(label, t);
}

static inline void database_batch_abort(database_txn_t *t) {
    database_txn_abort(t);
}

static inline int database_txn_put(
    const char *label,
    database_txn_t *t,
    MDB_dbi dbi,
    const void *key, size_t klen,
    const void *val, size_t vlen,
    unsigned flags
)
{
    MDB_val k = { klen, (void *)key };
    MDB_val v = { vlen, (void *)val };
    return database_error(label, mdb_put(t->txn, dbi, &k, &v, flags));
}

static inline int database_txn_get(
    database_txn_t *t,
    MDB_dbi dbi,
    const void *key,
    size_t klen,
    MDB_val *out
) 
{
    MDB_val k = { klen, (void *)key };
    return mdb_get(t->txn, dbi, &k, out);
}

static inline int database_txn_del(
    const char *label,
    database_txn_t *t,
    MDB_dbi dbi,
    const void *key,
    size_t klen
) 
{
    MDB_val k = { klen, (void *)key };
    return database_error(label, mdb_del(t->txn, dbi, &k, NULL));
}

static inline int database_put(
    const char *label,
    MDB_env *env,
    MDB_dbi dbi,
    const void *key,
    size_t klen,
    const void *val,
    size_t vlen,
    unsigned flags
) 
{
    database_txn_t t;
    int rc = database_txn_begin(label, env, &t);
    if (rc) return rc;

    rc = database_txn_put(label, &t, dbi, key, klen, val, vlen, flags);
    if (rc) {
        database_txn_abort(&t);
        return rc;
    }
    return database_txn_commit(label, &t);
}

static inline int database_get(
    const char *label,
    oritlsf_pool_t *pool, 
    MDB_env *env,
    MDB_dbi dbi,
    const void *key,
    size_t klen,
    void **out,
    size_t *outlen
) 
{
    database_txn_t t;
    MDB_val v;
    int rc = database_txn_begin(label, env, &t);
    if (rc) return rc;

    rc = database_txn_get(&t, dbi, key, klen, &v);
    if (rc != MDB_SUCCESS) {
        database_txn_abort(&t);
        return rc;
    }

	*out = (void *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, v.mv_size);
    if (!*out) {
        database_txn_abort(&t);
        return ENOMEM;
    }

    memcpy(*out, v.mv_data, v.mv_size);
    *outlen = v.mv_size;

    database_txn_abort(&t);
    return MDB_SUCCESS;
}

static inline int database_del(
    const char *label,
    MDB_env *env,
    MDB_dbi dbi,
    const void *key,
    size_t klen
) 
{
    database_txn_t t;
    int rc = database_txn_begin(label, env, &t);
    if (rc) return rc;

    rc = database_txn_del(label, &t, dbi, key, klen);
    if (rc) {
        database_txn_abort(&t);
        return rc;
    }
    return database_txn_commit(label, &t);
}

static inline int database_zc_get(
    const char *label,
    MDB_env *env,
    MDB_dbi dbi,
    MDB_txn **out_txn,
    const void *key,
    size_t klen,
    const void **val,
    size_t *vlen
) 
{
    MDB_txn *txn;
    MDB_val k = { klen, (void *)key };
    MDB_val v;
    int rc;

    rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    if (database_error(label, rc)) return rc;

    rc = mdb_get(txn, dbi, &k, &v);
    if (rc != MDB_SUCCESS) {
        mdb_txn_abort(txn);
        return rc;
    }

    *val = v.mv_data;
    *vlen = v.mv_size;
    *out_txn = txn;
    return MDB_SUCCESS;
}

static inline void database_zc_abort(MDB_txn *txn) {
    if (txn) mdb_txn_abort(txn);
}

static inline int database_cursor_open(
    const char *label,
    database_txn_t *t,
    MDB_dbi dbi,
    database_cursor_t *c
) 
{
    return database_error(label, mdb_cursor_open(t->txn, dbi, &c->cur));
}

static inline void database_cursor_close(database_cursor_t *c) {
    if (c && c->cur) {
        mdb_cursor_close(c->cur);
        c->cur = NULL;
    }
}

static inline int database_cursor_get_first(database_cursor_t *c, MDB_val *k, MDB_val *v) {
    return mdb_cursor_get(c->cur, k, v, MDB_FIRST);
}

static inline int database_cursor_get_last(database_cursor_t *c, MDB_val *k, MDB_val *v) {
    return mdb_cursor_get(c->cur, k, v, MDB_LAST);
}

static inline int database_cursor_get_next(database_cursor_t *c, MDB_val *k, MDB_val *v) {
    return mdb_cursor_get(c->cur, k, v, MDB_NEXT);
}

static inline int database_cursor_get_prev(database_cursor_t *c, MDB_val *k, MDB_val *v) {
    return mdb_cursor_get(c->cur, k, v, MDB_PREV);
}

static inline int database_cursor_seek(
    database_cursor_t *c,
    const void *key,
    size_t klen,
    MDB_val *outk,
    MDB_val *outv
) 
{
    MDB_val k = { klen, (void *)key };
    int rc = mdb_cursor_get(c->cur, &k, outv, MDB_SET_RANGE);
    if (rc == MDB_SUCCESS)
        *outk = k;
    return rc;
}

static inline int database_cursor_prefix_seek(
    database_cursor_t *c,
    const void *prefix,
    size_t plen,
    MDB_val *outk,
    MDB_val *outv
) 
{
    MDB_val k = { plen, (void *)prefix };
    int rc = mdb_cursor_get(c->cur, &k, outv, MDB_SET_RANGE);
    if (rc != MDB_SUCCESS)
        return rc;

    *outk = k;

    if (outk->mv_size < plen ||
        memcmp(outk->mv_data, prefix, plen) != 0)
        return MDB_NOTFOUND;

    return MDB_SUCCESS;
}

static inline int database_get_next(
    database_txn_t *t,
    MDB_dbi dbi,
    const void *key, size_t klen,
    MDB_val *outk,
    MDB_val *outv
) 
{
    MDB_cursor *cur;
    MDB_val k = { klen, (void *)key };
    int rc = mdb_cursor_open(t->txn, dbi, &cur);
    if (rc != MDB_SUCCESS) return rc;

    rc = mdb_cursor_get(cur, &k, outv, MDB_SET_RANGE);
    if (rc == MDB_SUCCESS &&
        k.mv_size == klen &&
        memcmp(k.mv_data, key, klen) == 0)
        rc = mdb_cursor_get(cur, &k, outv, MDB_NEXT);

    if (rc == MDB_SUCCESS)
        *outk = k;

    mdb_cursor_close(cur);
    return rc;
}

static inline int database_get_prev(
    database_txn_t *t,
    MDB_dbi dbi,
    const void *key, size_t klen,
    MDB_val *outk,
    MDB_val *outv
) 
{
    MDB_cursor *cur;
    MDB_val k = { klen, (void *)key };
    int rc = mdb_cursor_open(t->txn, dbi, &cur);
    if (rc != MDB_SUCCESS) return rc;

    rc = mdb_cursor_get(cur, &k, outv, MDB_SET_RANGE);
    if (rc == MDB_SUCCESS)
        rc = mdb_cursor_get(cur, &k, outv, MDB_PREV);

    if (rc == MDB_SUCCESS)
        *outk = k;

    mdb_cursor_close(cur);
    return rc;
}

#endif
