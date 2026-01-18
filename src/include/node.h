#ifndef NODE_H
#define NODE_H

#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>

#include "types.h"
#include "constants.h"
#include "pqc.h"
#include "database.h"
#include "lmdb.h"
#include "log.h"
#include "oritlsf.h"

typedef struct {
	uint8_t sgn_publickey[SIGN_PUBLICKEY_BYTES];
	uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
} node_publickeys_t;

typedef struct {
	uint64_t no;
	uint8_t vermaj;	
	uint8_t vermin;
	node_publickeys_t presiden;
	node_publickeys_t wapres;
	node_publickeys_t mendagri;
	node_publickeys_t wamendagri;
	node_publickeys_t dprkemendagri[DPR_COUNT];
	node_publickeys_t menlu;
	node_publickeys_t wamenlu;
	node_publickeys_t dprkemenlu[DPR_COUNT];
	node_publickeys_t menhan;
	node_publickeys_t wamenhan;
	node_publickeys_t dprkemenhan[DPR_COUNT];
	node_publickeys_t menkeu;
	node_publickeys_t wamenkeu;
	node_publickeys_t dprkemenkeu[DPR_COUNT];
	node_publickeys_t menkumham;
	node_publickeys_t wamenkumham;
	node_publickeys_t dprkemenkumham[DPR_COUNT];
	node_publickeys_t menkominfo;
	node_publickeys_t wamenkominfo;
	node_publickeys_t dprkemenkominfo[DPR_COUNT];
	node_publickeys_t mensos;
	node_publickeys_t wamensos;
	node_publickeys_t dprkemensos[DPR_COUNT];
	node_publickeys_t menperin;
	node_publickeys_t wamenperin;
	node_publickeys_t dprkemenperin[DPR_COUNT];
	node_publickeys_t menperdag;
	node_publickeys_t wamenperdag;
	node_publickeys_t dprkemenperdag[DPR_COUNT];
	node_publickeys_t menristek;
	node_publickeys_t wamenristek;
	node_publickeys_t dprkemenristek[DPR_COUNT];
	node_publickeys_t menpanrb;
	node_publickeys_t wamenpanrb;
	node_publickeys_t dprkemenpanrb[DPR_COUNT];
	node_publickeys_t menag;
	node_publickeys_t wamenag;
	node_publickeys_t dprkemenag[DPR_COUNT];
	node_publickeys_t irjen1;
	node_publickeys_t irjen2;
	node_publickeys_t irjen3;
	uint8_t ab[IPV6_ADDRESS_LEN][AB_COUNT];
	uint8_t prevhash[HASHES_BYTES];
	uint8_t hash[HASHES_BYTES];
	uint8_t signature[SIGN_GENERATE_SIGNATURE_BBYTES];
} era_t;

#define TABLE_ERA_SIZE ( \
    sizeof(uint64_t) + \
    (2 * sizeof(uint8_t)) + \
    (29 * (SIGN_PUBLICKEY_BYTES + KEM_PUBLICKEY_BYTES)) + \
    (12 * DPR_COUNT * (SIGN_PUBLICKEY_BYTES + KEM_PUBLICKEY_BYTES)) + \
    (AB_COUNT * IPV6_ADDRESS_LEN) + \
    (2 * HASHES_BYTES) + \
    SIGN_GENERATE_SIGNATURE_BBYTES \
)

static inline int database_get_latest_era(
	const char *label,
    oritlsf_pool_t *pool,
    MDB_env *env,
    MDB_dbi dbi,
    era_t **out_era
)
{
    database_txn_t t;
    database_cursor_t c;
    MDB_val k, v;
    int rc;
    rc = database_txn_begin(label, env, &t, 1);
    if (rc != MDB_SUCCESS) return rc;
    rc = database_cursor_open(label, &t, dbi, &c);
    if (rc != MDB_SUCCESS) {
        database_txn_abort(&t);
        return rc;
    }
    rc = database_cursor_get_last(&c, &k, &v);
    if (rc != MDB_SUCCESS) {
        database_cursor_close(&c);
        database_txn_abort(&t);
        return rc;
    }
    *out_era = (era_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, TABLE_ERA_SIZE);
    if (!*out_era) {
        database_cursor_close(&c);
        database_txn_abort(&t);
        return ENOMEM;
    }
    if (v.mv_size != TABLE_ERA_SIZE) {
        LOG_ERROR("ERA: Data size mismatch! Expected %zu, got %zu", TABLE_ERA_SIZE, v.mv_size);
        database_cursor_close(&c);
        database_txn_abort(&t);
        return MDB_CORRUPTED;
    }
    memcpy(*out_era, v.mv_data, v.mv_size);
    database_cursor_close(&c);
    database_txn_abort(&t);
    return MDB_SUCCESS;
}

typedef struct {
    uint16_t len;
    struct sockaddr_in6 addr[MAX_BOOTSTRAP_NODES];
} bootstrap_nodes_t;

status_t read_listen_port_and_bootstrap_nodes_from_json(
    const char* label, 
    const char* filename, 
    uint16_t *listen_port,
    bootstrap_nodes_t* bootstrap_nodes
);

#endif
