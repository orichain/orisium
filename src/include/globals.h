#ifndef GLOBALS_H
#define GLOBALS_H

#include "lmdb.h"
#include <signal.h>

extern volatile sig_atomic_t shutdown_requested;
extern MDB_env *g_nodekeys_env;
extern MDB_dbi g_nodekeys_keys;
extern MDB_env *g_dataab_env;
extern MDB_dbi g_dataab_metrics;
extern MDB_env *g_database_env;
extern MDB_dbi g_database_pkhash;
extern MDB_dbi g_database_era;

#endif
