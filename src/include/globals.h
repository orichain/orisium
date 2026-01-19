#ifndef GLOBALS_H
#define GLOBALS_H

#include <signal.h>
#include <lmdb.h>

extern volatile sig_atomic_t shutdown_requested;
extern MDB_env *g_database_env;
extern MDB_dbi g_nodekeys_nodekeys;
extern MDB_env *g_nodekeys_env;
extern MDB_dbi g_database_era;

#endif
