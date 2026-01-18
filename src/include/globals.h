#ifndef GLOBALS_H
#define GLOBALS_H

#include <signal.h>
#include <lmdb.h>

extern volatile sig_atomic_t shutdown_requested;
extern MDB_env *g_database_env;
extern MDB_dbi g_table_era;

#endif
