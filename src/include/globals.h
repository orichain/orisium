#ifndef GLOBALS_H
#define GLOBALS_H

#include <signal.h>
#include "node.h"

extern node_config_t node_config;
extern volatile sig_atomic_t shutdown_requested;

#endif
