#ifndef SESSIONS_UTILITIES_H
#define SESSIONS_UTILITIES_H

#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <bits/types/sig_atomic_t.h>
#include <math.h>
#include <netinet/in.h>

#include "log.h"
#include "ipc/protocol.h"
#include "orilink/protocol.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "sessions/workers_session.h"
#include "workers/master_ipc_cmds.h"
#include "workers/client_orilink_cmds.h"
#include "kalman.h"
#include "pqc.h"
#include "stdbool.h"

static inline void calculate_retry(const char *label, cow_c_session_t *session, int session_index, double try_count) {
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => RETRY %d", session_index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => RETRY %d", session_index);
    calculate_oricle_double(label, desc, &session->retry, try_count, ((double)MAX_RETRY * (double)2));
    free(desc);
}

static inline void calculate_rtt(const char *label, cow_c_session_t *session, int session_index, double rtt_value) {
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => RTT %d", session_index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => RTT %d", session_index);
    calculate_oricle_double(label, desc, &session->rtt, rtt_value, ((double)MAX_RTT_SEC * (double)1e9 * (double)2));
    free(desc);
}

#endif
