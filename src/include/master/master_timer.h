#ifndef MASTER_MASTER_TIMER_H
#define MASTER_MASTER_TIMER_H

#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#ifdef __NetBSD__
    #include <sys/errno.h>
#endif

#include "log.h"
#include "oritw.h"
#include "types.h"
#include "utilities.h"
#include "master/master.h"
#include "master/ipc/worker_ipc_cmds.h"
#include "constants.h"
#include "stdbool.h"
#include "oritw/timer_event.h"
#include "oritw/timer_id.h"
#include "async.h"
#include "oritlsf.h"

static inline status_t handle_master_timer_event(const char *label, master_context_t *master_ctx, int *current_fd, uint32_t *current_events) {
    if (*current_fd == master_ctx->timer.add_event_fd->fd) {
        if (async_event_is_IN(*current_events)) {
            bool rfailure = false;
            bool rpartial = true;
            if (master_ctx->timer.add_event_fd->buffer->in_size_tb == 0) {
                master_ctx->timer.add_event_fd->buffer->in_size_tb = sizeof(uint64_t);
                master_ctx->timer.add_event_fd->buffer->buffer_in = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, 
                    &master_ctx->oritlsf_pool,
                    master_ctx->timer.add_event_fd->buffer->in_size_tb,
                    sizeof(uint8_t)
                );
            }
            while (true) {
                ssize_t rsize = read(master_ctx->timer.add_event_fd->fd, master_ctx->timer.add_event_fd->buffer->buffer_in + master_ctx->timer.add_event_fd->buffer->in_size_c, master_ctx->timer.add_event_fd->buffer->in_size_tb-master_ctx->timer.add_event_fd->buffer->in_size_c);
                if (rsize < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        if (master_ctx->timer.add_event_fd->buffer->in_size_tb == master_ctx->timer.add_event_fd->buffer->in_size_c) {
                            rpartial = false;
                        }
                        break;
                    } else {
                        oritlsf_free(&master_ctx->oritlsf_pool, (void **)&master_ctx->timer.add_event_fd->buffer->buffer_in);
                        master_ctx->timer.add_event_fd->buffer->in_size_tb = 0;
                        master_ctx->timer.add_event_fd->buffer->in_size_c = 0;
                        rfailure = true;
                        break;
                    }
                } 
                if (rsize > 0) {
                    master_ctx->timer.add_event_fd->buffer->in_size_c += rsize;
                }
                if (master_ctx->timer.add_event_fd->buffer->in_size_tb == master_ctx->timer.add_event_fd->buffer->in_size_c) {
                    rpartial = false;
                    break;
                }
            }
            if (!rfailure) {
                if (!rpartial) {
                    timer_id_t *current_add;
                    status_t handler_result = SUCCESS;
                    do {
                        current_add = oritw_pop_timer_id_queue(&master_ctx->timer);
                        if (current_add == NULL) {
                            handler_result = FAILURE;
                            break;
                        }
                        handler_result = oritw_add_event(label, &master_ctx->oritlsf_pool, &master_ctx->master_async, &master_ctx->timer, current_add);
                        oritw_id_free(&master_ctx->oritlsf_pool, &master_ctx->timer, &current_add);
                        if (handler_result != SUCCESS) {
                            break;
                        }
                    } while (current_add != NULL);
                    if (handler_result == SUCCESS) {
                        master_ctx->timer.add_queue_head = NULL;
                        master_ctx->timer.add_queue_tail = NULL;
                    }
                    oritlsf_free(&master_ctx->oritlsf_pool, (void **)&master_ctx->timer.add_event_fd->buffer->buffer_in);
                    master_ctx->timer.add_event_fd->buffer->in_size_tb = 0;
                    master_ctx->timer.add_event_fd->buffer->in_size_c = 0;
                    return handler_result;
                } else {
                    return SUCCESS;
                }
            } else {
                return FAILURE;
            }
        }
        if (async_event_is_OUT(*current_events)) {
            if (master_ctx->timer.add_event_fd->buffer->out_size_tb != 0) {
                bool wfailure = false;
                bool wpartial = true;
                while (true) {
                    ssize_t wsize = write(master_ctx->timer.add_event_fd->fd, master_ctx->timer.add_event_fd->buffer->buffer_out + master_ctx->timer.add_event_fd->buffer->out_size_c, master_ctx->timer.add_event_fd->buffer->out_size_tb - master_ctx->timer.add_event_fd->buffer->out_size_c);
                    if (wsize < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            if (master_ctx->timer.add_event_fd->buffer->out_size_tb == master_ctx->timer.add_event_fd->buffer->out_size_c) {
                                wpartial = false;
                            }
                            break;
                        } else {
                            oritlsf_free(&master_ctx->oritlsf_pool, (void **)&master_ctx->timer.add_event_fd->buffer->buffer_out);
                            master_ctx->timer.add_event_fd->buffer->out_size_tb = 0;
                            master_ctx->timer.add_event_fd->buffer->out_size_c = 0;
                            wfailure = true;
                            break;
                        }
                    } 
                    if (wsize > 0) {
                        master_ctx->timer.add_event_fd->buffer->out_size_c += wsize;
                    }
                    if (master_ctx->timer.add_event_fd->buffer->out_size_tb == master_ctx->timer.add_event_fd->buffer->out_size_c) {
                        wpartial = false;
                        break;
                    }
                }
                if (!wfailure) {
                    if (!wpartial) {
                        oritlsf_free(&master_ctx->oritlsf_pool, (void **)&master_ctx->timer.add_event_fd->buffer->buffer_out);
                        master_ctx->timer.add_event_fd->buffer->out_size_tb = 0;
                        master_ctx->timer.add_event_fd->buffer->out_size_c = 0;
                    }
                }
            }
        }
    }
    for (uint32_t llv = 0; llv < MAX_TIMER_LEVELS; ++llv) {
        ori_timer_wheel_t *timer = master_ctx->timer.timer[llv];
        if (*current_fd == timer->tick_event_fd->fd) {
            if (async_event_is_IN(*current_events)) {
                bool rfailure = false;
                bool rpartial = true;
                if (timer->tick_event_fd->buffer->in_size_tb == 0) {
                    timer->tick_event_fd->buffer->in_size_tb = sizeof(uint64_t);
                    timer->tick_event_fd->buffer->buffer_in = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, 
                        &master_ctx->oritlsf_pool,
                        timer->tick_event_fd->buffer->in_size_tb,
                        sizeof(uint8_t)
                    );
                }
                while (true) {
                    ssize_t rsize = read(timer->tick_event_fd->fd, timer->tick_event_fd->buffer->buffer_in + timer->tick_event_fd->buffer->in_size_c, timer->tick_event_fd->buffer->in_size_tb-timer->tick_event_fd->buffer->in_size_c);
                    if (rsize < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            if (timer->tick_event_fd->buffer->in_size_tb == timer->tick_event_fd->buffer->in_size_c) {
                                rpartial = false;
                            }
                            break;
                        } else {
                            oritlsf_free(&master_ctx->oritlsf_pool, (void **)&timer->tick_event_fd->buffer->buffer_in);
                            timer->tick_event_fd->buffer->in_size_tb = 0;
                            timer->tick_event_fd->buffer->in_size_c = 0;
                            rfailure = true;
                            break;
                        }
                    } 
                    if (rsize > 0) {
                        timer->tick_event_fd->buffer->in_size_c += rsize;
                    }
                    if (timer->tick_event_fd->buffer->in_size_tb == timer->tick_event_fd->buffer->in_size_c) {
                        rpartial = false;
                        break;
                    }
                }
                if (!rfailure) {
                    if (!rpartial) {
                        uint64_t advance_ticks = (uint64_t)(timer->last_delay_us);
                        if (oritw_advance_time_and_process_expired(label, &master_ctx->master_async, &master_ctx->timer, llv, advance_ticks) != SUCCESS) return FAILURE;
                        bool wfailure = false;
                        bool wpartial = true;
                        uint64_t u = 1ULL;
                        if (timer->timeout_event_fd->buffer->out_size_tb == 0) {
                            timer->timeout_event_fd->buffer->out_size_tb = sizeof(uint64_t);
                            timer->timeout_event_fd->buffer->buffer_out = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, 
                                &master_ctx->oritlsf_pool,
                                timer->timeout_event_fd->buffer->out_size_tb,
                                sizeof(uint8_t)
                            );
                            memcpy(timer->timeout_event_fd->buffer->buffer_out, &u, sizeof(uint64_t));
                        } else {
                            timer->timeout_event_fd->buffer->out_size_tb += sizeof(uint64_t);
                            timer->timeout_event_fd->buffer->buffer_out = (uint8_t *)oritlsf_realloc(__FILE__, __LINE__, 
                                &master_ctx->oritlsf_pool,
                                timer->timeout_event_fd->buffer->buffer_out,
                                timer->timeout_event_fd->buffer->out_size_tb * sizeof(uint8_t)
                            );
                            memcpy(timer->timeout_event_fd->buffer->buffer_out + sizeof(uint64_t), &u, sizeof(uint64_t));
                        }
                        while (true) {
                            ssize_t wsize = write(timer->timeout_event_fd->fd, timer->timeout_event_fd->buffer->buffer_out + timer->timeout_event_fd->buffer->out_size_c, timer->timeout_event_fd->buffer->out_size_tb - timer->timeout_event_fd->buffer->out_size_c);
                            if (wsize < 0) {
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    if (timer->timeout_event_fd->buffer->out_size_tb == timer->timeout_event_fd->buffer->out_size_c) {
                                        wpartial = false;
                                    }
                                    break;
                                } else {
                                    oritlsf_free(&master_ctx->oritlsf_pool, (void **)&timer->timeout_event_fd->buffer->buffer_out);
                                    timer->timeout_event_fd->buffer->out_size_tb = 0;
                                    timer->timeout_event_fd->buffer->out_size_c = 0;
                                    wfailure = true;
                                    break;
                                }
                            } 
                            if (wsize > 0) {
                                timer->timeout_event_fd->buffer->out_size_c += wsize;
                            }
                            if (timer->timeout_event_fd->buffer->out_size_tb == timer->timeout_event_fd->buffer->out_size_c) {
                                wpartial = false;
                                break;
                            }
                        }
                        if (!wfailure) {
                            if (!wpartial) {
                                oritlsf_free(&master_ctx->oritlsf_pool, (void **)&timer->timeout_event_fd->buffer->buffer_out);
                                timer->timeout_event_fd->buffer->out_size_tb = 0;
                                timer->timeout_event_fd->buffer->out_size_c = 0;
                            }
                        }
                        //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
                        oritlsf_free(&master_ctx->oritlsf_pool, (void **)&timer->tick_event_fd->buffer->buffer_in);
                        timer->tick_event_fd->buffer->in_size_tb = 0;
                        timer->tick_event_fd->buffer->in_size_c = 0;
                        return SUCCESS;
                    } else {
                        return SUCCESS;
                    }
                } else {
                    return FAILURE;
                }
            }
        } else if (*current_fd == timer->timeout_event_fd->fd) {
            if (async_event_is_IN(*current_events)) {
                bool rfailure = false;
                bool rpartial = true;
                if (timer->timeout_event_fd->buffer->in_size_tb == 0) {
                    timer->timeout_event_fd->buffer->in_size_tb = sizeof(uint64_t);
                    timer->timeout_event_fd->buffer->buffer_in = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, 
                        &master_ctx->oritlsf_pool,
                        timer->timeout_event_fd->buffer->in_size_tb,
                        sizeof(uint8_t)
                    );
                }
                while (true) {
                    ssize_t rsize = read(timer->timeout_event_fd->fd, timer->timeout_event_fd->buffer->buffer_in + timer->timeout_event_fd->buffer->in_size_c, timer->timeout_event_fd->buffer->in_size_tb-timer->timeout_event_fd->buffer->in_size_c);
                    if (rsize < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            if (timer->timeout_event_fd->buffer->in_size_tb == timer->timeout_event_fd->buffer->in_size_c) {
                                rpartial = false;
                            }
                            break;
                        } else {
                            oritlsf_free(&master_ctx->oritlsf_pool, (void **)&timer->timeout_event_fd->buffer->buffer_in);
                            timer->timeout_event_fd->buffer->in_size_tb = 0;
                            timer->timeout_event_fd->buffer->in_size_c = 0;
                            rfailure = true;
                            break;
                        }
                    } 
                    if (rsize > 0) {
                        timer->timeout_event_fd->buffer->in_size_c += rsize;
                    }
                    if (timer->timeout_event_fd->buffer->in_size_tb == timer->timeout_event_fd->buffer->in_size_c) {
                        rpartial = false;
                        break;
                    }
                }
                if (!rfailure) {
                    if (!rpartial) {
                        timer_event_t *current_event;
                        status_t handler_result = SUCCESS;
                        do {
                            current_event = oritw_pop_ready_queue(timer);
                            if (current_event == NULL) {
                                handler_result = FAILURE;
                                break;
                            }
                            uint64_t expired_timer_id = current_event->timer_id;
                            if (expired_timer_id == master_ctx->check_healthy_timer_id.id) {
                                oritw_free(&master_ctx->oritlsf_pool, &master_ctx->timer, &master_ctx->check_healthy_timer_id.event);
                                master_ctx->check_healthy_timer_id.delay_us = worker_check_healthy_us();
                                status_t chst = oritw_add_event(label, &master_ctx->oritlsf_pool, &master_ctx->master_async, &master_ctx->timer, &master_ctx->check_healthy_timer_id);
                                if (chst != SUCCESS) {
                                    LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", label);
                                    master_ctx->shutdown_requested = 1;
                                    master_workers_info(label, master_ctx, IT_SHUTDOWN);
                                    handler_result = FAILURE;
                                    break;
                                }
                                master_ctx->hb_check_times++;
                                if (master_ctx->hb_check_times >= REKEYING_HB_TIMES) {
                                    master_ctx->hb_check_times = (uint16_t)0;
                                    master_ctx->is_rekeying = true;
                                    master_ctx->all_workers_is_ready = false;
                                    handler_result = master_workers_info(label, master_ctx, IT_REKEYING);
                                    if (handler_result != SUCCESS) {
                                        break;
                                    }
//----------------------------------------------------------------------
//--- Test Send IPC During Rekeying
//----------------------------------------------------------------------
                                    /*
                                    handler_result = master_workers_info(label, master_ctx, IT_WAKEUP);
                                    if (handler_result != SUCCESS) {
                                        break;
                                    }
                                    
                                    handler_result = master_workers_info(label, master_ctx, IT_WAKEUP);
                                    if (handler_result != SUCCESS) {
                                        break;
                                    }
                                    
                                    handler_result = master_workers_info(label, master_ctx, IT_WAKEUP);
                                    if (handler_result != SUCCESS) {
                                        break;
                                    }
                                    */
//----------------------------------------------------------------------
                                } else {
                                    handler_result = check_workers_healthy(label, master_ctx);
                                    if (handler_result != SUCCESS) {
                                        break;
                                    }
                                }
                            } else {
                                handler_result = FAILURE;
                                oritw_free(&master_ctx->oritlsf_pool, &master_ctx->timer, &current_event);
                                break;
                            }
                        } while (current_event != NULL);
                        if (handler_result == SUCCESS) {
                            timer->ready_queue_head = NULL;
                            timer->ready_queue_tail = NULL;
                        }
                        //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
                        oritlsf_free(&master_ctx->oritlsf_pool, (void **)&timer->timeout_event_fd->buffer->buffer_in);
                        timer->timeout_event_fd->buffer->in_size_tb = 0;
                        timer->timeout_event_fd->buffer->in_size_c = 0;
                        return handler_result;
                    } else {
                        return SUCCESS;
                    }
                } else {
                    return FAILURE;
                }
            }
            if (async_event_is_OUT(*current_events)) {
                if (timer->timeout_event_fd->buffer->out_size_tb != 0) {
                    bool wfailure = false;
                    bool wpartial = true;
                    while (true) {
                        ssize_t wsize = write(timer->timeout_event_fd->fd, timer->timeout_event_fd->buffer->buffer_out + timer->timeout_event_fd->buffer->out_size_c, timer->timeout_event_fd->buffer->out_size_tb - timer->timeout_event_fd->buffer->out_size_c);
                        if (wsize < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                if (timer->timeout_event_fd->buffer->out_size_tb == timer->timeout_event_fd->buffer->out_size_c) {
                                    wpartial = false;
                                }
                                break;
                            } else {
                                oritlsf_free(&master_ctx->oritlsf_pool, (void **)&timer->timeout_event_fd->buffer->buffer_out);
                                timer->timeout_event_fd->buffer->out_size_tb = 0;
                                timer->timeout_event_fd->buffer->out_size_c = 0;
                                wfailure = true;
                                break;
                            }
                        } 
                        if (wsize > 0) {
                            timer->timeout_event_fd->buffer->out_size_c += wsize;
                        }
                        if (timer->timeout_event_fd->buffer->out_size_tb == timer->timeout_event_fd->buffer->out_size_c) {
                            wpartial = false;
                            break;
                        }
                    }
                    if (!wfailure) {
                        if (!wpartial) {
                            oritlsf_free(&master_ctx->oritlsf_pool, (void **)&timer->timeout_event_fd->buffer->buffer_out);
                            timer->timeout_event_fd->buffer->out_size_tb = 0;
                            timer->timeout_event_fd->buffer->out_size_c = 0;
                        }
                    }
                }
            }
        }
    }
    return SUCCESS;
}

#endif
