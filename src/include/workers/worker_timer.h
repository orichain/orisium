#ifndef WORKERS_WORKER_TIMER_H
#define WORKERS_WORKER_TIMER_H

#include <inttypes.h>
#include <stdio.h>

#include "log.h"
#include "oritw.h"
#include "types.h"
#include "utilities.h"
#include "workers/workers.h"
#include "workers/worker_ipc.h"
#include "workers/worker_ipc_heartbeat.h"
#include "constants.h"
#include "orilink/protocol.h"
#include "stdbool.h"
#include "oritw/timer_event.h"
#include "oritw/timer_id.h"
#include "async.h"
#include "oritlsf.h"
#include "workers/master_ipc_cmds.h"

static inline status_t retry_transmit(
        worker_context_t *worker_ctx,
        void *xsession,
        packet_t *h,
        orilink_protocol_type_t orilink_protocol
        )
{
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
                      cow_c_session_t *session = (cow_c_session_t *)xsession;
                      orilink_identity_t *identity = session->identity;
                      orilink_security_t *security = session->security;
                      worker_type_t c_wot = identity->local_wot;
                      uint8_t c_index = identity->local_index;
                      uint8_t c_session_index = identity->local_session_index;
                      if (h->sent_try_count > (uint8_t)MAX_RETRY_CNT) {
                          LOG_DEVEL_DEBUG("%sDisconnected => session_index %d, trycount %d.", worker_ctx->label, c_session_index, h->sent_try_count);
                          cleanup_cow_session(worker_ctx, session);
                          if (setup_cow_session(worker_ctx, session, c_wot, c_index, c_session_index) != SUCCESS) {
                              return FAILURE;
                          }
                          if (worker_master_info(worker_ctx, c_session_index, IT_TIMEOUT) != SUCCESS) {
                              return FAILURE;
                          }
                          return FAILURE_MAXTRY;
                      }
                      if (h->udp_data == NULL) {
                          return FAILURE;
                      }
                      double try_count = (double)h->sent_try_count;
                      calculate_retry(worker_ctx, session, c_wot, try_count);
                      if (retry_control_packet(
                                  worker_ctx,
                                  identity,
                                  security,
                                  h,
                                  orilink_protocol
                                  ) != SUCCESS
                         )
                      {
                          return FAILURE;
                      }
                      break;
                  }
        case SIO: {
                      sio_c_session_t *session = (sio_c_session_t *)xsession;
                      orilink_identity_t *identity = session->identity;
                      orilink_security_t *security = session->security;
                      worker_type_t c_wot = identity->local_wot;
                      uint8_t c_index = identity->local_index;
                      uint8_t c_session_index = identity->local_session_index;
                      if (h->sent_try_count > (uint8_t)MAX_RETRY_CNT) {
                          LOG_DEVEL_DEBUG("%sDisconnected => session_index %d, trycount %d.", worker_ctx->label, c_session_index, h->sent_try_count);
                          cleanup_sio_session(worker_ctx, session);
                          if (setup_sio_session(worker_ctx, session, c_wot, c_index, c_session_index) != SUCCESS) {
                              return FAILURE;
                          }
                          if (worker_master_info(worker_ctx, c_session_index, IT_TIMEOUT) != SUCCESS) {
                              return FAILURE;
                          }
                          return FAILURE_MAXTRY;
                      }
                      if (h->udp_data == NULL) {
                          return FAILURE;
                      }
                      double try_count = (double)h->sent_try_count;
                      calculate_retry(worker_ctx, session, c_wot, try_count);
                      if (retry_control_packet(
                                  worker_ctx,
                                  identity,
                                  security,
                                  h,
                                  orilink_protocol
                                  ) != SUCCESS
                         )
                      {
                          return FAILURE;
                      }
                      break;
                  }
        default:
                  return FAILURE;
    }
    return SUCCESS;
}

static inline status_t handle_worker_session_timer_event(
        worker_context_t *worker_ctx,
        void **worker_sessions,
        uint8_t *id_session_index,
        timer_event_t *current_event
        )
{
    uint64_t timer_id = current_event->timer_id;
    worker_type_t wot = *worker_ctx->wot;
    switch (wot) {
        case COW: {
                      if (*id_session_index >= MAX_CONNECTION_PER_COW_WORKER) return FAILURE;
                      cow_c_session_t *session = ((cow_c_session_t **)worker_sessions)[*id_session_index];
                      if (timer_id == session->hello1.retry_timer_id.id) {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &session->hello1.retry_timer_id.event);
                          status_t result = retry_transmit(worker_ctx, session, &session->hello1, ORILINK_HELLO1);
                          return result;
                      } else if (timer_id == session->hello2.retry_timer_id.id) {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &session->hello2.retry_timer_id.event);
                          status_t result = retry_transmit(worker_ctx, session, &session->hello2, ORILINK_HELLO2);
                          return result;
                      } else if (timer_id == session->hello3.retry_timer_id.id) {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &session->hello3.retry_timer_id.event);
                          status_t result = retry_transmit(worker_ctx, session, &session->hello3, ORILINK_HELLO3);
                          return result;
                      } else if (timer_id == session->hello4.retry_timer_id.id) {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &session->hello4.retry_timer_id.event);
                          status_t result = retry_transmit(worker_ctx, session, &session->hello4, ORILINK_HELLO4);
                          return result;
                      } else if (timer_id == session->heartbeat.heartbeat.retry_timer_id.id) {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &session->heartbeat.heartbeat.retry_timer_id.event);
                          status_t result = retry_transmit(worker_ctx, session, &session->heartbeat.heartbeat, ORILINK_HEARTBEAT);
                          return result;
                      } else if (timer_id == session->heartbeat.heartbeat_sender_timer_id.id) {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &session->heartbeat.heartbeat_sender_timer_id.event);
                          if (!session->heartbeat.heartbeat.ack_rcvd) {
                              session->heartbeat.heartbeat_sender_timer_id.delay_us = session->heartbeat.heartbeat_interval;
                              status_t chst = oritw_add_event(worker_ctx->label, &worker_ctx->oritlsf_pool, &worker_ctx->async, &worker_ctx->timer, &session->heartbeat.heartbeat_sender_timer_id);
                              if (chst != SUCCESS) {
                                  return FAILURE;
                              }
                          } else {
                              send_heartbeat(worker_ctx, session, ORILINK_HEARTBEAT);
                          }
                          return SUCCESS;
                      }
#if defined(ACCRCY_TEST)
                      else if (timer_id == session->heartbeat.heartbeat_openner_timer_id.id) {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &session->heartbeat.heartbeat_openner_timer_id.event);
                          session->heartbeat.heartbeat_ack.ack_sent = true;
                          return SUCCESS;
                      }
#endif
                      else {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &current_event);
                          return FAILURE;
                      }
                      break;
                  }
        case SIO: {
                      if (*id_session_index >= MAX_CONNECTION_PER_SIO_WORKER) return FAILURE;
                      sio_c_session_t *session = ((sio_c_session_t **)worker_sessions)[*id_session_index];
                      if (timer_id == session->heartbeat.heartbeat.retry_timer_id.id) {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &session->heartbeat.heartbeat.retry_timer_id.event);
                          status_t result = retry_transmit(worker_ctx, session, &session->heartbeat.heartbeat, ORILINK_HEARTBEAT);
                          return result;
                      } else if (timer_id == session->heartbeat.heartbeat_sender_timer_id.id) {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &session->heartbeat.heartbeat_sender_timer_id.event);
                          if (!session->heartbeat.heartbeat.ack_rcvd) {
                              session->heartbeat.heartbeat_sender_timer_id.delay_us = session->heartbeat.heartbeat_interval;
                              status_t chst = oritw_add_event(worker_ctx->label, &worker_ctx->oritlsf_pool, &worker_ctx->async, &worker_ctx->timer, &session->heartbeat.heartbeat_sender_timer_id);
                              if (chst != SUCCESS) {
                                  return FAILURE;
                              }
                          } else {
                              send_heartbeat(worker_ctx, session, ORILINK_HEARTBEAT);
                          }
                          return SUCCESS;
                      }
#if defined(ACCRCY_TEST)
                      else if (timer_id == session->heartbeat.heartbeat_openner_timer_id.id) {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &session->heartbeat.heartbeat_openner_timer_id.event);
                          session->heartbeat.heartbeat_ack.ack_sent = true;
                          return SUCCESS;
                      }
#endif
                      else {
                          oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &current_event);
                          return FAILURE;
                      }
                      break;
                  }
        default:
                  return FAILURE;
    }
    return FAILURE;
}

static inline status_t handle_worker_timer_event(worker_context_t *worker_ctx, void **worker_sessions, int *current_fd, uint32_t *current_events) {
    if (*current_fd == worker_ctx->timer.add_event_fd->event_id) {
        if (async_event_is_IN(*current_events)) {
            et_result_t retr;
            retr.failure = false;
            retr.partial = true;
            retr.event_type = EIT_FD;
            retr.status = FAILURE;
            do {
                retr = async_read_event(&worker_ctx->oritlsf_pool, worker_ctx->timer.add_event_fd);
                if (!retr.failure) {
                    if (!retr.partial) {
                        if (retr.event_type == EIT_FD) oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&worker_ctx->timer.add_event_fd->buffer->buffer_in);
                        worker_ctx->timer.add_event_fd->buffer->in_size_tb = 0;
                        worker_ctx->timer.add_event_fd->buffer->in_size_c = 0;
                        retr.status = SUCCESS;
                    }
                }
            } while (retr.status == SUCCESS && retr.event_type == EIT_FD);
            timer_id_t *current_add;
            status_t handler_result = SUCCESS;
            do {
                current_add = oritw_pop_timer_id_queue(&worker_ctx->timer);
                if (current_add == NULL) {
                    handler_result = FAILURE;
                    break;
                }
                handler_result = oritw_add_event(worker_ctx->label, &worker_ctx->oritlsf_pool, &worker_ctx->async, &worker_ctx->timer, current_add);
                oritw_id_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &current_add);
                if (handler_result != SUCCESS) {
                    break;
                }
            } while (current_add != NULL);
            if (handler_result == SUCCESS) {
                worker_ctx->timer.add_queue_head = NULL;
                worker_ctx->timer.add_queue_tail = NULL;
            }
            return retr.status;
        }
        if (async_event_is_OUT(*current_events)) {
            if (worker_ctx->timer.add_event_fd->buffer->out_size_tb != 0) {
                et_result_t wetr = async_write_event(&worker_ctx->oritlsf_pool, &worker_ctx->async, worker_ctx->timer.add_event_fd, true);
                if (!wetr.failure) {
                    if (!wetr.partial) {
                        oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&worker_ctx->timer.add_event_fd->buffer->buffer_out);
                        worker_ctx->timer.add_event_fd->buffer->out_size_tb = 0;
                        worker_ctx->timer.add_event_fd->buffer->out_size_c = 0;
                    }
                }
            }
        }
    }
    for (uint32_t llv = 0; llv < MAX_TIMER_SHARD; ++llv) {
        ori_timer_wheel_t *timer = worker_ctx->timer.timer[llv];
        if (*current_fd == timer->tick_event_fd->event_id) {
            if (async_event_is_IN(*current_events)) {
                et_result_t retr;
                retr.failure = false;
                retr.partial = true;
                retr.event_type = EIT_FD;
                retr.status = FAILURE;
                do {
                    retr = async_read_event(&worker_ctx->oritlsf_pool, timer->tick_event_fd);
                    if (!retr.failure) {
                        if (!retr.partial) {
                            //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
                            if (retr.event_type == EIT_FD) oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&timer->tick_event_fd->buffer->buffer_in);
                            timer->tick_event_fd->buffer->in_size_tb = 0;
                            timer->tick_event_fd->buffer->in_size_c = 0;
                            retr.status = SUCCESS;
                        }
                    }
                } while (retr.status == SUCCESS && retr.event_type == EIT_FD);
                uint64_t advance_ticks = (uint64_t)(timer->last_delay_us);
                if (oritw_advance_time_and_process_expired(worker_ctx->label, &worker_ctx->async, &worker_ctx->timer, llv, advance_ticks) != SUCCESS) return FAILURE;
                et_result_t wetr = async_write_event(&worker_ctx->oritlsf_pool, &worker_ctx->async, timer->timeout_event_fd, false);
                if (!wetr.failure) {
                    if (!wetr.partial) {
                        oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&timer->timeout_event_fd->buffer->buffer_out);
                        timer->timeout_event_fd->buffer->out_size_tb = 0;
                        timer->timeout_event_fd->buffer->out_size_c = 0;
                    }
                }
                return retr.status;
            }
        } else if (*current_fd == timer->timeout_event_fd->event_id) {
            if (async_event_is_IN(*current_events)) {
                et_result_t retr;
                retr.failure = false;
                retr.partial = true;
                retr.event_type = EIT_FD;
                retr.status = FAILURE;
                do {
                    retr = async_read_event(&worker_ctx->oritlsf_pool, timer->timeout_event_fd);
                    if (!retr.failure) {
                        if (!retr.partial) {
                            //LOG_DEVEL_DEBUG("Timer event handled for fd=%d done", *current_fd);
                            if (retr.event_type == EIT_FD) oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&timer->timeout_event_fd->buffer->buffer_in);
                            timer->timeout_event_fd->buffer->in_size_tb = 0;
                            timer->timeout_event_fd->buffer->in_size_c = 0;
                            retr.status = SUCCESS;
                        }
                    }
                } while (retr.status == SUCCESS && retr.event_type == EIT_FD);
                timer_event_t *current_event;
                status_t handler_result = SUCCESS;
                do {
                    current_event = oritw_pop_ready_queue(timer);
                    if (current_event == NULL) {
                        handler_result = FAILURE;
                        break;
                    }
                    uint64_t expired_timer_id = current_event->timer_id;
                    if (expired_timer_id == worker_ctx->heartbeat_timer_id.id) {
                        oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &worker_ctx->heartbeat_timer_id.event);
                        worker_ctx->heartbeat_timer_id.delay_us = worker_hb_interval_with_jitter_us();
                        double new_heartbeat_interval_double_ms = worker_ctx->heartbeat_timer_id.delay_us / (double)1e3;
                        status_t chst = oritw_add_event(worker_ctx->label, &worker_ctx->oritlsf_pool, &worker_ctx->async, &worker_ctx->timer, &worker_ctx->heartbeat_timer_id);
                        if (chst != SUCCESS) {
                            LOG_ERROR("%sWorker error oritw_add_event for heartbeat.", worker_ctx->label);
                            handler_result = FAILURE;
                            break;
                        }
                        if (worker_master_heartbeat(worker_ctx, new_heartbeat_interval_double_ms) != SUCCESS) {
                            handler_result = FAILURE;
                            break;
                        }
                    } else if (worker_sessions != NULL) {
                        uint8_t id_session_index;
                        handler_result = read_id_si(worker_ctx->label, expired_timer_id, &id_session_index);
                        handler_result = handle_worker_session_timer_event(worker_ctx, worker_sessions, &id_session_index, current_event);
                        if (handler_result != SUCCESS) {
                            break;
                        }
                    } else {
                        handler_result = FAILURE;
                        oritw_free(&worker_ctx->oritlsf_pool, &worker_ctx->timer, &current_event);
                        break;
                    }
                } while (current_event != NULL);
                if (handler_result == SUCCESS) {
                    timer->ready_queue_head = NULL;
                    timer->ready_queue_tail = NULL;
                }
                return retr.status;
            }
            if (async_event_is_OUT(*current_events)) {
                if (timer->timeout_event_fd->buffer->out_size_tb != 0) {
                    et_result_t wetr = async_write_event(&worker_ctx->oritlsf_pool, &worker_ctx->async, timer->timeout_event_fd, true);
                    if (!wetr.failure) {
                        if (!wetr.partial) {
                            oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&timer->timeout_event_fd->buffer->buffer_out);
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
