#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#if defined(__FreeBSD__)
    #include <arpa/inet.h>
#endif

#include "log.h"
#include "orilink.h"
#include "types.h"
#include "master/master.h"
#include "master/master_worker_metrics.h"
#include "master/master_worker_selector.h"
#include "constants.h"
#include "stdbool.h"
#include "master/ipc/worker_ipc_cmds.h"
#include "utilities.h"
#include "orilink/protocol.h"

status_t handle_master_udp_sock_event(
    const char *label, 
    master_context_t *master_ctx, 
    struct sockaddr_in6 *remote_addr, 
    orilink_raw_protocol_t_status_t *orcvdo
)
{
    char host_str[NI_MAXHOST];
    char port_str[NI_MAXSERV];
    
    int getname_res = getnameinfo((struct sockaddr *)remote_addr, sizeof(struct sockaddr_in6),
                        host_str, NI_MAXHOST,
                        port_str, NI_MAXSERV,
                        NI_NUMERICHOST | NI_NUMERICSERV
                      );
    if (getname_res != 0) {
        LOG_ERROR("%sgetnameinfo failed. %s", label, strerror(errno));
        CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
        return FAILURE;
    }
    size_t host_str_len = strlen(host_str);
    if (host_str_len >= INET6_ADDRSTRLEN) {
        LOG_ERROR("%sKoneksi ditolak dari IP %s. IP terlalu panjang.", label, host_str);
        CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
        return FAILURE_IVLDIP;
    }
    char *endptr;
    long port_num = strtol(port_str, &endptr, 10);
    if (*endptr != '\0' || port_num <= 0 || port_num > 65535) {
        LOG_ERROR("%sKoneksi ditolak dari IP %s. PORT di luar rentang (1-65535).", label, host_str);
        CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
        return FAILURE_IVLDPORT;
    }
    orilink_protocol_type_t orilink_protocol = orcvdo->r_orilink_raw_protocol_t->type;
    uint64_t id_connection = orcvdo->r_orilink_raw_protocol_t->id_connection;
    switch (orilink_protocol) {
        case ORILINK_HELLO1: {
            master_sio_c_session_t *c_session = NULL;
//======================================================================
// + Security
//======================================================================
            for(uint16_t i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                c_session = &master_ctx->sio_c_session[i];
                if(c_session->in_use && c_session->in_secure) {
                    if (sockaddr_equal((const struct sockaddr *)remote_addr, (const struct sockaddr *)&c_session->remote_addr)) {
                        LOG_ERROR("%sConnection From Ip Address %s Port %s Already Exist.", label, host_str, port_str);
                        CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                        return FAILURE;
                    }
                    if (c_session->id_connection == id_connection) {
                        LOG_ERROR("%sId Connection %llu Already Exist.", label, (unsigned long long)c_session->id_connection);
                        CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                        return FAILURE;
                    }
                }
            }
//======================================================================
            uint8_t worker_index = 0xff;
            uint8_t session_index = 0xff;
            uint8_t trycount = orcvdo->r_orilink_raw_protocol_t->trycount;
            if (trycount == 0x01) {
                worker_index = select_best_worker(label, master_ctx, SIO);
                if (worker_index == 0xff) {
                    LOG_ERROR("%sFailed to select an SIO worker for new task.", label);
                    CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                    return FAILURE;
                }
                for(uint8_t i = 0; i < MAX_CONNECTION_PER_SIO_WORKER; ++i) {
                    master_sio_c_session_t *c_session = &master_ctx->sio_c_session[(worker_index * MAX_CONNECTION_PER_SIO_WORKER) + i];
                    if(!c_session->in_use) {
                        c_session->sio_index = worker_index;
                        c_session->in_use = true;
                        session_index = i;
                        break;
                    }
                }
                if (session_index == 0xff) {
                    LOG_ERROR("%sWARNING: No free session slots in sio-%d sessions.", label, worker_index);
                    CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                    return FAILURE;
                }
                if (new_task_metrics(label, master_ctx, SIO, worker_index) != SUCCESS) {
                    LOG_ERROR("%sFailed to input new task in COW %d metrics.", label, worker_index);
                    CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                    return FAILURE;
                }
                c_session = &master_ctx->sio_c_session[(worker_index * MAX_CONNECTION_PER_SIO_WORKER) + session_index];
                c_session->id_connection = id_connection;
                memcpy(&c_session->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
            } else {
                worker_index = orcvdo->r_orilink_raw_protocol_t->remote_index;
                session_index = orcvdo->r_orilink_raw_protocol_t->remote_session_index;
                c_session = &master_ctx->sio_c_session[worker_index];
                if (!sockaddr_equal((const struct sockaddr *)remote_addr, (const struct sockaddr *)&c_session->remote_addr)) {
                    LOG_ERROR("%sDiferent Connection From Ip Address %s Port %s.", label, host_str, port_str);
                    CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                    return FAILURE;
                }
                if (c_session->id_connection != id_connection) {
                    LOG_ERROR("%sDiferent Id Connection %llu.", label, (unsigned long long)c_session->id_connection);
                    CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                    return FAILURE;
                }
            }
            if (master_worker_udp_data(
                    label, 
                    master_ctx, 
                    SIO, 
                    worker_index, 
                    session_index, 
                    (uint8_t)orilink_protocol,
                    trycount,
                    remote_addr, 
                    orcvdo->r_orilink_raw_protocol_t
                ) != SUCCESS
            )
            {
                CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                return FAILURE;
            }
            CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
            break;
        }
        case ORILINK_HELLO1_ACK:
        case ORILINK_HELLO2:
        case ORILINK_HELLO2_ACK:
        case ORILINK_HELLO3:
        case ORILINK_HELLO3_ACK:
        case ORILINK_HELLO4:
        case ORILINK_HELLO4_ACK:
        case ORILINK_HEARTBEAT:
        case ORILINK_HEARTBEAT_ACK:
        case ORILINK_INFO:
        case ORILINK_INFO_ACK: {
            worker_type_t wot = orcvdo->r_orilink_raw_protocol_t->remote_wot;
            uint8_t worker_index = orcvdo->r_orilink_raw_protocol_t->remote_index;
            uint8_t session_index = orcvdo->r_orilink_raw_protocol_t->remote_session_index;
            uint8_t trycount = orcvdo->r_orilink_raw_protocol_t->trycount;
//======================================================================
// + Security
//======================================================================
            switch (wot) {
                case SIO: {
                    if (worker_index > MAX_SIO_WORKERS) {
                        CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                        return FAILURE;
                    }
                    if (session_index > MAX_CONNECTION_PER_SIO_WORKER) {
                        CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                        return FAILURE;
                    }
                    bool not_exist = true;
                    for(uint16_t i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                        master_sio_c_session_t *c_session = &master_ctx->sio_c_session[i];
                        if(c_session->in_use) {
                            if (
                                sockaddr_equal((const struct sockaddr *)remote_addr, (const struct sockaddr *)&c_session->remote_addr) &&
                                c_session->id_connection == id_connection
                            )
                            {
                                not_exist = false;
                                break;
                            }
                        }
                    }
                    if (not_exist) {
                        LOG_ERROR("%sNo Connection Exist From Ip Address %s Port %s Id Connection %llu.", label, host_str, port_str, (unsigned long long)id_connection);
                        CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                        return FAILURE;
                    }
                    break;
                }
                case COW: {
                    if (worker_index > MAX_COW_WORKERS) {
                        CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                        return FAILURE;
                    }
                    if (session_index > MAX_CONNECTION_PER_COW_WORKER) {
                        CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                        return FAILURE;
                    }
                    bool not_exist = true;
                    for(uint16_t i = 0; i < MAX_MASTER_COW_SESSIONS; ++i) {
                        master_cow_c_session_t *c_session = &master_ctx->cow_c_session[i];
                        if(c_session->in_use) {
                            if (
                                sockaddr_equal((const struct sockaddr *)remote_addr, (const struct sockaddr *)&c_session->remote_addr) &&
                                c_session->id_connection == id_connection
                            )
                            {
                                not_exist = false;
                                break;
                            }
                        }
                    }
                    if (not_exist) {
                        LOG_ERROR("%sNo Connection Exist From Ip Address %s Port %s Id Connection %llu.", label, host_str, port_str, (unsigned long long)id_connection);
                        CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                        return FAILURE;
                    }
                    break;
                }
                default:
                    CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                    return FAILURE;
            }
//======================================================================
            if (master_worker_udp_data(
                    label, 
                    master_ctx, 
                    wot, 
                    worker_index, 
                    session_index, 
                    (uint8_t)orilink_protocol,
                    trycount,
                    remote_addr, 
                    orcvdo->r_orilink_raw_protocol_t
                ) != SUCCESS
            )
            {
                CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
                return FAILURE;
            }
            CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
            break;
        }
        default:
            LOG_ERROR("%sUnknown ORILINK protocol type %d from %s:%s. Ignoring.", label, orilink_protocol, host_str, port_str);
            CLOSE_ORILINK_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &orcvdo->r_orilink_raw_protocol_t);
    }
    return SUCCESS;
}

status_t handle_master_ipv4_udp_sock_event(const char *label, master_context_t *master_ctx) {
    struct sockaddr_in remote_addr;
    struct sockaddr_in6 ipv6_remote_addr;
    
    orilink_raw_protocol_t_status_t orcvdo;
    orcvdo.status = FAILURE;
    do {
        orcvdo = receive_orilink_raw_protocol_packet(
            label,
            &master_ctx->oritlsf_pool,
            &master_ctx->ipv4_udp,
            (struct sockaddr *)&remote_addr,
            sizeof(struct sockaddr_in)
        );
        if (orcvdo.status == FAILURE_EAGNEWBLK) {
            break;
        } else {
            if (orcvdo.status != SUCCESS) return orcvdo.status;
            convert_ipv4_to_v4mapped_v6(&remote_addr, &ipv6_remote_addr);
            orcvdo.status = handle_master_udp_sock_event(label, master_ctx, &ipv6_remote_addr, &orcvdo);
        }
    } while (orcvdo.status == SUCCESS);
    return SUCCESS;
}

status_t handle_master_ipv6_udp_sock_event(const char *label, master_context_t *master_ctx) {
    struct sockaddr_in6 remote_addr;
    
    orilink_raw_protocol_t_status_t orcvdo;
    orcvdo.status = FAILURE;
    do {
        orcvdo = receive_orilink_raw_protocol_packet(
            label,
            &master_ctx->oritlsf_pool,
            &master_ctx->ipv6_udp,
            (struct sockaddr *)&remote_addr,
            sizeof(struct sockaddr_in6)
        );
        if (orcvdo.status == FAILURE_EAGNEWBLK) {
            break;
        } else {
            if (orcvdo.status != SUCCESS) return orcvdo.status;
            orcvdo.status = handle_master_udp_sock_event(label, master_ctx, &remote_addr, &orcvdo);
        }
    } while (orcvdo.status == SUCCESS);
    return SUCCESS;
}
