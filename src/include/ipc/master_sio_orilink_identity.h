#ifndef IPC_MASTER_SIO_ORILINK_IDENTITY_H
#define IPC_MASTER_SIO_ORILINK_IDENTITY_H

status_t ipc_serialize_master_sio_orilink_identity(const char *label, const ipc_master_sio_orilink_identity_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset);
status_t ipc_deserialize_master_sio_orilink_identity(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr);
ipc_protocol_t_status_t ipc_prepare_cmd_master_sio_orilink_identity(
    const char *label,
    struct sockaddr_in6 *remote_addr,
    uint64_t server_id,
    uint64_t client_id,
    uint16_t port,
    uint8_t *kem_privatekey,
    uint8_t *kem_publickey,
    uint8_t *kem_ciphertext,
    uint8_t *kem_sharedsecret,
    uint8_t *local_nonce,
    uint32_t local_ctr,
    uint8_t *remote_nonce,
    uint32_t remote_ctr,
    double rtt_pn,
    double rtt_mn,
    double rtt_ee,
    double rtt_se,
    uint8_t rtt_ii,    
    uint8_t rtt_fc,
    uint8_t rtt_kic,
    double rtt_iv,
    double rtt_tev,
    double rtt_vp,
    double retry_pn,
    double retry_mn,
    double retry_ee,
    double retry_se,
    uint8_t retry_ii,    
    uint8_t retry_fc,
    uint8_t retry_kic,
    double retry_iv,
    double retry_tev,
    double retry_vp,
    uint8_t rtt_kcs_len,
    uint8_t retry_kcs_len,
    double *rtt_retry_kcs
);

#endif
