#include "ipc.h"
#include "master/master.h"
#include "master/worker_ipc_cmds.h"
#include "types.h"

status_t handle_master_ipc_hello1(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, ipc_raw_protocol_t_status_t *ircvdi) {
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(label, &master_ctx->oritlsf_pool,
                                                                  security->aes_key, security->remote_nonce, &security->remote_ctr,
                                                                  (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
                                                                  );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &ircvdi->r_ipc_raw_protocol_t);
        return deserialized_ircvdi.status;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
        CLOSE_IPC_RAW_PROTOCOL(&master_ctx->oritlsf_pool, &ircvdi->r_ipc_raw_protocol_t);
    }
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_worker_master_hello1_t *ihello1i = received_protocol->payload.ipc_worker_master_hello1;
    uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
    if (security->hello1_rcvd) {
        LOG_ERROR("%sSudah ada HELLO1", label);
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
        return FAILURE;
    }
    memcpy(security->kem_publickey, ihello1i->kem_publickey, KEM_PUBLICKEY_BYTES);
    if (KEM_ENCODE_SHAREDSECRET(
        security->kem_ciphertext,
        kem_sharedsecret,
        security->kem_publickey
    ) != 0)
    {
        LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", label);
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
        return FAILURE;
    }
    //----------------------------------------------------------------------
    // hello1_ack masih memakai security->kem_sharedsecret kosong
    // karena worker belum siap enkripsi
    //----------------------------------------------------------------------
    uint8_t local_nonce[AES_NONCE_BYTES];
    if (generate_nonce(label, local_nonce) != SUCCESS) {
        LOG_ERROR("%sFailed to generate_nonce.", label);
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
        return FAILURE;
    }
    if (master_worker_hello1_ack(label, master_ctx, rcvd_wot, rcvd_index, security, worker_name, worker_uds_fd, local_nonce) != SUCCESS) {
        LOG_ERROR("%sFailed to master_worker_hello1_ack.", label);
        CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
        return FAILURE;
    }
    memcpy(security->local_nonce, local_nonce, AES_NONCE_BYTES);
    memset(local_nonce, 0, AES_NONCE_BYTES);
    //----------------------------------------------------------------------
    // setelah kirim hello1_ack
    // pasang shared_secret di security->kem_sharedsecret
    // untuk menerima pesan hello2 yang sudah terenkripsi
    //----------------------------------------------------------------------
    memcpy(security->kem_sharedsecret, kem_sharedsecret, KEM_SHAREDSECRET_BYTES);
    memset(kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    //----------------------------------------------------------------------
    // Di workers
    // 1. HELLO2 harus sudah pakai mac_key baru
    // 2. HELLO2 harus masih memakai aes_key lama
    //----------------------------------------------------------------------
    kdf(security->mac_key, HASHES_BYTES, security->kem_sharedsecret, KEM_SHAREDSECRET_BYTES, (uint8_t *)"mac_key", 7);
    //----------------------------------------------------------------------
    security->hello1_rcvd = true;
    CLOSE_IPC_PROTOCOL(&master_ctx->oritlsf_pool, &received_protocol);
    return SUCCESS;
}
