#ifndef AES_CUSTOM_H
#define AES_CUSTOM_H

void aes256_ctr_custom(unsigned char *out, size_t outlen, const unsigned char *iv, const aes256ctx *ctx);

#endif
