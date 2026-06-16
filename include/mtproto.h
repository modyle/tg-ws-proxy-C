#ifndef MTPROTO_H
#define MTPROTO_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mtproto_context {
    EVP_CIPHER_CTX *decrypt_ctx;
    EVP_CIPHER_CTX *encrypt_ctx;

    uint8_t preamble[64];
    size_t preamble_received;

    int initialized;
} mtproto_context;

void mtproto_init(mtproto_context *ctx);
void mtproto_free(mtproto_context *ctx);

int mtproto_process_preamble(
    mtproto_context *ctx,
    const char *psk_hex,
    const uint8_t *in_data,
    size_t in_len,
    size_t *bytes_consumed,
    int *out_dc_idx,
    uint32_t *out_proto_tag);

void mtproto_transform_inbound(mtproto_context *ctx, uint8_t *data, size_t len);
void mtproto_transform_outbound(mtproto_context *ctx, uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* MTPROTO_H */