#include "../include/mtproto.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define PREAMBLE_SIZE   64
#define KEY_SIZE        32
#define IV_SIZE         16
#define PSK_BIN_SIZE    16

static void _mtproto_log_hex_dump(const char* label, const uint8_t* data, size_t len) {
    if (!data || len == 0) return;
    size_t limit = (len > 64) ? 64 : len;
    for (size_t i = 0; i < limit; i++) {
    }
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int decode_psk(const char *hex, uint8_t out[PSK_BIN_SIZE]) {
    if (!hex) return 0;
    for (size_t i = 0; i < PSK_BIN_SIZE; ++i) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static void derive_key(const uint8_t raw_key[KEY_SIZE], const uint8_t psk[PSK_BIN_SIZE], uint8_t out_key[KEY_SIZE]) {
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, raw_key, KEY_SIZE);
    SHA256_Update(&sha, psk, PSK_BIN_SIZE);
    SHA256_Final(out_key, &sha);
}

void mtproto_init(mtproto_context *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->decrypt_ctx = EVP_CIPHER_CTX_new();
    ctx->encrypt_ctx = EVP_CIPHER_CTX_new();
}

void mtproto_free(mtproto_context *ctx) {
    if (!ctx) return;
    if (ctx->decrypt_ctx) {
        EVP_CIPHER_CTX_free(ctx->decrypt_ctx);
        ctx->decrypt_ctx = NULL;
    }
    if (ctx->encrypt_ctx) {
        EVP_CIPHER_CTX_free(ctx->encrypt_ctx);
        ctx->encrypt_ctx = NULL;
    }
    memset(ctx->preamble, 0, sizeof(ctx->preamble));
    ctx->preamble_received = 0;
    ctx->initialized = 0;
}

int mtproto_process_preamble(
    mtproto_context *ctx,
    const char *psk_hex,
    const uint8_t *in_data,
    size_t in_len,
    size_t *bytes_consumed,
    int *out_dc_idx,
    uint32_t *out_proto_tag) 
{
    uint8_t psk[PSK_BIN_SIZE];
    uint8_t inbound_key[KEY_SIZE], outbound_key[KEY_SIZE];
    uint8_t inbound_iv[IV_SIZE], outbound_iv[IV_SIZE];
    uint8_t reversed[PREAMBLE_SIZE];
    size_t needed, copy_len;
    int out_len;
    int16_t route_raw;
    int route_id;
    EVP_CIPHER_CTX *tmp_ctx = NULL;
    uint8_t decrypted_preamble[PREAMBLE_SIZE];

    if (!ctx || !psk_hex || !in_data || !bytes_consumed || !out_dc_idx || !out_proto_tag) return -1;

    *bytes_consumed = 0;
    if (ctx->initialized) return 1;

    needed = PREAMBLE_SIZE - ctx->preamble_received;
    copy_len = (in_len < needed) ? in_len : needed;

    memcpy(ctx->preamble + ctx->preamble_received, in_data, copy_len);
    ctx->preamble_received += copy_len;
    *bytes_consumed = copy_len;

    if (ctx->preamble_received < PREAMBLE_SIZE) return 0;
    if (!decode_psk(psk_hex, psk)) return -1;

    memcpy(inbound_key, ctx->preamble + 8, KEY_SIZE);
    memcpy(inbound_iv,  ctx->preamble + 40, IV_SIZE);

    for (size_t i = 0; i < PREAMBLE_SIZE; ++i)
        reversed[i] = ctx->preamble[PREAMBLE_SIZE - 1 - i];

    memcpy(outbound_key, reversed + 8, KEY_SIZE);
    memcpy(outbound_iv,  reversed + 40, IV_SIZE);

    derive_key(inbound_key, psk, inbound_key);
    derive_key(outbound_key, psk, outbound_key);

    if (!EVP_DecryptInit_ex(ctx->decrypt_ctx, EVP_aes_256_ctr(), NULL, inbound_key, inbound_iv)) return -1;
    if (!EVP_EncryptInit_ex(ctx->encrypt_ctx, EVP_aes_256_ctr(), NULL, outbound_key, outbound_iv)) return -1;

    tmp_ctx = EVP_CIPHER_CTX_new();
    if (!tmp_ctx) return -1;
    if (!EVP_CIPHER_CTX_copy(tmp_ctx, ctx->decrypt_ctx)) {
        EVP_CIPHER_CTX_free(tmp_ctx);
        return -1;
    }

    if (!EVP_DecryptUpdate(tmp_ctx, decrypted_preamble, &out_len, ctx->preamble, PREAMBLE_SIZE)) {
        EVP_CIPHER_CTX_free(tmp_ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(tmp_ctx);
    
    uint32_t proto_raw = 0;
    memcpy(&proto_raw, decrypted_preamble + 56, sizeof(proto_raw));
    memcpy(&route_raw, decrypted_preamble + 60, sizeof(route_raw));
    route_id = abs((int)route_raw);

    // Разрешаем DC от 1 до 5, а также DC 203 (Media сервер Telegram)
    if ((route_id < 1 || route_id > 5) && route_id != 203) return -1;

    *out_dc_idx = (int)route_raw; // Сохраняем знак!
    *out_proto_tag = proto_raw;
    ctx->initialized = 1;

    // Прокручиваем счетчик (keystream) входящего трафика клиента на 64 байта
    // Так как первые 64 байта (преамбула) уже его "съели"
    uint8_t dummy[64] = {0};
    int dummy_len = 0;
    EVP_DecryptUpdate(ctx->decrypt_ctx, dummy, &dummy_len, ctx->preamble, 64);

    return 1;
}

void mtproto_transform_inbound(mtproto_context *ctx, uint8_t *data, size_t len) {
    int out_len;
    if (!ctx || !ctx->initialized || !data || len == 0) return;
    EVP_DecryptUpdate(ctx->decrypt_ctx, data, &out_len, data, (int)len);
}

void mtproto_transform_outbound(mtproto_context *ctx, uint8_t *data, size_t len) {
    int out_len;
    if (!ctx || !ctx->initialized || !data || len == 0) return;
    EVP_EncryptUpdate(ctx->encrypt_ctx, data, &out_len, data, (int)len);
}