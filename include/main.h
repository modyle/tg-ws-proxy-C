#ifndef MAIN_H
#define MAIN_H

#include <libwebsockets.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "../include/mtproto.h"

// Буфер 128 КБ для быстрой прокачки медиафайлов
#define BUFFER_SIZE (128 * 1024)

typedef struct wss_crypto_context {
    EVP_CIPHER_CTX *encrypt_ctx;
    EVP_CIPHER_CTX *decrypt_ctx;
    uint8_t relay_init[64];
    int initialized;
    int relay_init_sent;
} wss_crypto_context;

struct bridge_session {
    struct lws *wsi_local_tcp;
    struct lws *wsi_remote_ws;
    int connection_established;
    
    int is_passthrough; // 1 — прямой TCP-пассру туннель, 0 — WebSocket-мост

    mtproto_context crypto;
    wss_crypto_context wss_crypto;

    uint8_t tcp_to_ws_raw[LWS_PRE + BUFFER_SIZE];
    size_t tcp_to_ws_len;

    uint8_t ws_to_tcp_raw[LWS_PRE + BUFFER_SIZE];
    size_t ws_to_tcp_len;

    int rx_paused_tcp;
    int rx_paused_ws;
};

extern FILE *global_log_file;

#endif // MAIN_H