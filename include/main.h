#ifndef MAIN_H
#define MAIN_H

#include <libwebsockets.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "../include/mtproto.h"

// Глобальный лимит на буферы пакетов: 3 Мегабайта. 
// Защищает от пожирания ОЗУ, останавливая загрузку при превышении.
#define MAX_GLOBAL_PAYLOAD (3 * 1024 * 1024)
#define SESSION_BUFFER_LIMIT (256 * 1024)

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

    mtproto_context crypto;
    wss_crypto_context wss_crypto;

    // Динамические буферы, которые растут только при необходимости
    uint8_t *tcp_to_ws_buf;
    size_t tcp_to_ws_len;
    size_t tcp_to_ws_cap;

    uint8_t *ws_to_tcp_buf;
    size_t ws_to_tcp_len;
    size_t ws_to_tcp_cap;

    int rx_paused_tcp;
    int rx_paused_ws;
};

extern FILE *global_log_file;

#endif // MAIN_H