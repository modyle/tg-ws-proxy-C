#include "../include/main.h"
#include "../include/secret.h"
#include "../include/crash_handler.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

FILE *global_log_file = NULL;

static int bind_port = 4443;
static char public_ip[256] = "127.0.0.1";
static char proxy_secret[65] = "00000000000000000000000000000000";

static const char *dc_hosts[] = {
    "kws1.web.telegram.org",
    "kws2.web.telegram.org",
    "kws3.web.telegram.org",
    "kws4.web.telegram.org",
    "kws5.web.telegram.org"
};

struct dc_ip_map {
    int dc;
    const char *ip;
};

static struct dc_ip_map dc_ips[] = {
    { 1, "149.154.175.50" },
    { 2, "149.154.167.50" },
    { 3, "149.154.175.100" },
    { 4, "149.154.167.91" },
    { 5, "91.108.56.100" },
    { 203, "91.105.192.100" }
};

static void get_log_filename(char *buffer, size_t size) {
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, size, "console-%Y-%m-%d_%H-%M-%S.log", timeinfo);
}

static void custom_lws_log(int level, const char *line) {
    (void)level;
    if (strstr(line, "Missing URI in HTTP request") != NULL) {
        return;
    }
    printf("%s", line);
    if (global_log_file) {
        fprintf(global_log_file, "%s", line);
        fflush(global_log_file);
    }
}

static void trim(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
}

static void load_config(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) return;

    char line[512];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == ';' || line[0] == '\n' || line[0] == '\r') continue;
        char *delim = strchr(line, '=');
        if (!delim) continue;

        *delim = '\0';
        char *key = line;
        char *value = delim + 1;
        trim(key);
        trim(value);

        if (strcmp(key, "public_ip") == 0) strncpy(public_ip, value, sizeof(public_ip) - 1);
        else if (strcmp(key, "proxy_secret") == 0) strncpy(proxy_secret, value, sizeof(proxy_secret) - 1);
    }
    fclose(file);
}

static int aes256_ctr_init(EVP_CIPHER_CTX *ctx, const uint8_t key[32], const uint8_t iv[16], int enc) {
    uint8_t zero[64] = {0};
    int out_len = 0;
    if (!ctx) return -1;
    if (enc) {
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) return -1;
        if (!EVP_EncryptUpdate(ctx, zero, &out_len, zero, sizeof(zero))) return -1;
    } else {
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) return -1;
    }
    return 0;
}

static void wss_crypto_free(wss_crypto_context *ctx) {
    if (!ctx) return;
    if (ctx->decrypt_ctx) { EVP_CIPHER_CTX_free(ctx->decrypt_ctx); ctx->decrypt_ctx = NULL; }
    if (ctx->encrypt_ctx) { EVP_CIPHER_CTX_free(ctx->encrypt_ctx); ctx->encrypt_ctx = NULL; }
    memset(ctx->relay_init, 0, sizeof(ctx->relay_init));
    ctx->initialized = 0;
    ctx->relay_init_sent = 0;
}

static int wss_crypto_init(wss_crypto_context *ctx, const uint8_t relay_init[64]) {
    if (!ctx || !relay_init) return -1;
    wss_crypto_free(ctx);

    ctx->encrypt_ctx = EVP_CIPHER_CTX_new();
    ctx->decrypt_ctx = EVP_CIPHER_CTX_new();
    if (!ctx->encrypt_ctx || !ctx->decrypt_ctx) return -1;

    memcpy(ctx->relay_init, relay_init, 64);

    uint8_t enc_key[32], enc_iv[16], rev[48], dec_key[32], dec_iv[16];
    memcpy(enc_key, relay_init + 8, 32);
    memcpy(enc_iv, relay_init + 40, 16);
    for (size_t i = 0; i < 48; ++i) rev[i] = relay_init[55 - i];
    memcpy(dec_key, rev, 32);
    memcpy(dec_iv, rev + 32, 16);

    if (aes256_ctr_init(ctx->encrypt_ctx, enc_key, enc_iv, 1) < 0 ||
        aes256_ctr_init(ctx->decrypt_ctx, dec_key, dec_iv, 0) < 0) {
        return -1;
    }

    ctx->initialized = 1;
    ctx->relay_init_sent = 0;
    return 0;
}

static int generate_relay_init(uint8_t out[64], uint32_t proto_tag, int dc_idx) {
    static const uint8_t reserved_first = 0xEF;
    static const uint32_t reserved_starts[] = {0x44414548u, 0x54534f50u, 0x20544547u, 0xeeeeeeeeu, 0xddddddddu, 0x02010316u};

    uint8_t rnd[64], tail_plain[8], enc_key[32], enc_iv[16], ks[64];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    for (;;) {
        if (RAND_bytes(rnd, sizeof(rnd)) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
        if (rnd[0] == reserved_first) continue;
        uint32_t first4 = (uint32_t)rnd[0] | ((uint32_t)rnd[1] << 8) | ((uint32_t)rnd[2] << 16) | ((uint32_t)rnd[3] << 24);
        int bad = 0;
        for (size_t i = 0; i < 6; ++i) { if (first4 == reserved_starts[i]) { bad = 1; break; } }
        if (bad || (rnd[4] == 0 && rnd[5] == 0 && rnd[6] == 0 && rnd[7] == 0)) continue;
        break;
    }

    tail_plain[0] = (uint8_t)(proto_tag & 0xFFu); tail_plain[1] = (uint8_t)((proto_tag >> 8) & 0xFFu);
    tail_plain[2] = (uint8_t)((proto_tag >> 16) & 0xFFu); tail_plain[3] = (uint8_t)((proto_tag >> 24) & 0xFFu);
    tail_plain[4] = (uint8_t)(dc_idx & 0xFF); tail_plain[5] = (uint8_t)((dc_idx >> 8) & 0xFF);
    if (RAND_bytes(tail_plain + 6, 2) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }

    memcpy(enc_key, rnd + 8, 32);
    memcpy(enc_iv, rnd + 40, 16);

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, enc_key, enc_iv)) { EVP_CIPHER_CTX_free(ctx); return -1; }
    int out_len = 0;
    if (!EVP_EncryptUpdate(ctx, ks, &out_len, rnd, 64)) { EVP_CIPHER_CTX_free(ctx); return -1; }
    EVP_CIPHER_CTX_free(ctx);

    memcpy(out, rnd, 56);
    for (size_t i = 0; i < 8; ++i) out[56 + i] = (uint8_t)(tail_plain[i] ^ (ks[56 + i] ^ rnd[56 + i]));
    return 0;
}

static int start_remote_connection(struct bridge_session *session, int route_id, uint32_t proto_tag, int dc_idx) {
    if (!session || !session->wsi_local_tcp) return -1;

    struct lws_client_connect_info ccinfo;
    memset(&ccinfo, 0, sizeof(ccinfo));
    ccinfo.context = lws_get_context(session->wsi_local_tcp);

    uint8_t relay_init[64];
    if (generate_relay_init(relay_init, proto_tag, dc_idx) < 0 || wss_crypto_init(&session->wss_crypto, relay_init) < 0) {
        return -1;
    }

    if (session->is_passthrough) {
        const char *target_ip = "149.154.167.50"; 
        for (size_t i = 0; i < sizeof(dc_ips)/sizeof(dc_ips[0]); i++) {
            if (dc_ips[i].dc == abs(dc_idx)) {
                target_ip = dc_ips[i].ip;
                break;
            }
        }
        ccinfo.address = target_ip;
        ccinfo.port = 443;
        ccinfo.path = NULL; 
        ccinfo.ssl_connection = 0; 
        ccinfo.protocol = NULL;
        ccinfo.local_protocol_name = "binary"; 
        ccinfo.origin = NULL;
        ccinfo.host = target_ip;
        ccinfo.method = "RAW"; 

        lwsl_user("[PASSTHROUGH] Трафик для DC %d -> Направление TCP: %s:443\n", dc_idx, target_ip);
    } else {
        int host_idx = abs(route_id);
        if (host_idx < 1 || host_idx > 5) return -1;

        ccinfo.address = dc_hosts[host_idx - 1];
        ccinfo.port = 443;
        ccinfo.path = "/apiws";
        ccinfo.host = dc_hosts[host_idx - 1]; 
        
        char origin_buf[512];
        snprintf(origin_buf, sizeof(origin_buf), "https://%s", ccinfo.host);
        ccinfo.origin = origin_buf;

        ccinfo.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
        ccinfo.protocol = "binary";
        ccinfo.userdata = NULL;

        lwsl_user("[WSS_CONNECT] Трафик для DC %d -> Направление WSS: %s\n", dc_idx, ccinfo.host);
    }

    session->wsi_remote_ws = lws_client_connect_via_info(&ccinfo);
    if (!session->wsi_remote_ws) return -1;
    
    lws_set_opaque_user_data(session->wsi_remote_ws, session);
    return 0;
}

int callback_remote_wss(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    struct bridge_session *session = (struct bridge_session *)lws_get_opaque_user_data(wsi);
    if (!session && 
        reason != LWS_CALLBACK_CLIENT_CLOSED && 
        reason != LWS_CALLBACK_CLIENT_CONNECTION_ERROR &&
        reason != LWS_CALLBACK_RAW_CLOSE) return 0;

    switch (reason) {
        case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
            unsigned char **p = (unsigned char **)in, *end = (*p) + len;
            if (lws_add_http_header_by_token(wsi, WSI_TOKEN_PROTOCOL, (unsigned char *)"binary", 6, p, end)) return -1;
            break;
        }
        case LWS_CALLBACK_RAW_CONNECTED:
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            session->connection_established = 1;
            lwsl_user("[%s] Подключено к Telegram.\n", session->is_passthrough ? "RAW" : "WSS");
            lws_callback_on_writable(wsi);
            if (session->rx_paused_tcp && session->wsi_local_tcp) {
                session->rx_paused_tcp = 0;
                lws_rx_flow_control(session->wsi_local_tcp, 1);
            }
            break;
        case LWS_CALLBACK_RAW_RX:
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            uint8_t *in_data = (uint8_t *)in;
            size_t in_len = len;

            size_t free_space = BUFFER_SIZE - session->ws_to_tcp_len;
            if (in_len > free_space) {
                in_len = free_space; 
            }

            if (in_len > 0) {
                uint8_t *target = session->ws_to_tcp_raw + LWS_PRE + session->ws_to_tcp_len;
                memcpy(target, in_data, in_len);
                session->ws_to_tcp_len += in_len;

                // Перешифрование требуется всегда!
                int out_len = 0;
                EVP_DecryptUpdate(session->wss_crypto.decrypt_ctx, target, &out_len, target, (int)in_len);
                EVP_EncryptUpdate(session->crypto.encrypt_ctx, target, &out_len, target, (int)in_len);
            }

            if (session->wsi_local_tcp && session->ws_to_tcp_len > 0) {
                lws_callback_on_writable(session->wsi_local_tcp);
            }

            if (session->ws_to_tcp_len >= (100 * 1024) && !session->rx_paused_ws) {
                session->rx_paused_ws = 1;
                lws_rx_flow_control(wsi, 0);
            }
            break;
        }
        case LWS_CALLBACK_RAW_WRITEABLE:
        case LWS_CALLBACK_CLIENT_WRITEABLE:
            if (!session->wss_crypto.relay_init_sent) {
                uint8_t temp[LWS_PRE + 64];
                memcpy(temp + LWS_PRE, session->wss_crypto.relay_init, 64);
                
                int written;
                if (session->is_passthrough) {
                    written = lws_write(wsi, temp + LWS_PRE, 64, LWS_WRITE_RAW);
                } else {
                    written = lws_write(wsi, temp + LWS_PRE, 64, lws_write_ws_flags(LWS_WRITE_BINARY, 1, 1));
                }
                if (written < 64) return -1;
                session->wss_crypto.relay_init_sent = 1;

                lws_callback_on_writable(wsi);
                break;
            }
            
            if (session->tcp_to_ws_len > 0) {
                int written;
                if (session->is_passthrough) {
                    written = lws_write(wsi, session->tcp_to_ws_raw + LWS_PRE, session->tcp_to_ws_len, LWS_WRITE_RAW);
                } else {
                    written = lws_write(wsi, session->tcp_to_ws_raw + LWS_PRE, session->tcp_to_ws_len, lws_write_ws_flags(LWS_WRITE_BINARY, 1, 1));
                }

                if (written < 0) return -1;
                if ((size_t)written < session->tcp_to_ws_len) {
                    memmove(session->tcp_to_ws_raw + LWS_PRE, session->tcp_to_ws_raw + LWS_PRE + written, session->tcp_to_ws_len - written);
                    session->tcp_to_ws_len -= written;
                    lws_callback_on_writable(wsi); 
                } else {
                    session->tcp_to_ws_len = 0;
                }
            }
            
            if (session->tcp_to_ws_len < (32 * 1024) && session->rx_paused_tcp && session->wsi_local_tcp) {
                session->rx_paused_tcp = 0;
                lws_rx_flow_control(session->wsi_local_tcp, 1);
            }
            break;
        case LWS_CALLBACK_CLIENT_CLOSED:
        case LWS_CALLBACK_RAW_CLOSE:
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            if (session) {
                session->wsi_remote_ws = NULL;
                session->connection_established = 0;
                session->tcp_to_ws_len = 0;
                session->ws_to_tcp_len = 0;
                wss_crypto_free(&session->wss_crypto);
                if (session->wsi_local_tcp) lws_set_timeout(session->wsi_local_tcp, 1, LWS_TO_KILL_ASYNC);
            }
            break;
        default: break;
    }
    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

int callback_local_tcp(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    struct bridge_session *session = (struct bridge_session *)user;

    switch (reason) {
        case LWS_CALLBACK_RAW_ADOPT:
            memset(session, 0, sizeof(*session));
            session->wsi_local_tcp = wsi;
            mtproto_init(&session->crypto);
            break;
        case LWS_CALLBACK_RAW_RX: {
            uint8_t *in_data = (uint8_t *)in;
            size_t in_len = len;

            if (!session->crypto.initialized) {
                size_t consumed = 0; int dc_idx = 0; uint32_t proto_tag = 0;
                int res = mtproto_process_preamble(&session->crypto, proxy_secret, in_data, in_len, &consumed, &dc_idx, &proto_tag);
                
                if (res == -1) return -1;
                if (res == 0) return 0;

                int route_id = abs(dc_idx);
                
                if (dc_idx < 0 || route_id == 203 || route_id == 1 || route_id == 3 || route_id == 5) {
                    session->is_passthrough = 1;
                } else {
                    session->is_passthrough = 0;
                }

                // Исходную преамбулу клиента не сохраняем, так как вместо неё шлем relay_init
                session->tcp_to_ws_len = 0;

                if (start_remote_connection(session, route_id, proto_tag, dc_idx) < 0) return -1;

                in_data += consumed;
                in_len -= consumed;

                if (!session->connection_established) {
                    session->rx_paused_tcp = 1;
                    lws_rx_flow_control(wsi, 0); 
                }
            }

            if (in_len == 0) break;

            size_t free_space = BUFFER_SIZE - session->tcp_to_ws_len;
            if (in_len > free_space) {
                in_len = free_space; 
            }

            if (in_len > 0) {
                uint8_t *target = session->tcp_to_ws_raw + LWS_PRE + session->tcp_to_ws_len;
                memcpy(target, in_data, in_len);
                session->tcp_to_ws_len += in_len;

                // Перешифрование трафика выполняется всегда
                int out_len = 0;
                EVP_DecryptUpdate(session->crypto.decrypt_ctx, target, &out_len, target, (int)in_len);
                EVP_EncryptUpdate(session->wss_crypto.encrypt_ctx, target, &out_len, target, (int)in_len);
            }

            if (session->connection_established && session->wsi_remote_ws && session->tcp_to_ws_len > 0) {
                lws_callback_on_writable(session->wsi_remote_ws);
            }

            if (session->tcp_to_ws_len >= (100 * 1024) && !session->rx_paused_tcp) {
                session->rx_paused_tcp = 1;
                lws_rx_flow_control(wsi, 0);
            }
            break;
        }
        case LWS_CALLBACK_RAW_WRITEABLE:
            if (session->ws_to_tcp_len > 0) {
                int written = lws_write(wsi, session->ws_to_tcp_raw + LWS_PRE, session->ws_to_tcp_len, LWS_WRITE_RAW);
                if (written < 0) return -1;
                if ((size_t)written < session->ws_to_tcp_len) {
                    memmove(session->ws_to_tcp_raw + LWS_PRE, session->ws_to_tcp_raw + LWS_PRE + written, session->ws_to_tcp_len - written);
                    session->ws_to_tcp_len -= written;
                    lws_callback_on_writable(wsi); 
                } else {
                    session->ws_to_tcp_len = 0;
                }
            }

            if (session->ws_to_tcp_len < (32 * 1024) && session->rx_paused_ws && session->wsi_remote_ws) {
                session->rx_paused_ws = 0;
                lws_rx_flow_control(session->wsi_remote_ws, 1);
            }
            break;
        case LWS_CALLBACK_RAW_CLOSE:
            if (session->wsi_remote_ws) {
                lws_set_opaque_user_data(session->wsi_remote_ws, NULL);
                lws_set_timeout(session->wsi_remote_ws, 1, LWS_TO_KILL_ASYNC);
            }
            mtproto_free(&session->crypto);
            wss_crypto_free(&session->wss_crypto);
            session->wsi_local_tcp = NULL;
            break;
        default: break;
    }
    return 0;
}

static struct lws_protocols protocols[] = {
    { "local-tcp-protocol", callback_local_tcp, sizeof(struct bridge_session), 0, 0, NULL, 0 },
    { "binary", callback_remote_wss, 0, 0, 0, NULL, 0 },
    { NULL, NULL, 0, 0 }
};

int main(void) {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
#endif

    init_crash_handler();
    char log_filename[256];
    get_log_filename(log_filename, sizeof(log_filename));
    global_log_file = fopen(log_filename, "a");

    lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, custom_lws_log);
    ensure_secret_exists("config.ini");
    load_config("config.ini");

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = bind_port;
    info.protocols = protocols;
    info.options = LWS_SERVER_OPTION_FALLBACK_TO_RAW | LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

    struct lws_context *context = lws_create_context(&info);
    if (!context) return 1;

    lwsl_user("\n==================================================================\n");
    lwsl_user("[INIT] tg-ws-proxy-C запущен на порту %d\n", bind_port);
    lwsl_user("[LINK] Ссылка для Telegram (нажми, чтобы применить):\n\n");
    lwsl_user("   ► tg://proxy?server=%s&port=%d&secret=dd%s\n", public_ip, bind_port, proxy_secret);
    lwsl_user("==================================================================\n\n");

    int n = 0;
    while (n >= 0 && !crash_tracker_should_stop()) {
        n = lws_service(context, 50); 
    }

    lwsl_user("\n[SHUTDOWN] Вызвано прерывание! Завершение работы... Выход с кодом 0.\n");
    lws_context_destroy(context);
    
    if (global_log_file) fclose(global_log_file);
    return 0;
}