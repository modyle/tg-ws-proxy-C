#include "../include/mtproto_transport.h"
#include <string.h>
#include <stdio.h>

void mtproto_transport_init(mtproto_transport_ctx *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
}

int mtproto_transport_detect(mtproto_transport_ctx *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data || len == 0) return -1;
    uint8_t first_byte = data[0];
    if (first_byte < 0xF0) {
        ctx->proto_type = PROTO_ABRIDGED;
        ctx->initialized = 1;
        return 1;
    }
    if (len < 4) return 0; 
    uint32_t signature = 0; 
    memcpy(&signature, data, sizeof(signature));
    
    if (signature == PROTO_INTERMEDIATE || signature == PROTO_PADDED_INTERMEDIATE) {
        ctx->proto_type = signature;
        ctx->initialized = 1;
        return 1;
    }
    return -1;
}

int mtproto_transport_get_packet_size(mtproto_transport_ctx *ctx, const uint8_t *buf, size_t buf_len) {
    if (!ctx || !buf || buf_len == 0 || !ctx->initialized) return 0;

    if (ctx->proto_type == PROTO_ABRIDGED) {
        if (buf_len < 1) return 0;
        uint8_t first = buf[0];
        if (first == 0x7F || first == 0xFF) {
            if (buf_len < 4) return 0;
            uint32_t payload_len = (uint32_t)(buf[1] | ((uint32_t)buf[2] << 8) | ((uint32_t)buf[3] << 16)) * 4u;
            if (payload_len == 0 || payload_len > 10u * 1024u * 1024u) {
                printf("[TRANSPORT_ERR_ABRIDGED] Невалидный размер: %u\n", payload_len);
                return -1;
            }
            size_t total = 4u + payload_len;
            if (buf_len < total) return 0;
            return (int)total;
        } else {
            uint32_t payload_len = (uint32_t)(first & 0x7F) * 4u;
            if (payload_len == 0 || payload_len > 10u * 1024u * 1024u) {
                printf("[TRANSPORT_ERR_ABRIDGED] Невалидный размер: %u\n", payload_len);
                return -1;
            }
            size_t total = 1u + payload_len;
            if (buf_len < total) return 0;
            return (int)total;
        }
    }

    if (ctx->proto_type == PROTO_INTERMEDIATE || ctx->proto_type == PROTO_PADDED_INTERMEDIATE) {
        // ИСПРАВЛЕНИЕ: Ждем 4 байта заголовка, а не 8
        if (buf_len < 4) {
            return 0;
        }

        // ИСПРАВЛЕНИЕ: Читаем длину из buf[0]...buf[3], а не buf[4]...buf[7]
        uint32_t payload_len = (uint32_t)(buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24)) & 0x7FFFFFFFu;
        
        if (payload_len == 0 || payload_len > 10u * 1024u * 1024u) {
            printf("[TRANSPORT_ERR_INTERMEDIATE] Невалидный размер: %u\n", payload_len);
            return -1;
        }

        // ИСПРАВЛЕНИЕ: Общий размер пакета = 4 байта (заголовок) + payload_len
        size_t total = 4u + payload_len;
        if (buf_len < total) return 0;
        
        return (int)total;
    }

    return -1;
}

const char* mtproto_transport_get_name(mtproto_transport_ctx *ctx) {
    if (!ctx || !ctx->initialized) return "UNKNOWN";
    switch (ctx->proto_type) {
        case PROTO_ABRIDGED: return "ABRIDGED";
        case PROTO_INTERMEDIATE: return "INTERMEDIATE";
        case PROTO_PADDED_INTERMEDIATE: return "PADDED_INTERMEDIATE";
        default: return "UNKNOWN";
    }
}