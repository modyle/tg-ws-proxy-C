#ifndef MTPROTO_TRANSPORT_H
#define MTPROTO_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// MTProto транспортные форматы
#define PROTO_ABRIDGED 0xEFEFEFEF         // Сокращённый формат
#define PROTO_INTERMEDIATE 0xEEEEEEEE     // Промежуточный формат
#define PROTO_PADDED_INTERMEDIATE 0xDDDDDDDD  // Промежуточный с паддингом

// Контекст парсера транспорта
typedef struct mtproto_transport_ctx {
    uint32_t proto_type;        // Тип протокола (PROTO_*)
    int initialized;            // Инициализирован ли
    uint8_t header_buf[4];      // Буфер для заголовка
    size_t header_received;     // Сколько байт заголовка получено
} mtproto_transport_ctx;

// Инициализация транспортного контекста
void mtproto_transport_init(mtproto_transport_ctx *ctx);

// Определить тип протокола из преамбулы
// Возвращает: 1 если определён, 0 если ещё ждём, -1 если ошибка
int mtproto_transport_detect(mtproto_transport_ctx *ctx, const uint8_t *data, size_t len);

// Получить размер следующего пакета в буфере
// Возвращает: размер пакета (включая заголовок), 0 если неполный, -1 если ошибка
int mtproto_transport_get_packet_size(mtproto_transport_ctx *ctx, const uint8_t *buf, size_t buf_len);

// Получить описание типа протокола
const char* mtproto_transport_get_name(mtproto_transport_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* MTPROTO_TRANSPORT_H */
