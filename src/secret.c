#include "../include/secret.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

void ensure_secret_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    int has_secret = 0;

    // 1. Проверяем, существует ли файл и есть ли там уже секрет
    if (file) {
        char line[512];
        while (fgets(line, sizeof(line), file)) {
            // Ищем подстроку "proxy_secret"
            if (strstr(line, "proxy_secret") != NULL) {
                has_secret = 1;
                break;
            }
        }
        fclose(file);
    }

    // 2. Если секрета нет, запускаем генерацию
    if (!has_secret) {
        uint8_t rand_bytes[16];
        
        // Используем криптографически стойкий генератор OpenSSL
        if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) {
            fprintf(stderr, "[ERROR] Не удалось собрать энтропию для OpenSSL RAND_bytes!\n");
            return;
        }

        // Переводим 16 байт в 32 символа HEX + 1 для нулевого терминатора
        char hex_secret[33];
        for (int i = 0; i < 16; i++) {
            sprintf(&hex_secret[i * 2], "%02x", rand_bytes[i]);
        }
        hex_secret[32] = '\0';

        // Открываем файл в режиме "a+" (создать или дописать в конец)
        file = fopen(filename, "a+");
        if (!file) {
            fprintf(stderr, "[ERROR] Не удалось открыть/создать файл конфигурации: %s\n", filename);
            return;
        }

        // Проверяем размер файла. Если он 0 (то есть файла не было и мы его создали),
        // запишем туда сразу и базовые дефолтные настройки.
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        
        if (size == 0) {
            fprintf(file, "# MTProto Proxy Configuration\n");
            fprintf(file, "bind_port=4443\n");
            fprintf(file, "public_ip=127.0.0.1\n");
        } else {
            // Если файл был, просто перейдем на новую строку на всякий случай
            fprintf(file, "\n");
        }

        // Дописываем сгенерированный ключ
        fprintf(file, "proxy_secret=%s\n", hex_secret);
        fclose(file);

        printf("[INIT] Первый запуск! Создан стойкий криптографический секрет в %s\n", filename);
    }
}