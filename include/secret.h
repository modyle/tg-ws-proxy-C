#ifndef SECRET_H
#define SECRET_H

// Функция проверяет конфигурационный файл. 
// Если ключа proxy_secret нет, она генерирует его и записывает в файл.
void ensure_secret_exists(const char *config_filename);

#endif // SECRET_H