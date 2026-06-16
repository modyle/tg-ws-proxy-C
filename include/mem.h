#ifndef MEM_H
#define MEM_H

#include <stddef.h>

// Инициализация кастомного аллокатора (ровно 5 МБ)
void q_mem_init(void);

// Выделение и освобождение памяти внутри наших 5 МБ
void* q_malloc(size_t size);
void q_free(void* ptr);

#endif // MEM_H