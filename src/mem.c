#include "../include/mem.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

// Жестко 5 242 880 байт (5 МБ)
#define EXACT_RAM_SIZE 5242880

typedef struct mem_block {
    size_t size;
    int is_free;
    struct mem_block* next;
} mem_block_t;

static uint8_t* g_arena = NULL;
static mem_block_t* g_head = NULL;

void q_mem_init(void) {
    // Выделяем ровно 5 МБ один раз при старте
    g_arena = (uint8_t*)malloc(EXACT_RAM_SIZE);
    if (!g_arena) {
        fprintf(stderr, "[FATAL] Не удалось выделить 5 МБ ОЗУ при запуске.\n");
        exit(1);
    }
    
    g_head = (mem_block_t*)g_arena;
    g_head->size = EXACT_RAM_SIZE - sizeof(mem_block_t);
    g_head->is_free = 1;
    g_head->next = NULL;
}

void* q_malloc(size_t size) {
    if (size == 0) return NULL;
    
    // Выравнивание до 8 байт
    size = (size + 7) & ~7;

    mem_block_t* curr = g_head;
    while (curr) {
        if (curr->is_free && curr->size >= size) {
            // Если блок сильно больше нужного, разбиваем его
            if (curr->size > size + sizeof(mem_block_t) + 8) {
                mem_block_t* new_block = (mem_block_t*)((uint8_t*)curr + sizeof(mem_block_t) + size);
                new_block->size = curr->size - size - sizeof(mem_block_t);
                new_block->is_free = 1;
                new_block->next = curr->next;

                curr->size = size;
                curr->next = new_block;
            }
            curr->is_free = 0;
            return (void*)((uint8_t*)curr + sizeof(mem_block_t));
        }
        curr = curr->next;
    }
    
    // Память 5МБ кончилась. Возвращаем NULL (вызовет разрыв соединения, но спасет программу)
    return NULL;
}

void q_free(void* ptr) {
    if (!ptr) return;
    mem_block_t* block = (mem_block_t*)((uint8_t*)ptr - sizeof(mem_block_t));
    block->is_free = 1;

    // Склеиваем свободные блоки (дефрагментация)
    mem_block_t* curr = g_head;
    while (curr) {
        if (curr->is_free && curr->next && curr->next->is_free) {
            curr->size += sizeof(mem_block_t) + curr->next->size;
            curr->next = curr->next->next;
        } else {
            curr = curr->next;
        }
    }
}