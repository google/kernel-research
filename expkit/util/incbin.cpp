#pragma once

#define INCBIN(var_name, filename) \
    __asm__(".section .rodata\n" \
            #var_name ":\n" \
            ".incbin \"" filename "\"\n" \
            #var_name "_end:\n" \
    ); \
    extern const unsigned char var_name[]; \
    extern const unsigned char var_name ## _end[]; \
    __asm__(".section .bss\n"); \
    extern const size_t var_name ## _size = var_name ## _end - var_name;
