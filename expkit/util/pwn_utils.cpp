#pragma once

#include <stdint.h>
#include "util/error.cpp"

uint64_t check_kaslr_base(uint64_t kbase_addr) {
    if ((kbase_addr & 0xFFFF0000000FFFFF) != 0xFFFF000000000000)
        throw ExpKitError("kernel base address (%p) is incorrect", kbase_addr);
    return kbase_addr;
}

int is_kaslr_base(uint64_t kbase_addr) {
    if ((kbase_addr & 0xFFFF0000000FFFFF) != 0xFFFF000000000000)
        return 0;
    return 1;
}

uint64_t check_heap_ptr(uint64_t heap_leak) {
    if ((heap_leak & 0xFFFF000000000000) != 0xFFFF000000000000)
        throw ExpKitError("kernel heap address (%p) is incorrect", heap_leak);
    return heap_leak;
}
