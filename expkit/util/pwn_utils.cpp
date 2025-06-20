#include <stdint.h>
#include "util/error.hpp"
#include "util/pwn_utils.hpp"

bool is_kaslr_base(uint64_t kbase_addr) {
    if ((kbase_addr & 0xFFFF0000000FFFFF) != 0xFFFF000000000000)
        return false;
    return true;
}

uint64_t check_kaslr_base(uint64_t kbase_addr) {
    if (!is_kaslr_base(kbase_addr))
        throw ExpKitError("kernel base address (%p) is incorrect", kbase_addr);
    return kbase_addr;
}

uint64_t check_heap_ptr(uint64_t heap_leak) {
    if ((heap_leak & 0xFFFF000000000000) != 0xFFFF000000000000)
        throw ExpKitError("kernel heap address (%p) is incorrect", heap_leak);
    return heap_leak;
}
