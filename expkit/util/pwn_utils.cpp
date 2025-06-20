#pragma once

#include <stdint.h>
#include "util/error.cpp"

/**
 * @brief Checks if the provided address is a valid KASLR base address.
 *
 * @param kbase_addr The address to check.
 * @return True if the address is a valid KASLR base, false otherwise.
 */
bool is_kaslr_base(uint64_t kbase_addr) {
    if ((kbase_addr & 0xFFFF0000000FFFFF) != 0xFFFF000000000000)
        return false;
    return true;
}

/**
 * @brief Checks if the provided address is a valid KASLR base address.
 *
 * @param kbase_addr The address to check.
 * @return The checked KASLR base address if valid.
 */
uint64_t check_kaslr_base(uint64_t kbase_addr) {
    if (!is_kaslr_base(kbase_addr))
        throw ExpKitError("kernel base address (%p) is incorrect", kbase_addr);
    return kbase_addr;
}

uint64_t check_heap_ptr(uint64_t heap_leak) {
    if ((heap_leak & 0xFFFF000000000000) != 0xFFFF000000000000)
        throw ExpKitError("kernel heap address (%p) is incorrect", heap_leak);
    /**
     * @brief Checks if the provided address is a valid kernel heap pointer.
     *
     * @param heap_leak The address to check.
     * @return The checked kernel heap pointer if valid.
     */
    return heap_leak;
}
