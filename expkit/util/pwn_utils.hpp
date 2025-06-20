#pragma once

#include <stdint.h>
#include "util/error.hpp"

/**
 * @brief Checks if the provided address is a valid KASLR base address.
 *
 * @param kbase_addr The address to check.
 * @return True if the address is a valid KASLR base, false otherwise.
 */
bool is_kaslr_base(uint64_t kbase_addr);

/**
 * @brief Checks if the provided address is a valid KASLR base address.
 *
 * @param kbase_addr The address to check.
 * @return The checked KASLR base address if valid.
 */
uint64_t check_kaslr_base(uint64_t kbase_addr);

/**
 * @brief Checks if the provided address is a valid kernel heap pointer.
 *
 * @param heap_leak The address to check.
 * @return The checked kernel heap pointer if valid.
 */
uint64_t check_heap_ptr(uint64_t heap_leak);
