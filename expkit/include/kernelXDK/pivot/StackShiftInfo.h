#pragma once

#include <cstdint>
#include <vector>
#include <kernelXDK/pivot/StackPivot.hpp>
#include <kernelXDK/payloads/Payload.hpp>

/**
 * @brief Represents information about a single stack shifting gadget within a chain.
 */
struct StackShiftInfo {
    /// @brief The offset within the payload where the address of this stack shift pivot is written.
    uint64_t ret_offset;
    /// @brief The stack shift pivot gadget.
    const StackShiftPivot pivot;
};

/**
 * @brief Stores information about a chain of stack shifting gadgets.
 */
struct StackShiftingInfo {
    /// @brief A vector of individual stack shift gadget information.
    std::vector<StackShiftInfo> stack_shifts;
    /// @brief The starting offset within the payload where the first stack shift pivot address is written.
    uint64_t from_offset;
    uint64_t to_offset;
    uint64_t next_ret_offset;

    void Apply(uint64_t kaslr_base, Payload& payload);
};