/**
 * @file PayloadBuilder.h
 * @brief Defines the PayloadBuilder class for constructing complex exploit payloads.
 */
#pragma once
#ifndef PAYLOAD_BUILDER_H
#define PAYLOAD_BUILDER_H

#include <cstdint>   // For uint64_t, size_t
#include <string>    // For std::string
#include <vector>    // For std::vector
#include <optional>  // For std::optional
#include <functional>// For std::reference_wrapper (used internally in .cpp logic)
#include <tuple>     // For std::tuple (used internally in .cpp logic)

// Project-specific includes (assuming these exist and define necessary types)
#include "Payload.hpp"         // For Payload class
#include "util/error.hpp"
#include "util/math_utils.hpp"  // For align

/**
 * @brief Helper struct to encapsulate payload data for the builder.
 *
 * This struct groups a Payload object, associated registers, and an optional
 * offset for the next RIP (Instruction Pointer).
 *
 * @note The `registers` member is stored by value, meaning a copy is made.
 */
struct PayloadData {
    Payload& payload;                          ///< @brief Reference to the Payload object.
    const std::vector<Register> registers;     ///< @brief Associated registers for this payload (stored by value).
    const std::optional<size_t> next_rip_offset; ///< @brief Optional offset for the next RIP.

    /**
     * @brief Constructs a PayloadData instance.
     * @param payload_ref Reference to the Payload.
     * @param regs Optional vector of Registers (defaults to empty).
     * @param offset Optional next RIP offset (defaults to `std::nullopt`).
     */
    PayloadData(Payload &payload_ref,
                const std::vector<Register> &regs = {},
                std::optional<size_t> offset = std::nullopt)
        : payload(payload_ref), registers(regs), next_rip_offset(offset)
    {
    }
};


/**
 * @brief Converts a 64-bit unsigned integer to its hexadecimal string representation.
 * @param value The 64-bit unsigned integer to convert.
 * @return A `std::string` containing the "0x" prefixed hexadecimal representation
 * of the value (uppercase).
 */
std::string intToHex(uint64_t value);


/**
 * @class PayloadBuilder
 * @brief A class designed to construct and optimize exploit payloads.
 *
 * This builder manages multiple payload components, ROP (Return-Oriented Programming)
 * chains, and stack pivots to create a cohesive and functional exploit payload.
 * It attempts to find suitable stack pivots and apply ROP actions efficiently.
 *
 * @details
 * The implementation tracks `StackShiftingInfo` for every `RopAction`. If two actions
 * can be stored adjacently, the `StackShiftingInfo` between them will represent an empty shift.
 */
class PayloadBuilder {
public:
    /**
     * @brief Constructs a PayloadBuilder instance.
     * @param pivots Available stack pivot gadgets.
     * @param kaslr_base The Kernel Address Space Layout Randomization base address.
     */
    PayloadBuilder(const Pivots &pivots, uint64_t kaslr_base) : pivots_(pivots), kaslr_base_(kaslr_base){}

    /**
     * @brief Adds a new payload component to the builder.
     * @param payload A reference to the Payload object to add.
     * @param registers A vector of Register states associated with this payload (defaults to empty).
     * @param next_rip_offset An optional offset within this payload for the next RIP (defaults to `std::nullopt`).
     */
    void AddPayload(Payload& payload,
                    const std::vector<Register>& registers = {},
                    std::optional<size_t> next_rip_offset = std::nullopt);

    /**
     * @brief Adds a new payload component with an optional single register.
     * @param payload A reference to the Payload object to add.
     * @param reg An optional single Register state (defaults to `std::nullopt`).
     * @param next_rip_offset An optional offset within this payload for the next RIP (defaults to `std::nullopt`).
     */
    void AddPayload(Payload& payload,
                    std::optional<Register> reg = std::nullopt,
                    std::optional<size_t> next_rip_offset = std::nullopt);

    /**
     * @brief Appends a ROP chain to the builder's sequence of ROP actions.
     * @param rop_chain The RopChain object to add.
     */
    void AddRopChain(const RopChain& rop_chain);

    /**
     * @brief Attempts to build the final payload.
     *
     * This method tries to find a suitable stack pivot, applies it to the
     * payload, and then attempts to integrate all ROP actions, performing
     * stack shifts as necessary.
     *
     * @param need_pivot If true, the builder will explicitly look for a pivot (defaults to `true`).
     * @return `true` if a successful payload is built, `false` otherwise.
     * @throws ExpKitError if multiple RIP offsets are found when `need_pivot` is true.
     */
    bool Build(bool need_pivot = true);

    /**
     * @brief Prints debug information about the built payload, if successful.
     *
     * This includes details about the chosen stack pivot, stack shifts, and ROP chain layout.
     */
    void PrintDebugInfo() const;

private:
    /**
     * @brief Attempts to apply a given stack pivot to a payload and integrate ROP actions.
     * @param payload A reference to the Payload object to modify.
     * @param pivot The StackPivot to try.
     * @return `true` if the pivot and all ROP actions can be successfully applied, `false` otherwise.
     */
    bool TryPayloadPivot(Payload& payload, StackPivot pivot);

    /**
     * @brief Estimates the contiguous free space after a given offset in a payload.
     *
     * This helper function is used during the build process to evaluate potential
     * payload layouts. It assumes 8-byte (uint64_t) alignment for free space.
     *
     * @param payload A reference to the Payload object.
     * @param offset The starting offset from which to estimate free space.
     * @return The estimated available free space in bytes.
     */
    uint64_t EstimatePayloadSpaceAfter(Payload& payload, uint64_t offset);

    std::vector<PayloadData> payload_datas_;           ///< @brief List of payload components to integrate.
    std::vector<RopAction> rop_actions_;               ///< @brief Sequence of ROP actions to execute.
    Pivots pivots_;                                    ///< @brief Available stack pivot gadgets.
    uint64_t kaslr_base_;                              ///< @brief The Kernel Address Space Layout Randomization base address.
    std::optional<StackPivot> chosen_pivot_;           ///< @brief The pivot chosen during the build process.
    std::optional<Payload> chosen_payload_;            ///< @brief The final constructed payload.
    std::vector<StackShiftingInfo> chosen_shifts_;     ///< @brief Information about stack shifts performed during the build.
};

#endif // PAYLOAD_BUILDER_H
