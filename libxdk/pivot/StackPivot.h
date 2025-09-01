/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file StackPivot.h
 * @brief Defines the StackPivot class for managing different types of stack pivoting techniques.
 */

#pragma once

#include <optional>
#include <string>
#include <set>
#include <xdk/pivot/Pivots.h>
#include <xdk/payloads/Payload.h>

/**
 * @defgroup pivot_classes Pivot Classes
 * @brief Classes for stack pivoting and related techniques.
 */

// Forward declarations if `Pivots.h` doesn't include full definitions,
// or if these are defined in separate headers.
// If these are actually defined in "pivot/Pivots.h", these might be redundant but harmless.
// struct OneGadgetPivot;
// struct PushIndirectPivot;
// struct PopRspPivot;
// class Register; // If Register is used directly as a type here, otherwise it's part of pivots.

/**
 * @ingroup pivot_classes
 * @class StackPivot
 * @brief Represents a mechanism for changing the stack pointer (RSP) during exploit execution.
 *
 * This class encapsulates different types of stack pivoting gadgets, such as
 * one-gadget pivots or combined push-indirect/pop-RSP pivots. It provides
 * functionality to describe the pivot, get relevant offsets, and apply the
 * pivot's effects to a payload buffer.
 */
class StackPivot {
private:
    std::optional<OneGadgetPivot> one_gadget_;   ///< @brief Optional OneGadgetPivot instance.
    std::optional<PushIndirectPivot> push_gadget_; ///< @brief Optional PushIndirectPivot instance.
    std::optional<PopRspPivot> pop_gadget_;     ///< @brief Optional PopRspPivot instance.

public:
    /**
     * @brief Constructs a StackPivot instance representing a one-gadget pivot.
     * @param one_gadget The OneGadgetPivot structure describing the gadget.
     */
    StackPivot(const OneGadgetPivot& one_gadget);

    /**
     * @brief Constructs a StackPivot instance representing a push-indirect and pop-RSP pivot combination.
     * @param push_gadget The PushIndirectPivot structure.
     * @param pop_gadget The PopRspPivot structure.
     */
    StackPivot(const PushIndirectPivot& push_gadget, const PopRspPivot& pop_gadget);

    /**
     * @brief Generates a human-readable description of the stack pivot.
     *
     * This description includes details about the gadget's address, registers used,
     * destination, and optionally a list of clobbered offsets.
     *
     * @param include_clobbers If true, include a list of clobbered stack offsets in the description.
     * @return A `std::string` containing the pivot's description.
     * @throws ExpKitError if the pivot instance is in an invalid state (neither one-gadget nor push/pop combination).
     */
    std::string GetDescription(bool include_clobbers = true) const;

    /**
     * @brief Returns the address of the primary gadget used for the pivot.
     *
     * For a one-gadget pivot, this is the one-gadget's address. For a push-indirect/pop-RSP
     * pivot, this is the address of the push-indirect gadget.
     *
     * @return The 64-bit unsigned integer address of the pivot gadget.
     */
    uint64_t GetGadgetOffset();

    /**
     * @brief Returns the offset within the payload where the stack is intended to land.
     *
     * For a one-gadget pivot, this is `one_gadget_->next_rip_offset`. For a
     * push-indirect/pop-RSP pivot, this is `pop_gadget_->next_rip_offset`.
     *
     * @return The 64-bit unsigned integer offset within the payload.
     */
    uint64_t GetDestinationOffset() const;

    /**
     * @brief Applies the effects of the stack pivot to a given payload.
     *
     * This involves setting up the payload to execute the pivot, and reserving
     * any stack offsets that might be clobbered by the pivot's execution.
     *
     * @param payload A reference to the Payload object to modify.
     * @param kaslr_base The Kernel Address Space Layout Randomization base address,
     * used to calculate absolute gadget addresses.
     */
    void ApplyToPayload(Payload &payload, uint64_t kaslr_base);
};