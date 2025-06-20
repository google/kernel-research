#pragma once

#include <optional>
#include <string>
#include <set>
#include "pivot/Pivots.cpp"
#include "util/error.cpp"
#include "util/str.cpp"
#include "payloads/Payload.h"

/**
 * @brief Represents a potential stack pivot gadget or sequence of gadgets.
 *
 * This class encapsulates information about different types of stack pivots (one-gadget, push/pop) and provides methods to apply them to a payload.
 */
class StackPivot {
    std::optional<OneGadgetPivot> one_gadget_;
    std::optional<PushIndirectPivot> push_gadget_;
    std::optional<PopRspPivot> pop_gadget_;
public:
    /**
     * @brief Constructs a StackPivot from a OneGadgetPivot.
     * @param one_gadget The OneGadgetPivot to use.
     */
    StackPivot(const OneGadgetPivot& one_gadget)
        : one_gadget_(one_gadget) { }

    /**
     * @brief Constructs a StackPivot from a PushIndirectPivot and a PopRspPivot.
     * @param push_gadget The PushIndirectPivot to use.
     * @param pop_gadget The PopRspPivot to use.
     */
    StackPivot(const PushIndirectPivot& push_gadget, const PopRspPivot& pop_gadget)
        : push_gadget_(push_gadget), pop_gadget_(pop_gadget) { }

    /**
     * @brief Gets a string description of the stack pivot.
     * @param include_clobbers Whether to include information about clobbered offsets in the description.
     * @return A string describing the stack pivot.
     * @throws ExpKitError if the StackPivot is in an invalid state.
     */
    std::string GetDescription(bool include_clobbers = true) const {
        std::string result;
        if (one_gadget_) {
            result = format_str("OneGadget @ 0x%llx: set RSP to %s + 0x%llx", one_gadget_->address,
                register_names[(uint) one_gadget_->pivot_reg.reg], one_gadget_->next_rip_offset);
        } else if (push_gadget_ && pop_gadget_) {
            result = format_str("PushIndirect @ 0x%llx: push %s and %s [%s + 0x%llx]; PopRsp @ 0x%llx: pivots to buf + 0x%llx",
                push_gadget_->address, register_names[(uint) push_gadget_->push_reg.reg],
                push_gadget_->indirect_type == IndirectType::JMP ? "jmp" : "call", register_names[(uint) push_gadget_->indirect_reg.reg],
                push_gadget_->next_rip_offset, pop_gadget_->address, pop_gadget_->next_rip_offset);
        } else
            throw ExpKitError("Invalid Pivot.");

        if (include_clobbers) {
            std::set<int64_t> used_offsets;
            if (one_gadget_)
                for (auto offs : one_gadget_->pivot_reg.used_offsets)
                    used_offsets.insert(offs);

            if (push_gadget_) {
                for (auto offs : push_gadget_->push_reg.used_offsets)
                    used_offsets.insert(offs);
                for (auto offs : push_gadget_->indirect_reg.used_offsets)
                    used_offsets.insert(offs);
            }

            if (!used_offsets.empty()) {
                std::string clobber_list;
                for (auto offs : used_offsets)
                    clobber_list += format_str("%s0x%llx", clobber_list.empty() ? "" : ", ", offs);
                result += format_str(" (clobbers %s)", clobber_list.c_str());
            }
        }

        return result;
    }

    /**
     * @brief Gets the address of the primary gadget in the stack pivot.
     * @return The address of the primary gadget.
     */
    uint64_t GetGadgetOffset() {
        return one_gadget_ ? one_gadget_->address : push_gadget_->address;
    }

    /**
     * @brief Gets the destination offset within the buffer where the pivot will transfer execution.
     * @return The destination offset.
     *
     * This is typically the location where the next instruction or ROP chain should be placed.
     */
    uint64_t GetDestinationOffset() const {
        return one_gadget_ ? one_gadget_->next_rip_offset : pop_gadget_->next_rip_offset;
    }

    /**
     * @brief Applies the stack pivot to a given payload.
     * @param payload The Payload object to modify.
     * @param kaslr_base The KASLR base address.
     */
    void ApplyToPayload(Payload &payload, uint64_t kaslr_base)
    {
        if (push_gadget_ && pop_gadget_)
            payload.Set(push_gadget_->next_rip_offset, kaslr_base + pop_gadget_->address);

        // Handle clobbered offsets
        if (one_gadget_)
            // Go through all the used offsets and reserve
            for (auto used_offset : one_gadget_->pivot_reg.used_offsets)
                payload.Reserve(used_offset, 8);

        if (push_gadget_)
        {
            // Currently our code guarantees that indirect_reg and push_reg point at the same buffer
            // TODO: Check if push_reg and indirect_reg are pointing to the same buffer
            // since we might want to support them pointing at different buffers eventually.
            for (auto used_offset : push_gadget_->indirect_reg.used_offsets)
                payload.Reserve(used_offset, 8);
            for (auto used_offset : push_gadget_->push_reg.used_offsets)
                payload.Reserve(used_offset, 8);
        }
    }
};
