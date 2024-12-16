#pragma once

#include <optional>
#include <string>
#include <set>
#include "pivot/Pivots.cpp"
#include "util/str.cpp"
#include "util/Payload.cpp"

class StackPivot {
    std::optional<const OneGadgetPivot> one_gadget_;
    std::optional<const PushIndirectPivot> push_gadget_;
    std::optional<const PopRspPivot> pop_gadget_;
public:
    StackPivot(const OneGadgetPivot& one_gadget)
        : one_gadget_(one_gadget) { }

    StackPivot(const PushIndirectPivot& push_gadget, const PopRspPivot& pop_gadget)
        : push_gadget_(push_gadget), pop_gadget_(pop_gadget) { }

    std::string GetDescription(bool include_clobbers = true) {
        std::string result;
        if (one_gadget_) {
            result = format_str("OneGadget @ 0x%llx: set RSP to %s + 0x%llx", one_gadget_->address,
                register_names[(uint) one_gadget_->pivot_reg.reg], one_gadget_->next_rip_offset);
        } else if (push_gadget_ && pop_gadget_) {
            result = format_str("PushIndirect @ 0x%llx: push %s and %s [%s + 0x%llx]; PopRsp @ 0x%llx: pivots to buf + 0x%llx", 
                push_gadget_->address, register_names[(uint) push_gadget_->push_reg.reg],
                push_gadget_->indirect_type == IndirectType::JMP ? "jmp" : "call", register_names[(uint) push_gadget_->indirect_reg.reg],
                push_gadget_->next_rip_offset, pop_gadget_->address, pop_gadget_->next_rip_offset);
        }

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

    uint64_t GetGadgetOffset() {
        return one_gadget_ ? one_gadget_->address : push_gadget_->address;
    }

    uint64_t GetDestinationOffset() {
        return one_gadget_ ? one_gadget_->next_rip_offset : pop_gadget_->next_rip_offset;
    }

    void ApplyToPayload(Payload& payload) {
        if (push_gadget_ && pop_gadget_)
            payload.Set(push_gadget_->next_rip_offset, pop_gadget_->address);
    }
};
