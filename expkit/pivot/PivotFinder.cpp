#pragma once

#include <optional>
#include "pivot/Pivots.cpp"
#include "pivot/StackPivot.cpp"
#include "util/Payload.cpp"

class PivotFinder {
    const Pivots& pivots_;
    Register buf_reg_;
    Payload& payload_;

    std::vector<StackPivot> Find(bool only_one) {
        std::vector<StackPivot> result;

        for (auto& gadget : pivots_.one_gadgets) {
            if (!CheckOneGadget(gadget))
                continue;

            result.push_back(StackPivot(gadget));
            if (only_one)
                return result;
        }

        for (auto& push : pivots_.push_indirects) {
            if (!CheckPushIndirect(push))
                continue;

            for (auto& pop : pivots_.pop_rsps) {
                auto push_change = push.indirect_type == IndirectType::CALL ? 8 : 0;
                if (pop.stack_change_before_rsp != push_change ||
                    !payload_.CheckFree(pop.next_rip_offset, 8))
                        continue;

                    result.push_back(StackPivot(push, pop));
                    if (only_one)
                        return result;
            }
        }

        return result;
    }

public:
    PivotFinder(const Pivots& pivots, Register buf_reg, Payload& payload): pivots_(pivots), buf_reg_(buf_reg), payload_(payload) { }

    bool CheckRegister(const RegisterUsage& reg) {
        if (reg.reg != buf_reg_)
            return false;

        // TODO: it can be used as long as it is not used for RIP control (just pre-RIP control vuln trigger)
        // TODO: it is also possible that we can jump over it
        for (auto offs : reg.used_offsets)
            if (!payload_.CheckFree(offs, 8))
                return false;

        return true;
    }

    bool CheckOneGadget(const OneGadgetPivot& pivot) {
        return CheckRegister(pivot.pivot_reg) &&
               payload_.CheckFree(pivot.next_rip_offset, 8);
    }

    bool CheckPushIndirect(const PushIndirectPivot& pivot) {
        return CheckRegister(pivot.push_reg) &&
               CheckRegister(pivot.indirect_reg) &&
               payload_.CheckFree(pivot.next_rip_offset, 8);
    }

    std::vector<StackPivot> FindAll() {
        return Find(false);
    }

    std::optional<StackPivot> Find() {
        auto result = Find(true);
        return result.empty() ? std::nullopt : std::optional(result[0]);
    }
};