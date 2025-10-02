// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <limits>
#include <optional>
#include <queue>
#include <xdk/pivot/Pivots.h>
#include <xdk/pivot/StackPivot.h>
#include <xdk/pivot/PivotFinder.h>
#include <xdk/payloads/Payload.h>
#include <xdk/payloads/RopChain.h>
#include <xdk/util/error.h>
#include "util/stdutils.h"

void RopPivotInfo::PrintDebugInfo() const {
  printf("[+] Selected stack pivot: %s\n", pivot.GetDescription().c_str());

  for (auto& shift : stack_shift.stack_shifts)
    printf("[+] Stack jump @0x%lx: 0x%lx -> 0x%lx (size: 0x%lx)\n",
           shift.pivot.address, shift.ret_offset,
           shift.ret_offset + shift.pivot.shift_amount,
           shift.pivot.shift_amount);

  printf("[+] ROP chain offset: 0x%lx\n", rop_offset);
}

StackShiftPivot PivotFinder::GetSingleRet() {
  // should always work, otherwise throw
  for (const StackShiftPivot& pivot : pivots_.stack_shifts) {
    if (pivot.JumpsToShift() && pivot.shift_amount == 8) return pivot;
  }
  throw ExpKitError("could not find a shift which is just 'ret'");
}

std::optional<PopRspPivot> PivotFinder::GetPopRsp() {
  for (const auto& pivot : pivots_.pop_rsps)
    if (pivot.stack_change_before_rsp == 0 && pivot.next_rip_offset == 0)
      return std::optional(pivot);
  return std::nullopt;
}

RopPivotInfo PivotFinder::PivotToRop(const RopChain& rop) {
  auto snapshot = payload_.Snapshot();
  for (auto& pivot : FindInternal(false)) {
    payload_.Restore(snapshot);
    pivot.ApplyToPayload(payload_, rop.kaslr_base_);

    auto shifts =
        GetShiftToRop(pivot.GetDestinationOffset(), rop.GetByteSize(), false);
    if (!shifts) continue;

    shifts->Apply(rop.kaslr_base_, payload_);
    std::vector<uint64_t> rop_words = rop.GetDataWords();
    payload_.SetU64(shifts->next_ret_offset, rop_words[0]);

    uint64_t payload_off = shifts->to_offset;
    for (uint64_t i = 1; i < rop_words.size(); i++) {
      payload_.SetU64(payload_off, rop_words[i]);
      payload_off += 8;
    }
    return RopPivotInfo{rop, pivot, shifts->to_offset, shifts->to_offset,
                        *shifts};
  }

  payload_.Restore(snapshot);
  throw ExpKitError("could not pivot");
}

uint64_t PivotFinder::ApplyShift(uint64_t kaslr_base, uint64_t from_offset,
                                 uint64_t min_to_offset) {
  auto shifts = GetShiftToOffset(from_offset, min_to_offset);
  if (!shifts.has_value())
    throw ExpKitError("could not find a right stack shift gadget");
  shifts->Apply(kaslr_base, payload_);
  return shifts->to_offset;
}

StackShiftingInfo PivotFinder::GetShiftInfoFromChain(
    const std::vector<StackShiftPivot>& chain, uint64_t from_offset) {
  /*
  Turns a chain of stack shift gadgets into a vector of StackShiftInfo
  */
  std::vector<StackShiftInfo> shift_info;

  // first address is stored at "from_offset"
  uint64_t ret_offset = from_offset;
  uint64_t sp_offset = from_offset + 8;  // move one slot for first ret
  for (const StackShiftPivot stack_shift : chain) {
    uint64_t next_ret = sp_offset + stack_shift.ret_offset;
    sp_offset += stack_shift.shift_amount;
    shift_info.push_back({ret_offset, stack_shift});
    ret_offset = next_ret;
  }
  return StackShiftingInfo{shift_info, from_offset, sp_offset, ret_offset};
}

std::optional<StackShiftingInfo> PivotFinder::FindShiftsInternal(
    uint64_t from_offset, std::optional<uint64_t> min_to_offset,
    std::optional<uint64_t> min_next_space) {
  if (!min_to_offset && !min_next_space) {
    throw ExpKitError(
        "Internal error, min_to_offset or min_next_space should be set");
  }

  std::queue<std::pair<uint64_t, std::vector<StackShiftPivot>>>
      q;  // (next_sp, path)
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
  uint64_t sp_after_prev_inst = from_offset + 8;

  q.push({sp_after_prev_inst,
          {}});  // SP starts one slot after from_offset with an empty path
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
    for (size_t i = 0; i < pivots_.stack_shifts.size(); i++) {
      StackShiftPivot pivot = pivots_.stack_shifts[i];

      uint64_t new_sp = sp + pivot.shift_amount;
      // skip shifts which shift past the payload
      if (new_sp > payload_.Size()) continue;

      // skip shifts to a position we've already visited
      if (visited[new_sp]) continue;

      // skip shifts which don't have a free ret_offset
      uint64_t next_ret_off = sp + pivot.ret_offset;
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
  for (auto& pair : finished) {
    if (pair.first < smallest_sp) {
      smallest_sp = pair.first;
      smallest = pair.second;
    }
  }

  return GetShiftInfoFromChain(smallest, from_offset);
}

std::optional<StackShiftingInfo> PivotFinder::GetShiftToRop(
    uint64_t from_offset, uint64_t byte_size,
    bool include_extra_slot, uint64_t min_rop_start) {
  // search for min_next_space = rop_size-8
  // because the first gadget is put in the next_ret_offset
  if (byte_size == 0) throw ExpKitError("byte_size is 0");
  uint64_t search_size = byte_size - 8;
  if (include_extra_slot) search_size += 8;
  return FindShiftsInternal(from_offset, min_rop_start, search_size);
}

std::optional<StackShiftingInfo> PivotFinder::GetShiftToOffset(
    uint64_t from_offset, uint64_t min_to_offset) {
  std::optional<StackShiftingInfo> shift_info =
      FindShiftsInternal(from_offset, min_to_offset, std::nullopt);
  if (!shift_info) return std::nullopt;

  // "clean up" in case the last gadget didn't end with ret and sp aligned
  // e.g. in the case of retn 0x10, we will add a ret gadget as the retn 0x10
  // return
  if (shift_info->next_ret_offset != shift_info->to_offset - 8) {
    shift_info->stack_shifts.push_back(
        {shift_info->next_ret_offset, GetSingleRet()});
    shift_info->next_ret_offset = shift_info->to_offset;
  }
  // "clean up" the to_offset to be the same as the next_ret_offset
  if (shift_info->next_ret_offset == shift_info->to_offset - 8) {
    shift_info->to_offset = shift_info->next_ret_offset;
  }
  return shift_info;
}

std::optional<StackPivot> PivotFinder::Find(uint64_t free_bytes_after) {
  auto result = FindInternal(true, free_bytes_after);
  return result.empty() ? std::nullopt : std::optional(result[0]);
}

std::optional<StackShiftPivot> PivotFinder::FindShift(uint64_t min_shift,
                                                      uint64_t upper_bound) {
  // Find the minimum shift_amount >= min_shift
  for (const auto& pivot : pivots_.stack_shifts) {
    // Only consider shifts which have the next rip in the last position for now
    if (pivot.shift_amount >= min_shift && pivot.shift_amount < upper_bound &&
        pivot.JumpsToShift()) {
      return pivot;
    }
  }

  // No match found
  return std::nullopt;
}

std::vector<StackPivot> PivotFinder::FindAll() { return FindInternal(false); }

bool PivotFinder::CheckPushIndirect(const PushIndirectPivot& pivot,
                                    uint64_t free_bytes_after) {
  return CheckRegister(pivot.push_reg) && CheckRegister(pivot.indirect_reg) &&
         payload_.CheckFree(pivot.next_rip_offset, 8 + free_bytes_after);
}

bool PivotFinder::CheckOneGadget(const OneGadgetPivot& pivot,
                                 uint64_t free_bytes_after) {
  return CheckRegister(pivot.pivot_reg) &&
         payload_.CheckFree(pivot.next_rip_offset, 8 + free_bytes_after);
}

bool PivotFinder::CheckRegister(const RegisterUsage& reg) {
  // Check it's using a register pointing at this buffer
  if (buf_regs_.find(reg.reg) == buf_regs_.end()) return false;

  // TODO: it can be used as long as it is not used for RIP control (just
  // pre-RIP control vuln trigger)
  // TODO: it is also possible that we can jump over it
  for (auto offs : reg.used_offsets)
    if (!payload_.CheckFree(offs, 8)) return false;

  return true;
}

PivotFinder::PivotFinder(const Pivots& pivots, std::vector<Register> buf_regs,
                         Payload& payload)
    : pivots_(pivots),
      buf_regs_(buf_regs.begin(), buf_regs.end()),
      payload_(payload) {
  SortFields();
}

PivotFinder::PivotFinder(const Pivots& pivots, Register buf_reg,
                         Payload& payload)
    : pivots_(pivots), buf_regs_({buf_reg}), payload_(payload) {
  SortFields();
}

void PivotFinder::SortFields() {
  sortByField<OneGadgetPivot>(pivots_.one_gadgets,
                              [](auto& a) { return a.next_rip_offset; });
  sortByField<PushIndirectPivot>(pivots_.push_indirects,
                                 [](auto& a) { return a.next_rip_offset; });
  sortByField<PopRspPivot>(pivots_.pop_rsps,
                           [](auto& a) { return a.next_rip_offset; });
  sortByField<StackShiftPivot>(pivots_.stack_shifts,
                               [](auto& a) { return a.shift_amount; });
}

std::vector<StackPivot> PivotFinder::FindInternal(bool only_one,
                                                  uint64_t free_bytes_after) {
  auto snapshot =
      payload_.Snapshot();  // run on snapshot to avoid increasing bytes used
  std::vector<StackPivot> result;

  for (auto& gadget : pivots_.one_gadgets) {
    if (!CheckOneGadget(gadget, free_bytes_after)) continue;

    result.push_back(StackPivot(gadget));
    if (only_one) return result;
  }

  for (auto& push : pivots_.push_indirects) {
    if (!CheckPushIndirect(push, free_bytes_after)) continue;

    snapshot.Reserve(push.next_rip_offset, 8);

    for (auto& pop : pivots_.pop_rsps) {
      uint64_t push_change = push.indirect_type == IndirectType::CALL ? 8 : 0;
      if (pop.stack_change_before_rsp != push_change ||
          !snapshot.CheckFree(pop.next_rip_offset, 8 + free_bytes_after))
        continue;

      result.push_back(StackPivot(push, pop));
      if (only_one) break;
    }

    snapshot.Release(push.next_rip_offset, 8);

    if (only_one && !result.empty()) break;
  }

  return result;
}
