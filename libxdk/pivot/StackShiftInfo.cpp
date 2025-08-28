#include <xdk/pivot/StackShiftInfo.h>

void StackShiftingInfo::Apply(uint64_t kaslr_base, Payload& payload) {
  for (auto& shift : stack_shifts) {
    payload.Set(shift.ret_offset, kaslr_base + shift.pivot.address);
  }
}