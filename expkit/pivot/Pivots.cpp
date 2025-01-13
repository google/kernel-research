#pragma once

#include <cstdint>
#include <vector>
#include "util/Register.cpp"

enum class IndirectType { JMP, CALL };

struct Pivot {
    uint64_t address;
};

struct RegisterUsage {
    Register reg;
    std::vector<int64_t> used_offsets;
};

struct StackShiftPivot: Pivot {
    uint64_t ret_offset;
    uint64_t shift_amount;
};

struct OneGadgetPivot: Pivot {
    RegisterUsage pivot_reg;
    int64_t next_rip_offset;
};

struct PushIndirectPivot: Pivot {
    IndirectType indirect_type;
    RegisterUsage push_reg;
    RegisterUsage indirect_reg;
    int64_t next_rip_offset;
};

struct PopRspPivot: Pivot {
    uint64_t stack_change_before_rsp;
    int64_t next_rip_offset;
};

struct Pivots {
    std::vector<OneGadgetPivot> one_gadgets;
    std::vector<PushIndirectPivot> push_indirects;
    std::vector<PopRspPivot> pop_rsps;
    std::vector<StackShiftPivot> stack_shifts;
};