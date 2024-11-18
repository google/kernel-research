#pragma once

#include <cstdint>
#include <vector>

enum class Register { RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, R8, R9, R10, R11, R12, R13, R14, R15 };
enum class IndirectType { JMP, CALL };

struct Pivot {
    uint64_t address;
};

struct RegisterUsage {
    Register reg;
    std::vector<int64_t> used_offsets;
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
};