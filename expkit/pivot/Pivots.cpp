/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

    bool JumpsToShift() const { return ret_offset == shift_amount - 8; }
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
