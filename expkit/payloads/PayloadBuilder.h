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

#ifndef PAYLOAD_BUILDER_H
#define PAYLOAD_BUILDER_H

#include <vector>
#include <optional>
#include <cstdint>
#include <tuple>

#include "util/Register.cpp"

#include "Payload.cpp"
#include "RopChain.cpp"

// TODO we could also know a buffer's address?

struct PayloadData {
    Payload& payload;
    const std::vector<Register> registers;
    const std::optional<size_t> next_rip_offset;

    PayloadData(Payload &payload_ref,
                const std::vector<Register> &regs = {},
                std::optional<size_t> offset = std::nullopt)
        : payload(payload_ref), registers(regs), next_rip_offset(offset)
    {
    }
};

/**
 * PayloadBuilder allows the user to specify multiple buffers that they have control of
 * as well as the register(s) pointing at each buffer.
 *
 * AddPayload and AddRopChain then call Build() to set up the buffer for pivoting and executing a RopChain.
 *
 * Implementation details:
 *
 * There will be a StackShiftingInfo for every RopAction.
 * e.g. PayloadBuilder.chosen_shifts_.size() == PayloadBuilder.rop_actions_.size()
 * if we can store two actions adjacent to each other then the StackShiftingInfo
 * between them will be an empty shift.
 */
class PayloadBuilder {
  public:
    PayloadBuilder(const Pivots &pivots, uint64_t kaslr_base) : pivots_(pivots), kaslr_base_(kaslr_base){}

    void AddPayload(Payload& payload,
                    const std::vector<Register>& registers = {},
                    std::optional<size_t> next_rip_offset = std::nullopt);

    void AddPayload(Payload& payload,
                    std::optional<Register> reg = std::nullopt,
                    std::optional<size_t> next_rip_offset = std::nullopt);

    void AddRopChain(const RopChain& rop_chain);

    // Build the final payload.
    bool Build(bool need_pivot = true);

    void PrintDebugInfo() const;

  private:

    bool TryPayloadPivot(Payload& payload, StackPivot pivot);

    uint64_t EstimatePayloadSpaceAfter(Payload& payload, uint64_t offset);

    std::vector<PayloadData> payload_datas_;
    std::vector<RopAction> rop_actions_;
    Pivots pivots_;
    uint64_t kaslr_base_;
    std::optional<StackPivot> chosen_pivot_;
    std::optional<Payload> chosen_payload_;
    std::vector<StackShiftingInfo> chosen_shifts_;
};

#endif // PAYLOAD_BUILDER_H
