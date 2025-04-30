#pragma once

#include <cstdint>
#include <vector>
#include <cstring>

#include "target/Target.cpp"

struct RopAction {
    std::vector<uint64_t> values;
};

/*
A RopChain is an ordered sequence of rop actionss
*/
class RopChain {
public:
    RopChain(Target &target, uint64_t kaslr_base) : target_(target), kaslr_base_(kaslr_base) {}

    void AddRopAction(RopActionId id, std::vector<uint64_t> arguments = {}) {

        std::vector<RopItem> rop_items = target_.GetItemsForAction(id);
        RopAction action;

        for (auto item : rop_items) {
            if (item.type == RopItemType::CONSTANT_VALUE) {
                action.values.push_back(item.value);
            } else if (item.type == RopItemType::ARGUMENT) {
                if (item.value < arguments.size())
                    action.values.push_back(arguments[item.value]);
                else
                    throw ExpKitError("not enough arguments for RopAction, got %u arguments, but needed %u", arguments.size(), item.value + 1);
            } else if (item.type == RopItemType::SYMBOL) {
                action.values.push_back(item.value + kaslr_base_);
            } else
                throw ExpKitError("unexpected RopAction item type %u", item.type);
        }

        actions_.push_back(action);
    }

    void Add(uint64_t item, bool offset = false) {
        RopAction fake_action;
        fake_action.values.push_back((offset ? kaslr_base_ : 0) + item);
        actions_.push_back(fake_action);
    }

    std::vector<uint8_t> GetData() const {
        // Collect the actions into a single uint64_t vector
        std::vector<uint64_t> items;
        for (const auto& action : actions_) {
            items.insert(items.end(), action.values.begin(), action.values.end());
        }

        // Create a uint8_t vector from the uint64_t vector
        auto result_size = items.size() * sizeof(uint64_t);
        std::vector<uint8_t> result(result_size);
        memcpy(result.data(), items.data(), result_size);
        return result;
    }

    std::vector<uint64_t> GetDataWords() const {
        // Collect the actions into a single uint64_t vector
        std::vector<uint64_t> items;
        for (const auto& action : actions_) {
            items.insert(items.end(), action.values.begin(), action.values.end());
        }
        return items;
    }

    uint64_t GetByteSize() const {
        uint64_t size = 0;
        for (const auto& action : actions_) {
            size += action.values.size() * sizeof(uint64_t);
        }
        return size;
    }

    std::vector<RopAction> GetActions() const {
        return actions_;
    }

    uint64_t kaslr_base_;
    std::vector<RopAction> actions_;
    Target& target_;
};
