#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <cstring>
#include "util/error.cpp"
#include "util/RopChain.cpp"
#include "pivot/Pivots.cpp"

enum struct RopActionId: uint32_t {
    MSLEEP = 0x01,
    COMMIT_KERNEL_CREDS = 0x02,
    SWITCH_TASK_NAMESPACES = 0x03,
    CORE_PATTERN_OVERWRITE = 0x04,
    FORK = 0x5,
    TELEFORK = 0x6,
    KPTI_TRAMPOLINE = 0x07,
};

enum struct RopItemType: uint8_t {
    CONSTANT_VALUE = 0,
    SYMBOL = 1,
    ARGUMENT = 2
};
struct RopItem {
    RopItemType type;
    uint64_t value;

    RopItem(RopItemType type, uint64_t value): type(type), value(value) { }
};
struct RopActionArgMeta {
    std::string name;
    bool required;
    uint64_t default_value;

    RopActionArgMeta(std::string name, bool required, uint64_t default_value)
        : name(name), required(required), default_value(default_value) { }
};
struct RopActionMeta {
    RopActionId type_id;
    std::string desc;
    std::vector<RopActionArgMeta> args;

    RopActionMeta() {}
    RopActionMeta(RopActionId type_id, std::string desc): type_id(type_id), desc(desc) { }
};

struct StructField {
    std::string name;
    uint64_t offset;
    uint64_t size;
};

struct Struct {
    std::string name;
    uint64_t size;
    std::map<std::string, StructField> fields;
};

struct Target {
    std::string distro;
    std::string release_name;
    std::string version;
    std::map<std::string, uint32_t> symbols;
    std::map<RopActionId, std::vector<RopItem>> rop_actions;
    std::map<std::string, Struct> structs;
    Pivots pivots;

    uint32_t GetSymbolOffset(std::string symbol_name) const {
        auto it = symbols.find(symbol_name);
        if (it == symbols.end() || it->second == 0)
            throw ExpKitError("symbol (%s) is not available for the target", symbol_name.c_str());
        return it->second;
    }

    void AddRopAction(RopChain& rop, RopActionId id, std::vector<uint64_t> arguments = {}) {
        if (rop_actions.find(id) == rop_actions.end()){
            throw ExpKitError("missing RopActionID %u", id);
        }

        for (auto item : rop_actions[id]) {
            if (item.type == RopItemType::CONSTANT_VALUE) {
                rop.Add(item.value);
            } else if (item.type == RopItemType::ARGUMENT) {
                if (item.value < arguments.size())
                    rop.Add(arguments[item.value]);
                else
                    throw ExpKitError("not enough arguments for RopAction, got %u arguments, but needed %u", arguments.size(), item.value + 1);
            } else if (item.type == RopItemType::SYMBOL) {
                rop.Add(item.value, true);
            } else
                throw ExpKitError("unexpected RopAction item type %u", item.type);
        }
    }
};

struct StaticTarget: Target {
    StaticTarget(const std::string& distro, const std::string& release_name, const std::string& version = "") {
        this->distro = distro;
        this->release_name = release_name;
        this->version = version;
    }

    void AddSymbol(const std::string& name, uint64_t value) {
        symbols[name] = value;
    }

    void AddStruct(const std::string& name, uint64_t size, const std::vector<StructField>& fields) {
        Struct str { name, size };
        for (auto field : fields)
            str.fields[field.name] = field;
        structs[name] = str;
    }
};