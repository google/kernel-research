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
#include <map>
#include <string>
#include <cstring>
#include "util/error.cpp"
#include "pivot/Pivots.cpp"

enum struct RopActionId: uint32_t {
    MSLEEP = 0x01,
    COMMIT_KERNEL_CREDS = 0x02,
    SWITCH_TASK_NAMESPACES = 0x03,
    WRITE_WHAT_WHERE_64 = 0x04,
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

    std::vector<RopItem> GetItemsForAction(RopActionId id) {
        if (rop_actions.find(id) == rop_actions.end()){
            throw ExpKitError("missing RopActionID %u", id);
        }
        return rop_actions[id];
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
