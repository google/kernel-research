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

    /**
     * @brief Get the offset of a symbol within the target.
     * @param symbol_name The name of the symbol.
     * @return The offset of the symbol.
     * @throws ExpKitError if the symbol is not found or has an offset of 0.
     */
    uint32_t GetSymbolOffset(std::string symbol_name) const {
        auto it = symbols.find(symbol_name);
        if (it == symbols.end() || it->second == 0)
            throw ExpKitError("symbol (%s) is not available for the target", symbol_name.c_str());
        return it->second;
    }

    /**
     * @brief Get the ROP items for a specific ROP action ID.
     * @param id The ROP action ID.
     * @return A vector of ROP items for the specified action.
     * @throws ExpKitError if the ROP action ID is not found.
     */
    std::vector<RopItem> GetItemsForAction(RopActionId id) {
        if (rop_actions.find(id) == rop_actions.end()){
            throw ExpKitError("missing RopActionID %u", id);
        }
        return rop_actions[id];
    }
};

struct StaticTarget: Target {
    /**
     * @brief Constructor for a StaticTarget.
     * @param distro The distribution name.
     * @param release_name The release name.
     * @param version The version string (optional).
     */
    StaticTarget(const std::string& distro, const std::string& release_name, const std::string& version = "") {
        this->distro = distro;
        this->release_name = release_name;
        this->version = version;
    }

    /**
     * @brief Add a symbol to the static target.
     * @param name The name of the symbol.
     * @param value The value (offset) of the symbol.
     */
    void AddSymbol(const std::string& name, uint64_t value) {
        symbols[name] = value;
    }
    
    /**
     * @brief Add a struct definition to the static target.
     * @param name The name of the struct.
     * @param size The size of the struct.
     * @param fields A vector of StructField objects representing the fields of the struct.
     */
    void AddStruct(const std::string& name, uint64_t size, const std::vector<StructField>& fields) {
        Struct str { name, size };
        for (auto field : fields)
            str.fields[field.name] = field;
        structs[name] = str;
    }
};