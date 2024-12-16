#pragma once

#include <cstdint>
#include <map>
#include <string>
#include "util/error.cpp"
#include "pivot/Pivots.cpp"

#define SYM_FUNC   0x01000000
#define SYM_STRUCT 0x02000000
#define SYM_OPS    0x03000000

enum SymbolId: uint32_t {
    PREPARE_KERNEL_CRED =    SYM_FUNC | 0x01,
    COMMIT_CREDS =           SYM_FUNC | 0x02,
    FIND_TASK_BY_VPID =      SYM_FUNC | 0x03,
    SWITCH_TASK_NAMESPACES = SYM_FUNC | 0x04,
    __X64_SYS_FORK =         SYM_FUNC | 0x05,
    MSLEEP =                 SYM_FUNC | 0x06,

    INIT_NSPROXY =           SYM_STRUCT | 0x01,

    ANON_PIPE_BUF_OPS =      SYM_OPS | 0x01,
};

std::map<SymbolId, const char*> symbol_names {
    { PREPARE_KERNEL_CRED, "PREPARE_KERNEL_CRED" },
    { COMMIT_CREDS, "COMMIT_CREDS" },
    { FIND_TASK_BY_VPID, "FIND_TASK_BY_VPID" },
    { SWITCH_TASK_NAMESPACES, "SWITCH_TASK_NAMESPACES" },
    { __X64_SYS_FORK, "__X64_SYS_FORK" },
    { MSLEEP, "MSLEEP" },

    { INIT_NSPROXY, "INIT_NSPROXY" },

    { ANON_PIPE_BUF_OPS, "ANON_PIPE_BUF_OPS" },
};

enum struct RopActionId: uint32_t {
    MSLEEP = 0x01,
    COMMIT_KERNEL_CREDS = 0x02,
    SWITCH_TASK_NAMESPACES = 0x03,
    CORE_PATTERN_OVERWRITE = 0x04,
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

struct Target {
    static Target current;

    std::string distro;
    std::string release_name;
    std::string version;
    std::map<SymbolId, uint32_t> symbols;
    std::map<RopActionId, std::vector<RopItem>> rop_actions;
    Pivots pivots;

    Target() { }

    uint32_t GetSymbolOffset(SymbolId id) const {
        auto it = symbols.find(id);
        if (it == symbols.end() || it->second == 0)
            throw ExpKitError("symbol (%s) is not available for the target", symbol_names.at(id));
        return it->second;
    }
};

Target Target::current;