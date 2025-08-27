#include <kernelXDK/target/Target.h>
#include <cstdint>
#include <map>
#include <string>
#include <cstring>
#include <kernelXDK/util/error.h>

std::map<RopActionId, std::string> RopActionNames {
    { RopActionId::MSLEEP, "msleep" },
    { RopActionId::COMMIT_INIT_TASK_CREDS, "commit_creds" },
    { RopActionId::SWITCH_TASK_NAMESPACES, "switch_task_namespaces" },
    { RopActionId::WRITE_WHAT_WHERE_64, "write_what_where_64" },
    { RopActionId::FORK, "fork" },
    { RopActionId::TELEFORK, "telefork" },
    { RopActionId::KPTI_TRAMPOLINE, "ret_via_kpti_retpoline" },
};

std::vector<RopItem> Target::GetItemsForAction(RopActionId id) {
  std::string name = RopActionNames.at(id);
  if (rop_actions.find(name) == rop_actions.end()) {
    throw ExpKitError("missing RopActionID %u, name=%s", id, name.c_str());
  }
  return rop_actions[name];
}

uint32_t Target::GetSymbolOffset(std::string symbol_name) const {
  auto it = symbols.find(symbol_name);
  if (it == symbols.end() || it->second == 0)
    throw ExpKitError("symbol (%s) is not available for the target",
                      symbol_name.c_str());
  return it->second;
}

void StaticTarget::AddStruct(const std::string& name, uint64_t size,
                             const std::vector<StructField>& fields) {
  Struct str{name, size, {}};
  for (auto field : fields) str.fields[field.name] = field;
  structs[name] = str;
}

void StaticTarget::AddSymbol(const std::string& name, uint64_t value) {
  symbols[name] = value;
}

StaticTarget::StaticTarget(const std::string& distro,
                           const std::string& release_name,
                           const std::string& version) {
  this->distro = distro;
  this->release_name = release_name;
  this->version = version;
}
