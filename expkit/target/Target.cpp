#include <kernelXDK/target/Target.hpp>
#include <cstdint>
#include <map>
#include <string>
#include <cstring>
#include <kernelXDK/util/error.hpp>

std::vector<RopItem> Target::GetItemsForAction(RopActionId id) {
  if (rop_actions.find(id) == rop_actions.end()) {
    throw ExpKitError("missing RopActionID %u", id);
  }
  return rop_actions[id];
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
  Struct str{name, size};
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
