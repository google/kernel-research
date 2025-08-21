#pragma once

#include <cstdint>
#include <string>
#include <map>
#include <optional>
#include <vector>
#include "target/BinaryReader.h"
#include <kernelXDK/target/Target.h>
#include <kernelXDK/pivot/Pivots.h>

struct FieldMeta {
    std::string field_name;
    bool optional;
};

struct StructMeta {
    std::string struct_name;
    std::vector<FieldMeta> fields;
};

enum class Section { Meta = 1, Targets = 2, StructLayouts = 3 };

struct SectionInfo {
    uint32_t offset;
    uint32_t size;
};

class KxdbParser: protected BinaryReader {
protected:
    uint64_t offset_targets_ = 0, offset_struct_layouts_ = 0;
    std::vector<std::string> symbol_names_;
    std::vector<StructMeta> structs_meta_;
    std::map<uint64_t, Struct> struct_layouts_;
    std::map<Section, SectionInfo> sections_;

    /**
     * @brief Parses the symbols header section of the KXDB file.
     * @details Reads the number of symbols and their metadata, storing the symbol names.
     * @throws ExpKitError if there's an error reading the binary data.
     */
    void ParseSymbolsHeader();

    /**
     * @brief Parses the symbols section for a given target.
     * @details Reads the symbol values based on the parsed symbol names and populates the target's symbols map.
     * @param target The Target object to populate with symbols.
     * @throws ExpKitError if there's an error reading the binary data.
     */
    void ParseSymbols(Target& target);

    /**
     * @brief Parses the ROP actions header section of the KXDB file.
     * @details Reads the number of ROP actions and their metadata, storing the ROP action IDs and optionally parsing detailed metadata.
     * @throws ExpKitError if there's an error reading the binary data.
     */
    void ParseRopActionsHeader();

    /**
     * @brief Parses the ROP actions section for a given target.
     * @details Reads the ROP item sequences for each ROP action based on the parsed ROP action IDs and populates the target's rop_actions map.
     * @param target The Target object to populate with ROP actions.
     * @throws ExpKitError if there's an error reading the binary data.
     */
    void ParseRopActions(Target& target);

    /**
     * @brief Reads RegisterUsage data from the binary stream.
     * @return A RegisterUsage object containing the parsed register and used offsets.
     * @throws ExpKitError if there's an error reading the binary data.
     */
    RegisterUsage ReadRegisterUsage();

    /**
     * @brief Parses the pivots section for a given target.
     * @details Reads various types of pivots (one-gadgets, push indirects, pop rsp, stack shifts) and populates the target's pivots structure.
     * @param target The Target object to populate with pivots.
     * @throws ExpKitError if there's an error reading the binary data.
     */
    void ParsePivots(Target& target);

    /**
     * @brief Parses the structs header section of the KXDB file.
     * @details Reads the metadata for each struct, including its name and fields, and stores it. Also reads the offset to the struct layouts.
     * @throws ExpKitError if there's an error reading the binary data.
     */
    void ParseStructsHeader();

    /**
     * @brief Parses a specific struct layout from the binary stream.
     * @details Seeks to the specified layout index, reads the struct's size, name, and field offsets and sizes.
     * @param layout_idx The index of the struct layout to parse.
     * @return A reference to the parsed Struct object.
     * @throws ExpKitError if there's an error reading the binary data or if a non-optional field is missing.
     */
    Struct& ParseStructLayout(uint64_t layout_idx);

    /**
     * @brief Retrieves a struct layout, parsing it if necessary.
     * @param layout_idx The index of the struct layout to retrieve.
     * @return A reference to the Struct object.
     * @throws ExpKitError if there's an error parsing the struct layout.
     */
    Struct& GetStructLayout(uint64_t layout_idx);

    /**
     * @brief Parses the structs section for a given target.
     * @details Reads the struct layout indices for each struct metadata entry and retrieves or parses the corresponding struct layouts, populating the target's structs map.
     * @param target The Target object to populate with structs.
     */
    void ParseStructs(Target& target);

    /**
     * @brief Parses targets from the KXDB file that match the optional filter criteria.
     * @param distro Optional filter for the distribution name.
     * @param release_name Optional filter for the release name.
     * @param version Optional filter for the version string.
     * @return A vector of Target objects that match the specified criteria.
     * @throws ExpKitError if there's an error parsing the binary data.
     */
    std::vector<Target> ParseTargets(
        std::optional<const std::string> distro,
        std::optional<const std::string> release_name,
        std::optional<const std::string> version);

    /**
     * @brief Parses and retrieves a single target matching the specified criteria.
     * @param distro Optional filter for the distribution name.
     * @param release_name Optional filter for the release name.
     * @param version Optional filter for the version string.
     * @param throw_on_missing If true, throws an exception if no target or multiple targets are found.
     * @return An optional containing the matched Target object, or std::nullopt if no target is found and throw_on_missing is false.
     * @throws ExpKitError if no target or multiple targets are found and throw_on_missing is true.
     */
    std::optional<Target> ParseTarget(
        std::optional<const std::string> distro,
        std::optional<const std::string> release_name,
        std::optional<const std::string> version, bool throw_on_missing);

   public:
    std::vector<RopActionMeta> rop_action_meta_;

    /**
     * @brief Constructs a KxdbParser from a buffer.
     * @param buffer The buffer containing the KXDB data.
     * @param size The size of the buffer.
     */
    KxdbParser(const uint8_t* buffer, size_t size);

    /**
     * @brief Constructs a KxdbParser from a vector of bytes.
     * @param data The vector containing the KXDB data.
     */
    KxdbParser(const std::vector<uint8_t> data);

    /**
     * @brief Constructs a KxdbParser by reading data from a file.
     * @param filename The path to the KXDB file.
     * @return A KxdbParser object initialized with the file's content.
     * @throws ExpKitError if the file cannot be read.
     */
    static KxdbParser FromFile(const std::string &filename);

    /**
     * @param log The logger instance to use.
     */
    void SetLog(ILog* log);

    /**
     * @brief Parses the header section of the KXDB file.
     * @details Reads the magic number, version, and the offsets to the different data sections (symbols, ROP actions, structs, targets). Optionally parses known metadata.
     * @throws ExpKitError if the magic number is invalid, the version is unsupported, or there's an error reading the binary data.
     */
    void ParseHeader();

    /**
     * @brief Retrieves a target by its distribution and release name.
     * @param distro The distribution name of the target.
     * @param release_name The release name of the target.
     * @param throw_on_missing If true, throws an exception if no target or multiple targets are found.
     * @return An optional containing the matched Target object, or std::nullopt if no target is found and throw_on_missing is false.
     * @throws ExpKitError if no target or multiple targets are found for the given distro and release name, and throw_on_missing is true.
     */
    std::optional<Target> GetTarget(const std::string& distro,
                                    const std::string& release_name,
                                    bool throw_on_missing = false);

    /**
     * @brief Retrieves a target by its full version string.
     * @param version The full version string of the target.
     * @param throw_on_missing If true, throws an exception if no target or multiple targets are found.
     * @return An optional containing the matched Target object, or std::nullopt if no target is found and throw_on_missing is false.
     * @throws ExpKitError if no target or multiple targets are found for the given version, and throw_on_missing is true.
     */
    std::optional<Target> GetTarget(const std::string& version,
                                    bool throw_on_missing = false);

    /**
     * @brief Retrieves all targets available in the KXDB file.
     * @return A vector of all Target objects found in the file.
     */
    std::vector<Target> GetAllTargets();
};
