#pragma once
#include "core/types.h"
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

namespace lmpfs {

// A single field inside a user_type (struct).
struct FieldInfo {
    u64         offset;
    std::string type_name;  // e.g. "task_struct", "list_head", "int", "char[16]"
    std::string type_kind;  // "struct", "pointer", "base", "array", "enum"
};

struct TypeInfo {
    std::string kind;       // "struct", "union", "class"
    u64         size = 0;
    std::unordered_map<std::string, FieldInfo> fields;
};

struct SymbolInfo {
    VAddr       address = 0;
    std::string type_name;
};

// Volatility3-compatible ISF symbol table.
class IsfSymbols {
public:
    // Loads a .json or .json.xz file from disk.
    static std::unique_ptr<IsfSymbols> load(const std::filesystem::path& p);

    const TypeInfo*   find_type(const std::string& name) const;
    const SymbolInfo* find_symbol(const std::string& name) const;
    u64               field_offset(const std::string& type, const std::string& field) const;
    // Like field_offset, but returns nullopt instead of throwing when the type
    // or field is absent. Use this for fields that exist only on some kernel
    // versions (e.g. mm_struct.mm_mt is 6.1+; pre-6.1 has mmap/vm_next instead).
    std::optional<u64> field_offset_opt(const std::string& type, const std::string& field) const;
    u64               type_size(const std::string& type) const;

    // Read-only access to the full symbol table — used by /sys/kallsyms to
    // generate the /proc/kallsyms-style listing.
    const std::unordered_map<std::string, SymbolInfo>& symbols() const { return symbols_; }

    // Banner (from the linux_banner symbol contents) — populated by caller.
    void set_banner(std::string b) { banner_ = std::move(b); }
    const std::string& banner() const { return banner_; }

    // The Linux kernel release extracted from ISF metadata
    // (e.g. "6.14.0-36-generic"); empty if not present.
    const std::string& kernel_release() const { return kernel_release_; }

private:
    std::unordered_map<std::string, TypeInfo>   types_;
    std::unordered_map<std::string, SymbolInfo> symbols_;
    std::string                                 banner_;
    std::string                                 kernel_release_;
};

} // namespace lmpfs
