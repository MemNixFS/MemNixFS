#include "symbols/isf_symbols.h"
#include "symbols/xz_decompress.h"
#include "core/error.h"
#include "core/log.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <functional>
#include <sstream>

namespace lmpfs {

namespace {

std::string type_to_string(const nlohmann::json& t) {
    // Mirrors Volatility's intermed.py logic just enough for the names we need.
    if (!t.is_object()) return "?";
    std::string k = t.value("kind", "");
    if (k == "base" || k == "struct" || k == "union" || k == "class" || k == "enum")
        return t.value("name", "?");
    if (k == "pointer") return type_to_string(t["subtype"]) + "*";
    if (k == "array")   return type_to_string(t["subtype"]) +
                                "[" + std::to_string(t.value("count", 0)) + "]";
    if (k == "function") return "fn";
    if (k == "bitfield") return type_to_string(t["type"]);
    return k;
}

ByteBuf read_whole_uncompressed(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw_error("Cannot open {}", p.string());
    std::ostringstream ss; ss << f.rdbuf();
    auto s = ss.str();
    return ByteBuf(s.begin(), s.end());
}

} // anonymous

std::unique_ptr<IsfSymbols> IsfSymbols::load(const std::filesystem::path& p) {
    ByteBuf json_bytes;
    if (p.extension() == ".xz")          json_bytes = xz_decompress_file(p);
    else if (p.extension() == ".json")   json_bytes = read_whole_uncompressed(p);
    else {
        // Try xz first, fall back to plain.
        try { json_bytes = xz_decompress_file(p); }
        catch (...) { json_bytes = read_whole_uncompressed(p); }
    }

    log::info("Parsing ISF JSON ({} bytes uncompressed)...", json_bytes.size());
    auto root = nlohmann::json::parse(json_bytes.begin(), json_bytes.end());
    auto out = std::make_unique<IsfSymbols>();

    // Pull the kernel release from metadata.linux.symbols[0].name — typically
    // "vmlinux-<release>" — so we can sanity-check against the dump's banner.
    if (root.contains("metadata") && root["metadata"].contains("linux")) {
        const auto& lin = root["metadata"]["linux"];
        if (lin.contains("symbols") && lin["symbols"].is_array() && !lin["symbols"].empty()) {
            std::string name = lin["symbols"][0].value("name", std::string{});
            // strip "vmlinux-" prefix
            const std::string pfx = "vmlinux-";
            if (name.rfind(pfx, 0) == 0) name = name.substr(pfx.size());
            out->kernel_release_ = name;
            log::info("ISF kernel release: {}", out->kernel_release_);
        }
    }

    if (root.contains("user_types") && root["user_types"].is_object()) {
        for (auto& [name, td] : root["user_types"].items()) {
            TypeInfo ti;
            ti.kind = td.value("kind", "struct");
            ti.size = td.value("size", 0);
            if (td.contains("fields") && td["fields"].is_object()) {
                for (auto& [fname, fd] : td["fields"].items()) {
                    FieldInfo fi;
                    fi.offset = fd.value("offset", 0);
                    if (fd.contains("type")) {
                        fi.type_kind = fd["type"].value("kind", "");
                        fi.type_name = type_to_string(fd["type"]);
                    }
                    ti.fields.emplace(fname, std::move(fi));
                }
            }
            out->types_.emplace(name, std::move(ti));
        }
        // Flatten fields from anonymous unions/structs into their parents so
        // callers can look up "vm_start" on "vm_area_struct" even when it lives
        // inside an anonymous union.
        std::function<void(TypeInfo&, const std::string&, u64, int)> flatten =
            [&](TypeInfo& dst, const std::string& src_type, u64 base, int depth)
        {
            if (depth > 6) return;
            auto it = out->types_.find(src_type);
            if (it == out->types_.end()) return;
            for (const auto& [fname, fi] : it->second.fields) {
                u64 off = base + fi.offset;
                if ((fi.type_kind == "struct" || fi.type_kind == "union") &&
                    fi.type_name.rfind("unnamed_", 0) == 0) {
                    flatten(dst, fi.type_name, off, depth + 1);
                } else {
                    FieldInfo cp = fi;
                    cp.offset = off;
                    // Only insert if not already present at the parent level —
                    // outer fields take priority.
                    dst.fields.emplace(fname, std::move(cp));
                }
            }
        };
        for (auto& [tname, ti] : out->types_) {
            std::vector<std::pair<std::string, u64>> to_expand;
            for (const auto& [fname, fi] : ti.fields) {
                if ((fi.type_kind == "struct" || fi.type_kind == "union") &&
                    fi.type_name.rfind("unnamed_", 0) == 0) {
                    to_expand.emplace_back(fi.type_name, fi.offset);
                }
            }
            for (auto& [n, off] : to_expand) flatten(ti, n, off, 1);
        }
    }
    if (root.contains("base_types") && root["base_types"].is_object()) {
        // Treat base_types like 0-field types so size lookups work.
        for (auto& [name, td] : root["base_types"].items()) {
            TypeInfo ti;
            ti.kind = "base";
            ti.size = td.value("size", 0);
            out->types_.emplace(name, std::move(ti));
        }
    }
    if (root.contains("symbols") && root["symbols"].is_object()) {
        for (auto& [name, sd] : root["symbols"].items()) {
            SymbolInfo si;
            si.address = sd.value("address", 0ULL);
            if (sd.contains("type")) si.type_name = type_to_string(sd["type"]);
            out->symbols_.emplace(name, std::move(si));
        }
    }
    log::info("ISF: {} types, {} symbols", out->types_.size(), out->symbols_.size());
    return out;
}

const TypeInfo* IsfSymbols::find_type(const std::string& n) const {
    auto it = types_.find(n);
    return it == types_.end() ? nullptr : &it->second;
}
const SymbolInfo* IsfSymbols::find_symbol(const std::string& n) const {
    auto it = symbols_.find(n);
    return it == symbols_.end() ? nullptr : &it->second;
}
u64 IsfSymbols::field_offset(const std::string& t, const std::string& f) const {
    auto ti = find_type(t);
    if (!ti) throw_error("ISF: unknown type '{}'", t);
    auto it = ti->fields.find(f);
    if (it == ti->fields.end()) throw_error("ISF: type '{}' has no field '{}'", t, f);
    return it->second.offset;
}
std::optional<u64> IsfSymbols::field_offset_opt(const std::string& t, const std::string& f) const {
    auto ti = find_type(t);
    if (!ti) return std::nullopt;
    auto it = ti->fields.find(f);
    if (it == ti->fields.end()) return std::nullopt;
    return it->second.offset;
}
u64 IsfSymbols::type_size(const std::string& t) const {
    auto ti = find_type(t);
    if (!ti) throw_error("ISF: unknown type '{}'", t);
    return ti->size;
}

} // namespace lmpfs
