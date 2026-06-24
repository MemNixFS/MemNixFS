// symbol_resolver.h — picks (or auto-generates) the right ISF file for a dump.
//
// Resolution order (each step skipped if the input doesn't apply):
//   1. If `--symbols PATH` is a file → use it (existing behaviour)
//   2. If `--symbols PATH` is a directory → walk for an ISF whose
//      metadata.kernel_release matches the dump's banner
//   3. Standard cache locations:
//        <--symbol-cache>/<release>.json{,.xz}                  (if given)
//        ./symbols/linux/<release>.json{,.xz}
//        $LMPFS_SYMBOL_CACHE/<release>.json{,.xz}
//        %LOCALAPPDATA%/MemNixFS/symbols/<release>.json{,.xz}   (Windows)
//        ~/.cache/lmpfs/symbols/<release>.json{,.xz}                    (Unix)
//   4. If `--auto-fetch` is on → invoke `tools/fetch_symbols.sh <release>`
//      (via WSL on Windows, natively on Linux) and use the result
//   5. Else: throw with a clear, copy-pasteable command
//
// All steps key off the dump's banner — no human input required.
//
#pragma once
#include "core/types.h"
#include "formats/physical_layer.h"
#include <filesystem>
#include <string>

namespace lmpfs {

struct SymbolResolveOptions {
    std::filesystem::path user_path;       // --symbols (file or directory; may be empty)
    std::filesystem::path vmlinux_path;    // --vmlinux  (we'll run dwarf2json on this)
    std::filesystem::path cache_dir;       // --symbol-cache: where downloaded/generated
                                           // ISFs are SAVED (and searched first). Empty →
                                           // $LMPFS_SYMBOL_CACHE or the platform default.
    bool                  auto_fetch  = false;   // --auto-fetch (distro pkg + dwarf2json)
    bool                  http_cache  = true;    // try community mirrors before auto-fetch
};

struct SymbolResolveResult {
    std::filesystem::path isf_path;
    std::string           kernel_release;
    std::string           how;             // "user-file" | "auto-discover" | "fetched" | …
};

// Reads the banner from `phys`, identifies the kernel release, and returns
// the path of an ISF that matches. Throws Error if no match is possible.
SymbolResolveResult resolve_symbols(const PhysicalLayer&        phys,
                                    const SymbolResolveOptions& opts);

} // namespace lmpfs
