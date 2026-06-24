// symbol_resolver.cpp — see header.
#include "symbols/symbol_resolver.h"
#include "symbols/isf_symbols.h"
#include "symbols/symbol_cache_http.h"
#include "symbols/btf_to_isf.h"
#include "os/linux/banner_scan.h"
#include "os/linux/btf_probe.h"
#include "core/error.h"
#include "core/log.h"
#include <cstdlib>
#include <filesystem>
#include <fstream>

#ifdef _WIN32
#  include <windows.h>
#endif

namespace lmpfs {
namespace fs = std::filesystem;

namespace {

// Returns true if path is a regular file with a JSON-ish extension we'd accept.
bool looks_like_isf(const fs::path& p) {
    if (!fs::is_regular_file(p)) return false;
    auto ext = p.extension().string();
    if (ext == ".xz") {
        // strip .xz, then check inner extension
        auto base = p.stem().string();
        auto dot  = base.rfind('.');
        if (dot == std::string::npos) return false;
        ext = base.substr(dot);
    }
    return ext == ".json";
}

// Loads metadata.linux.symbols[0].name and strips the "vmlinux-" prefix to
// get the kernel release this ISF was built for. Empty string if unparseable.
std::string isf_release(const fs::path& p) {
    try {
        auto isf = IsfSymbols::load(p);
        return isf->kernel_release();
    } catch (...) {
        return {};
    }
}

// Number of kernel-VA symbols in an ISF. A BTF-derived (types-only) ISF
// returns 0 here — it can drive struct-offset reads but not symbol-anchored
// ones (init_task, super_blocks, modules, kallsyms listing, validated DTB).
// Used to decide whether a cached/generated ISF is "good enough" or whether
// we should keep looking for a symbol-rich source.
std::size_t isf_symbol_count(const fs::path& p) {
    try {
        auto isf = IsfSymbols::load(p);
        return isf->symbols().size();
    } catch (...) {
        return 0;
    }
}

// Standard cache locations to look for ISFs, in priority order. `preferred`
// (the --symbol-cache dir, may be empty) is searched first so a previously
// saved ISF there round-trips on the next run.
std::vector<fs::path> standard_cache_dirs(const fs::path& preferred) {
    std::vector<fs::path> dirs;
    if (!preferred.empty()) dirs.emplace_back(preferred);
    dirs.emplace_back("symbols/linux");
    dirs.emplace_back("symbols");
    if (const char* env = std::getenv("LMPFS_SYMBOL_CACHE"))
        dirs.emplace_back(env);
#ifdef _WIN32
    if (const char* la = std::getenv("LOCALAPPDATA"))
        dirs.emplace_back(fs::path(la) / "MemNixFS" / "symbols");
#else
    if (const char* home = std::getenv("HOME"))
        dirs.emplace_back(fs::path(home) / ".cache/lmpfs/symbols");
#endif
    return dirs;
}

// Look in `dir` for an ISF whose metadata.kernel_release == `release`.
fs::path search_dir_for_release(const fs::path& dir, const std::string& release) {
    if (!fs::is_directory(dir)) return {};
    for (auto& e : fs::recursive_directory_iterator(dir)) {
        if (!looks_like_isf(e.path())) continue;
        // Fast-path: filename contains the release.
        if (e.path().filename().string().find(release) != std::string::npos) {
            // Sanity check via metadata.
            if (isf_release(e.path()) == release) return e.path();
        }
    }
    // Slow scan: open every ISF, check metadata. Useful when files were renamed.
    for (auto& e : fs::recursive_directory_iterator(dir)) {
        if (!looks_like_isf(e.path())) continue;
        if (isf_release(e.path()) == release) return e.path();
    }
    return {};
}

// Resolves the bundled fetch_symbols.sh — searches several plausible roots so
// it works from build trees, install prefixes, and `cwd`-relative invocations.
fs::path bundled_script_path() {
    std::vector<fs::path> roots;
    if (const char* env = std::getenv("LMPFS_TOOLS_DIR"))
        roots.emplace_back(env);
    roots.emplace_back(fs::current_path());

#ifdef _WIN32
    wchar_t buf[MAX_PATH]; GetModuleFileNameW(nullptr, buf, MAX_PATH);
    fs::path exe_dir = fs::path(buf).parent_path();
#else
    fs::path exe_dir = fs::current_path();
#endif
    // Walk a few parents up from the exe to find the project / install root.
    fs::path p = exe_dir;
    for (int i = 0; i < 6; ++i) {
        roots.push_back(p);
        if (p.has_parent_path()) p = p.parent_path(); else break;
    }

    for (auto& r : roots) {
        auto candidate = r / "tools" / "fetch_symbols.sh";
        if (fs::exists(candidate)) return candidate;
    }
    return {};
}

#ifdef _WIN32
std::string to_wsl_path(const fs::path& p) {
    auto abs = fs::absolute(p).string();
    std::string out = "/mnt/";
    if (abs.size() >= 2 && abs[1] == ':') {
        out.push_back(std::tolower(abs[0]));
        out.append(abs.substr(2));
    } else {
        out = abs;
    }
    std::replace(out.begin(), out.end(), '\\', '/');
    return out;
}

// Quote a path for inclusion inside a `bash -lc "..."` command. Single-quote
// it so spaces, parens, etc. survive; embedded single-quotes are escaped via
// the standard '\'' trick.
std::string sq(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('\'');
    for (char c : s) {
        if (c == '\'') out += "'\\''";
        else            out.push_back(c);
    }
    out.push_back('\'');
    return out;
}
#endif

// Output directory for fetched / generated ISFs. Precedence:
//   1. `preferred` (--symbol-cache), if given
//   2. $LMPFS_SYMBOL_CACHE (so the env var actually overrides the *save* dir,
//      matching its documented "override the symbol cache dir" behaviour)
//   3. platform default (%LOCALAPPDATA%/MemNixFS/symbols | ~/.cache/lmpfs/symbols)
fs::path cache_output_dir(const fs::path& preferred) {
    if (!preferred.empty()) return preferred;
    if (const char* env = std::getenv("LMPFS_SYMBOL_CACHE"))
        return fs::path(env);
#ifdef _WIN32
    if (const char* la = std::getenv("LOCALAPPDATA"))
        return fs::path(la) / "MemNixFS" / "symbols";
#else
    if (const char* home = std::getenv("HOME"))
        return fs::path(home) / ".cache/lmpfs/symbols";
#endif
    return fs::current_path() / "symbols" / "linux";
}

// Attempts to generate `release`.json.xz into `out_dir` via the bundled
// script. Returns the produced ISF path on success. If `vmlinux` is non-empty
// the script skips the distro install step and runs dwarf2json directly on it.
fs::path try_fetch(const std::string& release, const fs::path& out_dir,
                   const fs::path& vmlinux = {}) {
    auto script = bundled_script_path();
    if (script.empty()) {
        log::warn("auto-fetch: tools/fetch_symbols.sh not found "
                  "(set LMPFS_TOOLS_DIR or run from project root)");
        return {};
    }
    log::debug("auto-fetch: using script {}", script.string());
    if (!vmlinux.empty())
        log::debug("auto-fetch: with user-supplied vmlinux {}", vmlinux.string());

    fs::create_directories(out_dir);
    fs::path out_isf = out_dir / (release + ".json.xz");

#ifdef _WIN32
    // Invoke via WSL. Script + output + optional vmlinux paths may contain
    // spaces (e.g. "Real Projects"), so single-quote each argument.
    auto script_wsl = to_wsl_path(script);
    auto out_wsl    = to_wsl_path(out_isf);
    std::string inner = sq(script_wsl) + " " + sq(release) + " " + sq(out_wsl);
    if (!vmlinux.empty())
        inner += " " + sq(to_wsl_path(vmlinux));
    std::string cmd = "wsl.exe bash -lc \"" + inner + "\"";
    log::debug("auto-fetch: invoking WSL → {}", cmd);
    int rc = std::system(cmd.c_str());
#else
    std::string cmd = script.string() + " '" + release
                      + "' '" + out_isf.string() + "'";
    if (!vmlinux.empty()) cmd += " '" + vmlinux.string() + "'";
    log::debug("auto-fetch: {}", cmd);
    int rc = std::system(cmd.c_str());
#endif
    if (rc != 0) {
        log::error("auto-fetch: script exited with code {}", rc);
        return {};
    }
    if (!fs::exists(out_isf)) {
        log::error("auto-fetch: script succeeded but no output at {}", out_isf.string());
        return {};
    }
    return out_isf;
}

[[noreturn]] void cannot_resolve(const std::string& release,
                                 const std::string& distro,
                                 const SymbolResolveOptions& opts)
{
    std::string hint;
    if (distro == "ubuntu") {
        hint = "  # Ubuntu kernel debug symbols are on the ddebs repo.\n"
               "  # Pass --auto-fetch to have us run this automatically,\n"
               "  # OR run the bundled script yourself in WSL:\n"
               "  wsl bash -lc \"tools/fetch_symbols.sh '" + release + "'\"\n";
    } else {
        hint = "  # Refer to your distro's documentation for kernel-debug packages,\n"
               "  # then run dwarf2json against the resulting vmlinux:\n"
               "  dwarf2json linux --elf /path/to/vmlinux-" + release + " | xz > out.json.xz\n";
    }
    throw_error(
        "No ISF found for kernel release '{}' (distro hint: {}).\n"
        "Searched: {}, ./symbols/linux/, $LMPFS_SYMBOL_CACHE, %LOCALAPPDATA%/MemNixFS/symbols.\n"
        "{}",
        release, distro,
        opts.user_path.empty() ? std::string("(no --symbols path)")
                               : opts.user_path.string(),
        hint);
}

} // anonymous

SymbolResolveResult resolve_symbols(const PhysicalLayer&        phys,
                                    const SymbolResolveOptions& opts)
{
    // Step 1: user-supplied file — use it directly (matching the historical
    // CLI). The banner-vs-ISF mismatch check still happens later in
    // resolve_kernel(), so wrong files still get flagged loudly.
    if (!opts.user_path.empty() && fs::is_regular_file(opts.user_path)) {
        return { opts.user_path, /*release=*/{}, "user-file" };
    }

    // We need the dump's banner for everything below.
    log::debug("Scanning dump for banner to identify kernel release...");
    auto banner  = linux::find_banner_in_dump(phys);
    if (banner.empty())
        throw_error("Cannot find 'Linux version' banner in dump — corrupt? Unsupported format?");
    auto release = linux::parse_kernel_release(banner);
    auto distro  = linux::parse_distro(banner);
    if (release.empty())
        throw_error("Banner found but unparseable: '{}'", banner.substr(0, 200));
    log::note("Detected kernel release: {} (distro={}, banner shown above)", release, distro);

    // Directory where any downloaded / generated ISF is saved (and which is
    // searched first). Honors --symbol-cache, then $LMPFS_SYMBOL_CACHE.
    const fs::path out_dir = cache_output_dir(opts.cache_dir);

    // Step 2: user gave a directory? walk it.
    if (!opts.user_path.empty() && fs::is_directory(opts.user_path)) {
        auto p = search_dir_for_release(opts.user_path, release);
        if (!p.empty()) {
            log::info("Auto-picked ISF from --symbols dir: {}", p.string());
            return { p, release, "auto-discover-user-dir" };
        }
    }

    // A symbol-less (BTF/types-only) ISF found in the cache must NOT short-
    // circuit the chain — otherwise the tool stays permanently degraded once
    // it has cached one, never trying the HTTP mirror / auto-fetch that could
    // supply a symbol-rich ISF. We remember it here and only fall back to it
    // at the very end if no symbol-rich source pans out.
    fs::path    types_only_fallback;
    std::string types_only_how;
    bool        have_types_only_cache = false;

    // Step 3: standard cache locations (--symbol-cache dir searched first).
    for (auto& d : standard_cache_dirs(opts.cache_dir)) {
        auto p = search_dir_for_release(d, release);
        if (!p.empty()) {
            std::size_t nsym = isf_symbol_count(p);
            if (nsym > 0) {
                log::info("Auto-picked ISF from cache {}: {} ({} symbols)",
                          d.string(), p.string(), nsym);
                return { p, release, "auto-discover-cache" };
            }
            // Types-only cache hit — keep as fallback, keep looking.
            log::warn("Cached ISF {} is types-only (0 symbols); will try "
                      "symbol-rich sources before falling back to it",
                      p.string());
            if (types_only_fallback.empty()) {
                types_only_fallback   = p;
                types_only_how        = "auto-discover-cache (types-only)";
                have_types_only_cache = true;
            }
            break;   // one cache hit is enough to record the fallback
        }
    }

    // Step 3.5: BTF + kallsyms in the dump itself (truly offline — no toolchain,
    // no network, no separate file). Modern kernels (≥ 5.x with
    // CONFIG_DEBUG_INFO_BTF=y) embed ~3 MB of BTF in `.BTF`. kallsyms is
    // present in every CONFIG_KALLSYMS=y kernel (i.e. all distro kernels).
    // Together they produce a fully-functional ISF.
    //
    // Skip this entirely if the cache already holds a types-only ISF: BTF
    // generation is deterministic per dump, so it would reproduce the exact
    // same 0-symbol result we already have. No point burning the seconds.
    if (!have_types_only_cache) {
        // Extract kallsyms ONCE up-front so the same data is reused across
        // any BTF candidates we try.
        log::debug("Extracting kallsyms from the dump...");
        auto kallsyms = linux::extract_kallsyms(phys);
        if (kallsyms.ok) {
            log::debug("kallsyms: {} symbols (relative_base = {:#x})",
                      kallsyms.symbols.size(), kallsyms.relative_base);
        } else {
            log::warn("kallsyms extraction failed: {} — produced ISF will "
                      "lack a symbols section", kallsyms.error);
        }

        auto btf_blobs = linux::probe_btf_all(phys);
        // Try the few largest; smaller ones are per-module BTF and won't have
        // the full kernel type universe.
        for (std::size_t i = 0; i < btf_blobs.size() && i < 3; ++i) {
            const auto& info = btf_blobs[i];
            log::debug("Trying BTF→ISF from blob #{} ({} bytes @ PA {:#x})",
                       i + 1, info.size, info.offset_pa);
            auto blob = linux::read_btf(phys, info);
            std::filesystem::path out = out_dir / (release + ".json.xz");
            auto r = btf_to_isf(blob, release, out,
                                kallsyms.ok ? &kallsyms : nullptr);
            if (!r.ok) {
                log::debug("  BTF→ISF failed: {}", r.error);
                continue;
            }
            // Validate by round-trip: load the freshly-written ISF, check it
            // parses and has the expected kernel release.
            if (isf_release(out) != release) {
                log::debug("  generated ISF kernel_release mismatch (got '{}')",
                           isf_release(out));
                // Keep it anyway — release tag is metadata-only; the types are
                // still valid. (Falls through to user choice.)
            }
            if (r.symbol_count > 0) {
                log::info("BTF→ISF: generated {} ({} types, {} symbols) — "
                          "using as our ISF",
                          out.string(), r.type_count, r.symbol_count);
                return { out, release, "btf+kallsyms-from-dump" };
            }
            // Types-only result (kallsyms not recoverable from this dump).
            // Keep it as a fallback, but try the symbol-rich sources below
            // (HTTP mirror / auto-fetch) before settling for it.
            log::warn("BTF→ISF: generated {} types but 0 symbols "
                      "(kallsyms not in dump) — keeping as fallback, trying "
                      "symbol-rich sources next", r.type_count);
            if (types_only_fallback.empty()) {
                types_only_fallback = out;
                types_only_how      = "btf-from-dump (types-only)";
            }
            break;   // regenerating from another BTF blob gives the same
        }
    }

    // Step 4: --vmlinux escape hatch (offline-capable).
    if (!opts.vmlinux_path.empty()) {
        if (!fs::is_regular_file(opts.vmlinux_path))
            throw_error("--vmlinux file does not exist: {}", opts.vmlinux_path.string());
        log::info("Generating ISF from user-supplied vmlinux: {}", opts.vmlinux_path.string());
        auto p = try_fetch(release, out_dir, opts.vmlinux_path);
        if (!p.empty()) {
            log::info("Generated + cached ISF at: {}", p.string());
            return { p, release, "from-vmlinux" };
        }
        log::error("ISF generation from vmlinux failed");
    }

    // Step 5: community symbol-cache HTTP fetch (no local toolchain needed).
    if (opts.http_cache) {
        log::debug("Trying community symbol cache (HTTP)...");
        auto r = fetch_isf_from_mirrors(banner, release, out_dir,
                                        default_isf_mirrors());
        if (r.ok) {
            log::info("Downloaded ISF from {}", r.from_url);
            return { r.path, release, "community-cache" };
        }
        log::debug("HTTP cache miss: {}", r.error);
    }

    // Step 6: auto-fetch via distro debug packages (needs network + WSL/native).
    if (opts.auto_fetch) {
        log::debug("--auto-fetch enabled, running symbol-fetch pipeline...");
        auto p = try_fetch(release, out_dir);
        if (!p.empty()) {
            log::info("Fetched + cached ISF at: {}", p.string());
            return { p, release, "auto-fetched" };
        }
        log::error("Auto-fetch did not produce an ISF.");
    }

    // No symbol-rich source panned out. If we stashed a types-only ISF along
    // the way (cached or freshly BTF-generated), fall back to it now — running
    // degraded beats not running at all. Process/VMA/fd/dcache views still
    // work via struct offsets; only symbol-anchored features (modules, dmesg,
    // validated DTB, /sys/kallsyms) stay limited.
    if (!types_only_fallback.empty()) {
        log::warn("No symbol-rich ISF available for {} — falling back to "
                  "types-only ISF {} (degraded: kernel-VA symbol anchors "
                  "unavailable). For full symbols, re-run with --auto-fetch "
                  "or --vmlinux <path>.",
                  release, types_only_fallback.string());
        return { types_only_fallback, release, types_only_how };
    }

    cannot_resolve(release, distro, opts);
}

} // namespace lmpfs
