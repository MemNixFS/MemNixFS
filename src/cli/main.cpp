#include "app/engine.h"
#include "core/log.h"
#include "core/error.h"
#include "formats/format_factory.h"
#include "io/memory_source.h"
#include "symbols/kallsyms.h"
#include "os/linux/dmesg.h"
#include <fmt/format.h>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fmt/color.h>

#ifdef _WIN32
  #include <io.h>
  #include <windows.h>
#else
  #include <unistd.h>
#endif

#if defined(LMPFS_HAS_WINFSP)
namespace lmpfs::mount {
int run_winfsp_mount(lmpfs::Engine& eng, const std::string& mount_point);
}
#endif
#ifdef LMPFS_HAS_FUSE
namespace lmpfs::mount {
int run_fuse_mount(lmpfs::Engine& eng, const std::string& mount_point);
}
#endif

#ifndef LMPFS_VERSION
#define LMPFS_VERSION "0.37.1"
#endif

// Exported from memnixfs.dll (src/api/lmpfs.cpp). Called after
// Engine::create so /plugins/<plugin>/ paths are visible through every
// CLI subcommand including `mount`.
extern "C" void lmpfs_internal_scan_plugins(lmpfs::Engine* eng);

namespace {

void usage() {
    fmt::print(stderr,
        "MemNixFS " LMPFS_VERSION "\n"
        "Usage:\n"
        "  memnixfs --dump <file> [--symbols <path>] [--auto-fetch] [command]\n"
        "\n"
        "Primary command (the whole point of this project):\n"
#ifdef LMPFS_HAS_WINFSP
        "  mount <pt>          Mount as a Windows filesystem via WinFsp.\n"
        "                      <pt> is a drive letter (e.g. M:) or an empty\n"
        "                      directory. Once mounted, browse the dump in\n"
        "                      Explorer / cmd / PowerShell like any disk:\n"
        "                        M:\\fs\\ reconstructed root filesystem\n"
        "                        M:\\proc\\ per-process analysis dirs\n"
        "                        M:\\sys\\ kernel diagnostics\n"
        "                        M:\\files\\ page-cache file recovery\n"
        "                        M:\\mem\\  phys.raw + helpers\n"
#elif defined(LMPFS_HAS_FUSE)
        "  mount <pt>          Mount as a read-only FUSE filesystem.\n"
        "                      <pt> is an existing empty directory. Browse it\n"
        "                      with ls/cat/find like any mounted filesystem:\n"
        "                        <pt>/fs      reconstructed root filesystem\n"
        "                        <pt>/proc    per-process analysis dirs\n"
        "                        <pt>/sys     kernel diagnostics\n"
        "                        <pt>/files   page-cache file recovery\n"
        "                        <pt>/mem     phys.raw + helpers\n"
#else
        "  mount               (UNAVAILABLE - build with WinFsp on Windows\n"
        "                       or FUSE on Linux.)\n"
#endif
        "\n"
        "Other commands (CLI smoke tests over the same VFS):\n"
        "  (no command)        Short overview + suggested next commands\n"
        "  list                List processes (full table)\n"
        "  tree                Print the VFS tree\n"
        "  cat <vfs-path>      Dump a single VFS file to stdout. Pair with\n"
        "                      --offset OFF --length LEN to window into huge\n"
        "                      streams (e.g. /mem/kern_va.raw, /mem/phys.raw).\n"
        "                      OFF/LEN accept 0x... hex, decimal, or K/M/G/T\n"
        "                      suffix (e.g. --offset 0x80000000 --length 64K).\n"
        "  export <dir>        Write the VFS to a real folder (huge; avoid)\n"
        "  kallsyms [name]     Extract kernel symbols straight from the dump\n"
        "                      (no ISF needed). With [name], print just that symbol.\n"
        "  dmesg               Print the kernel's printk ring buffer\n"
        "                      (/var/log/kern.log-style timestamped messages).\n"
        "\n"
        "Symbol resolution (each step tried in turn):\n"
        "  --symbols PATH      Explicit ISF .json[.xz] file OR a directory to\n"
        "                      search; omit to auto-discover from caches.\n"
        "  --vmlinux PATH      Generate ISF from this user-supplied vmlinux\n"
        "                      (offline; runs dwarf2json via WSL on Windows).\n"
        "                      Highest-leverage escape hatch for custom kernels.\n"
        "  --symbol-cache DIR  Directory where auto-downloaded / generated ISFs\n"
        "                      are SAVED (and searched first on the next run).\n"
        "                      Overrides $LMPFS_SYMBOL_CACHE and the default\n"
        "                      %%LOCALAPPDATA%%/MemNixFS/symbols. Created if absent.\n"
        "  --auto-fetch        Run tools/fetch_symbols.sh to download the\n"
        "                      matching kernel-debug package (Ubuntu/Debian/\n"
        "                      Fedora/RHEL/Arch/openSUSE).\n"
        "  --no-http-cache     Disable the community symbol-mirror lookup\n"
        "                      (HTTP). Useful for air-gapped / offline runs.\n"
        "  --forensic[=MODE]   Pre-warm expensive-but-small files in the\n"
        "                      background so browsing/opening them is instant.\n"
        "                      MODE = quick | smart (default) | full:\n"
        "                        quick = system-wide only (findevil, dmesg)\n"
        "                        smart = quick + per-process analytics (no yara)\n"
        "                        full  = smart + per-process yara + every light\n"
        "                                system-wide file (i.e. also does what\n"
        "                                --precompute does). The maximal mode.\n"
        "                      Mount stays responsive; memory-heavy files (e.g.\n"
        "                      strings.txt) stay lazy.\n"
        "  --forensic-include CATS   Add categories (comma list).\n"
        "  --forensic-exclude CATS   Drop categories, e.g. --forensic=full\n"
        "                      --forensic-exclude yara. Categories: system-info,\n"
        "                      threat-hunt, per-process, yara.\n"
        "  --precompute        Background-warm the system-wide analysis files so\n"
        "                      the tree shows real sizes and opens instantly\n"
        "                      (/sys, /sys/net, modules). Cheapest-first; mount\n"
        "                      stays responsive. Heavy corpus/per-process scans\n"
        "                      (findevil, /search yara+iocs, /forensic aggregates,\n"
        "                      /proc per-process, /files,/fs content) stay\n"
        "                      on-demand -- add --forensic to also warm those.\n"
        "Environment:\n"
        "  LMPFS_SYMBOL_CACHE  Override the symbol cache dir for both saving and\n"
        "                      searching (default: %%LOCALAPPDATA%%/MemNixFS/\n"
        "                      symbols). --symbol-cache takes precedence.\n"
        "  LMPFS_ISF_MIRRORS   Semicolon-separated list of mirror URL templates,\n"
        "                      each containing {{KEY}} (banner sha256) and/or\n"
        "                      {{KEY:0:2}} (first 2 chars).\n"
        "Other:\n"
        "  -v, --verbose       Verbose: show the diagnostic pipeline logging\n"
        "                      (symbol resolution, page-table/DTB scans, etc.).\n"
        "  -vv                 Even more verbose (trace).\n"
        "  -q, --quiet         Quiet: print critical errors only.\n");
}

void export_tree(const lmpfs::vfs::NodePtr& n, const std::filesystem::path& out) {
    namespace fs = std::filesystem;
    if (n->is_dir()) {
        fs::create_directories(out);
        for (auto& e : n->list()) export_tree(e.node, out / e.name);
    } else {
        std::ofstream f(out, std::ios::binary);
        const std::size_t kBuf = 64 * 1024;
        std::vector<char> buf(kBuf);
        std::uint64_t off = 0;
        while (true) {
            std::size_t got = n->read(off, buf.data(), buf.size());
            if (got == 0) break;
            f.write(buf.data(), got);
            off += got;
            if (got < buf.size()) break;
        }
    }
}

void print_tree(const lmpfs::vfs::NodePtr& n, std::string indent = "") {
    fmt::print("{}{}{}\n", indent, n->is_dir() ? "[DIR] " : "      ", n->name());
    if (n->is_dir()) for (auto& e : n->list()) print_tree(e.node, indent + "  ");
}

// ---- stdout color ---------------------------------------------------------
// Colour is opt-out: on when stdout is a real terminal and NO_COLOR is unset,
// off when piped/redirected so captured output stays clean. On Windows we
// flip the console into ANSI/VT mode so the codes render in cmd.exe too.
bool g_use_color = false;

void init_console_color() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    const bool tty = _isatty(_fileno(stdout)) != 0;
#else
    const bool tty = isatty(fileno(stdout)) != 0;
#endif
    g_use_color = tty && std::getenv("NO_COLOR") == nullptr;
}

template <typename... A>
void cprint(const fmt::text_style& st, fmt::format_string<A...> f, A&&... a) {
    const std::string s = fmt::format(f, std::forward<A>(a)...);
    if (g_use_color) fmt::print(st, "{}", s);
    else             fmt::print("{}", s);
}

} // anonymous

int main(int argc, char** argv) {
    using lmpfs::log::Level;
    using lmpfs::log::set_level;
    init_console_color();

    std::filesystem::path dump, syms, vmlinux, symbol_cache;
    std::string command = "overview";
    std::string mount_point;
    bool auto_fetch = false;
    bool no_http_cache = false;
    bool forensic = false;
    bool precompute = false;               // --precompute: warm everything
    std::string forensic_mode = "smart";   // quick | smart | full
    std::string forensic_include;          // comma list of categories to add
    std::string forensic_exclude;          // comma list of categories to drop
    // Optional window for `cat` (useful for /mem/{phys,kern_va}.raw — those
    // are huge sparse streams; you almost never want to dump them whole).
    std::uint64_t cat_offset = 0;
    std::uint64_t cat_length = 0;   // 0 = read to EOF (legacy behavior)

    auto parse_u64 = [](const char* s) -> std::uint64_t {
        // Accepts 0x... hex, plain decimal, or trailing K/M/G suffix.
        std::string t(s);
        std::uint64_t mult = 1;
        if (!t.empty()) {
            char c = static_cast<char>(std::toupper((unsigned char)t.back()));
            if (c == 'K')      { mult = 1ULL << 10; t.pop_back(); }
            else if (c == 'M') { mult = 1ULL << 20; t.pop_back(); }
            else if (c == 'G') { mult = 1ULL << 30; t.pop_back(); }
            else if (c == 'T') { mult = 1ULL << 40; t.pop_back(); }
        }
        int base = 10;
        if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) base = 16;
        return std::stoull(t, nullptr, base) * mult;
    };

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-v" || a == "--verbose")  set_level(Level::Debug);
        else if (a == "-vv")  set_level(Level::Trace);
        else if (a == "-q" || a == "--quiet") set_level(Level::Error);
        else if (a == "-h" || a == "--help") { usage(); return 0; }
        else if (a == "--dump"     && i + 1 < argc) dump = argv[++i];
        else if (a == "--symbols"  && i + 1 < argc) syms = argv[++i];
        else if (a == "--vmlinux"  && i + 1 < argc) vmlinux = argv[++i];
        else if ((a == "--symbol-cache" || a == "--symbols-cache") && i + 1 < argc)
            symbol_cache = argv[++i];
        else if (a == "--auto-fetch") auto_fetch = true;
        else if (a == "--no-http-cache") no_http_cache = true;
        else if (a == "--forensic") forensic = true;
        else if (a.rfind("--forensic=", 0) == 0) {
            forensic = true;
            forensic_mode = a.substr(std::string("--forensic=").size());
        }
        else if (a == "--forensic-include" && i + 1 < argc) {
            forensic = true; forensic_include = argv[++i];
        }
        else if (a == "--forensic-exclude" && i + 1 < argc) {
            forensic = true; forensic_exclude = argv[++i];
        }
        else if (a == "--precompute") precompute = true;
        else if (a == "--offset"   && i + 1 < argc) cat_offset = parse_u64(argv[++i]);
        else if (a == "--length"   && i + 1 < argc) cat_length = parse_u64(argv[++i]);
        else if (a == "list" || a == "tree" || a == "dmesg" || a == "overview") command = a;
        else if (a == "cat" && i + 1 < argc) {
            command = "cat"; mount_point = argv[++i];   // mount_point reused as path
        }
        else if (a == "export" && i + 1 < argc) {
            command = "export"; mount_point = argv[++i];
        }
        else if (a == "mount" && i + 1 < argc) {
            command = "mount"; mount_point = argv[++i];
        }
        else if (a == "kallsyms") {
            command = "kallsyms";
            // Optional positional: a single symbol name to look up.
            if (i + 1 < argc && argv[i + 1][0] != '-') mount_point = argv[++i];
        } else {
            fmt::print(stderr, "Unknown arg: {}\n\n", a); usage(); return 2;
        }
    }

    // `syms` may be empty (auto-discovery) — only the dump is mandatory.
    if (dump.empty()) { usage(); return 2; }

    try {
        // `kallsyms` runs directly off the physical layer — no Engine, no ISF,
        // no banner needed. Useful for triaging dumps where everything else fails.
        if (command == "kallsyms") {
            auto src  = lmpfs::open_best_memory_source(dump);
            auto phys = lmpfs::open_physical_layer(std::move(src));
            auto r    = lmpfs::linux::extract_kallsyms(*phys);
            if (!r.ok) {
                fmt::print(stderr, "kallsyms extraction failed: {}\n", r.error);
                return 1;
            }
            if (!mount_point.empty()) {
                auto* e = lmpfs::linux::find_symbol(r, mount_point);
                if (!e) {
                    fmt::print(stderr, "Symbol not found: {}\n", mount_point);
                    return 1;
                }
                fmt::print("{:#018x} {} {}\n", e->address, e->type, e->name);
                return 0;
            }
            // Bulk dump: report the totals + a handful of well-known symbols
            // for quick sanity-checking against /proc/kallsyms on a live system.
            fmt::print("\nkallsyms: {} symbols  (relative_base = {:#x})\n",
                       r.num_syms, r.relative_base);
            fmt::print("Tables (PA): names={:#x} markers={:#x} token_table={:#x} "
                       "token_index={:#x} num_syms={:#x} offsets={:#x} relative_base={:#x}\n\n",
                       r.names_pa, r.markers_pa, r.token_table_pa, r.token_index_pa,
                       r.num_syms_pa, r.offsets_pa, r.relative_base_pa);
            static const char* well_known[] = {
                "linux_banner", "init_task", "init_top_pgt", "swapper_pg_dir",
                "modules", "log_buf", "log_buf_len", "kallsyms_addresses",
                "kallsyms_offsets", "kallsyms_relative_base", "kallsyms_num_syms",
                "kallsyms_names", "kallsyms_markers", "kallsyms_token_table",
                "kallsyms_token_index", "_text", "_etext", "_stext",
            };
            fmt::print("{:>18}  T  Name\n", "Address");
            fmt::print("{:->18}--+-{:->32}\n", "", "");
            for (const char* n : well_known) {
                auto* e = lmpfs::linux::find_symbol(r, n);
                if (e) fmt::print("{:#018x}  {}  {}\n", e->address, e->type, e->name);
                else   fmt::print("{:>18}  ?  {} (NOT FOUND)\n", "-", n);
            }
            return 0;
        }

        lmpfs::Engine::Options opts{};
        opts.dump_path          = dump;
        opts.symbols_path       = syms;
        opts.vmlinux_path       = vmlinux;
        opts.symbol_cache_dir   = symbol_cache;
        opts.auto_fetch_symbols = auto_fetch;
        opts.http_symbol_cache  = !no_http_cache;
        opts.forensic           = forensic;
        // --forensic=full is the maximal mode: it subsumes --precompute (warm
        // the light, system-wide files too) on top of its heavy per-process /
        // findevil / yara analytics. So full ⊇ precompute ⊇ the rest.
        opts.precompute         = precompute || (forensic && forensic_mode == "full");
        if (forensic) {
            using Cat = lmpfs::vfs::FileCost::Category;
            // Map a category token to its bit, or 0 if unknown.
            auto cat_bit = [](const std::string& t) -> unsigned {
                if (t == "system-info" || t == "sysinfo") return lmpfs::vfs::warm_bit(Cat::SystemInfo);
                if (t == "threat-hunt" || t == "findevil") return lmpfs::vfs::warm_bit(Cat::ThreatHunt);
                if (t == "per-process" || t == "procs")    return lmpfs::vfs::warm_bit(Cat::PerProcess);
                if (t == "yara")                            return lmpfs::vfs::warm_bit(Cat::Yara);
                return 0;
            };
            auto apply = [&](const std::string& csv, bool add) {
                std::size_t i2 = 0;
                while (i2 < csv.size()) {
                    std::size_t j = csv.find(',', i2);
                    if (j == std::string::npos) j = csv.size();
                    std::string tok = csv.substr(i2, j - i2);
                    unsigned b = cat_bit(tok);
                    if (b == 0)
                        lmpfs::log::warn("--forensic: unknown category '{}' "
                            "(valid: system-info, threat-hunt, per-process, yara)", tok);
                    else if (add) opts.forensic_mask |= b;
                    else          opts.forensic_mask &= ~b;
                    i2 = j + 1;
                }
            };
            // Base set from the mode. SystemInfo + ThreatHunt are always in;
            // smart adds per-process; full adds yara on top.
            const unsigned sysinfo = lmpfs::vfs::warm_bit(Cat::SystemInfo);
            const unsigned hunt    = lmpfs::vfs::warm_bit(Cat::ThreatHunt);
            const unsigned proc    = lmpfs::vfs::warm_bit(Cat::PerProcess);
            const unsigned yara    = lmpfs::vfs::warm_bit(Cat::Yara);
            if      (forensic_mode == "quick") opts.forensic_mask = sysinfo | hunt;
            else if (forensic_mode == "full")  opts.forensic_mask = sysinfo | hunt | proc | yara;
            else {
                if (forensic_mode != "smart")
                    lmpfs::log::warn("--forensic: unknown mode '{}' - using 'smart'", forensic_mode);
                opts.forensic_mask = sysinfo | hunt | proc;   // smart (default)
            }
            apply(forensic_include, /*add=*/true);
            apply(forensic_exclude, /*add=*/false);
        }
        const auto t_load0 = std::chrono::steady_clock::now();
        auto eng = lmpfs::Engine::create(opts);

        // v0.25 — run the plugin scanner so /plugins/<plugin>/ is visible
        // through `mount`, `tree`, `cat`, `export`. The function lives in
        // memnixfs.dll; the EXE links it via the import lib.
        lmpfs_internal_scan_plugins(eng.get());
        lmpfs::log::note("Loaded in {:.1f}s", std::chrono::duration<double>(
            std::chrono::steady_clock::now() - t_load0).count());

        if (command == "dmesg") {
            // Quick path: dump /sys/dmesg directly without exporting the
            // entire VFS. Useful for fast triage / regression testing.
            auto body = lmpfs::linux::format_dmesg(*eng);
            std::cout.write(reinterpret_cast<const char*>(body.data()),
                            body.size());
            return 0;
        }
        else if (command == "overview") {
            // Default when no command is given: a short, friendly summary
            // instead of dumping the whole process table. Points at the
            // commands that actually do something.
#if defined(LMPFS_HAS_WINFSP)
            const char* mount_hint = "mount M:";
#elif defined(LMPFS_HAS_FUSE)
            const char* mount_hint = "mount /mnt/dump";
#else
            const char* mount_hint = "mount <pt>";
#endif
            fmt::print("\n");
            cprint(fmt::emphasis::bold | fmt::fg(fmt::color::cyan), "MemNixFS " LMPFS_VERSION);
            fmt::print("  —  ");
            cprint(fmt::fg(fmt::color::spring_green), "{}", eng->processes().size());
            fmt::print(" processes, filesystem reconstructed.\n\n");
            auto hint = [](const char* cmd, const char* desc) {
                fmt::print("  ");
                cprint(fmt::emphasis::bold | fmt::fg(fmt::color::spring_green), "{:<34}", cmd);
                cprint(fmt::fg(fmt::color::gray), "{}\n", desc);
            };
            hint(mount_hint,                       "browse the whole image as a drive");
            hint("cat /sys/findevil/findevil.txt", "one-shot kernel-compromise triage");
            hint("list",                           "full process table");
            hint("tree",                           "the entire VFS tree");
            hint("-h",                             "all commands and options");
            fmt::print("\n");
        }
        else if (command == "list") {
            cprint(fmt::emphasis::bold | fmt::fg(fmt::color::cyan),
                   "\n{:>6}  {:>6}  {:>6}  {:>6}  {:>6}  {}\n",
                   "PID", "TGID", "PPID", "UID", "GID", "COMM");
            cprint(fmt::fg(fmt::color::gray), "{:->60}\n", "");
            for (const auto& p : eng->processes()) {
                // Kernel threads (children of kthreadd, pid 2) are dimmed so
                // real userspace processes stand out.
                const bool kthread = (p.ppid == 2 || p.pid == 2);
                cprint(kthread ? fmt::fg(fmt::color::gray) : fmt::text_style{},
                       "{:>6}  {:>6}  {:>6}  {:>6}  {:>6}  {}\n",
                       p.pid, p.tgid, p.ppid, p.uid, p.gid, p.comm);
            }
            cprint(fmt::fg(fmt::color::gray), "\nTotal: {} processes\n", eng->processes().size());
        } else if (command == "tree") {
            print_tree(eng->vfs_root());
        } else if (command == "cat") {
            // Dump a single VFS file to stdout. Avoids touching disk and is
            // perfect for quick parser regression checks. With --offset /
            // --length you can window into huge sparse streams like
            // /mem/phys.raw and /mem/kern_va.raw without trying to read the
            // whole 128 TiB.
            auto node = lmpfs::vfs::resolve(eng->vfs_root(), mount_point);
            if (!node || !node->is_file()) {
                fmt::print(stderr, "cat: not a file: {}\n", mount_point);
                return 1;
            }
            const std::size_t kBuf = 64 * 1024;
            std::vector<char> buf(kBuf);
            std::uint64_t off = cat_offset;
            // length==0  ⇒  read until producer returns 0 (legacy behavior,
            // matches dumping a finite file end-to-end).
            const bool bounded = cat_length != 0;
            std::uint64_t remaining = bounded ? cat_length
                                              : std::numeric_limits<std::uint64_t>::max();
            while (remaining > 0) {
                std::size_t want = static_cast<std::size_t>(
                    std::min<std::uint64_t>(remaining, buf.size()));
                std::size_t got = node->read(off, buf.data(), want);
                if (got == 0) break;
                std::cout.write(buf.data(), got);
                off += got;
                if (bounded) remaining -= got;
                if (got < want) break;
            }
        } else if (command == "export") {
            std::filesystem::path out(mount_point);
            export_tree(eng->vfs_root(), out);
            fmt::print("Exported VFS to: {}\n", out.string());
        }
#ifdef LMPFS_HAS_WINFSP
        else if (command == "mount") {
            return lmpfs::mount::run_winfsp_mount(*eng, mount_point);
        }
#elif defined(LMPFS_HAS_FUSE)
        else if (command == "mount") {
            return lmpfs::mount::run_fuse_mount(*eng, mount_point);
        }
#else
        else if (command == "mount") {
            fmt::print(stderr,
                       "mount: unavailable in this build; enable WinFsp on "
                       "Windows or FUSE on Linux.\n");
            return 2;
        }
#endif
        else {
            fmt::print(stderr, "Unknown command: {}\n", command);
            return 2;
        }
        return 0;
    } catch (const std::exception& e) {
        fmt::print(stderr, "Error: {}\n", e.what());
        return 1;
    }
}
