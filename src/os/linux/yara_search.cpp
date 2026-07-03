// yara_search.cpp — see header.
#include "os/linux/yara_search.h"
#include "os/linux/vma.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "arch/x86_64/paging.h"
#include "core/log.h"
#include "core/app_paths.h"
#include <fmt/format.h>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#ifdef LMPFS_HAS_YARA
#include <yara.h>
#endif

namespace lmpfs::linux {

// User-supplied rule paths from --yara-rules. Stored regardless of whether YARA
// is compiled into this binary; only the real scanner below reads them.
namespace { std::vector<std::string> g_user_yara_paths; }

void set_user_yara_paths(std::vector<std::string> paths) {
    g_user_yara_paths = std::move(paths);
}

#ifndef LMPFS_HAS_YARA

ByteBuf format_yara_global(const Engine&) {
    const char msg[] =
        "# /search/yara.txt — YARA scanning support not built into this binary.\n"
        "# Rebuild with -DLMPFS_BUILD_YARA=ON (and libyara installed via vcpkg).\n";
    return ByteBuf(msg, msg + sizeof(msg) - 1);
}

ByteBuf format_yara_per_pid(const Engine&, const Process& p) {
    auto txt = fmt::format(
        "# /proc/{}/yara.txt — YARA scanning support not built into this binary.\n"
        "# Rebuild with -DLMPFS_BUILD_YARA=ON.\n", p.pid);
    return ByteBuf(txt.begin(), txt.end());
}

ByteBuf format_yara_csv(const Engine&) {
    const char h[] = "rule,pid,comm,vma_start,hit_va,preview\r\n";
    return ByteBuf(h, h + sizeof(h) - 1);
}
ByteBuf format_yara_json(const Engine&) {
    const char j[] = "[]\n";
    return ByteBuf(j, j + sizeof(j) - 1);
}
std::vector<YaraHit> collect_global_yara_hits(const Engine&) { return {}; }

#else   // LMPFS_HAS_YARA — real implementation below.

namespace {

// ---- default ruleset ------------------------------------------------------
//
// A small, well-tested baseline that lights up cleanly on known test patterns
// (EICAR) and covers common forensic-interest markers. Keep this set narrow —
// users add their own .yar files via $LMPFS_YARA_RULES.
//
// Each block is a separate compile unit so a single broken rule doesn't take
// down the whole ruleset.
constexpr const char* kDefaultRules =
    R"YARA(

rule EICAR_Test_File
{
    meta:
        description = "Standard EICAR antivirus test string (RFC 3514-style canary)"
        severity    = "low"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Mimikatz_String_Markers
{
    meta:
        description = "Strings observed in Mimikatz / kerbrute / Rubeus binaries"
        severity    = "high"
    strings:
        $a1 = "sekurlsa::logonpasswords" nocase
        $a2 = "kerberos::list" nocase
        $a3 = "lsadump::sam" nocase
        $a4 = "gentilkiwi"
    condition:
        any of them
}

rule CobaltStrike_Beacon_Strings
{
    meta:
        description = "Common strings from Cobalt Strike beacon payloads"
        severity    = "high"
    strings:
        $a1 = "%s as %s\\%s: %d" wide ascii
        $a2 = "could not run command (w/ implant prefix) because of its lengt"
        $a3 = "process inject failed"
        $a4 = "beacon.x64.dll"
        $a5 = "beacon.dll"
        $a6 = "%%IMPORT%%"
    condition:
        any of them
}

rule Meterpreter_Strings
{
    meta:
        description = "Metasploit Meterpreter payload strings"
        severity    = "high"
    strings:
        $a1 = "metsrv.dll"
        $a2 = "stdapi_sys_process_get_processes"
        $a3 = "load stdapi"
        $a4 = "ReflectiveLoader"
    condition:
        any of them
}

rule Shellcode_x86_NOP_Sled
{
    meta:
        description = "Long NOP sled — possible exploit payload (>=64 NOPs)"
        severity    = "info"
    strings:
        $nop64 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
                   90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
                   90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
                   90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop64
}

rule Packer_UPX
{
    meta:
        description = "UPX packer markers"
        severity    = "info"
    strings:
        $a1 = "UPX0"
        $a2 = "UPX1"
        $a3 = "UPX!"
        $a4 = "$Info: This file is packed with the UPX executable packer"
    condition:
        any of them
}

rule Suspicious_Reverse_Shell_Commands
{
    meta:
        description = "Cleartext markers commonly found in injected reverse shells"
        severity    = "medium"
    strings:
        $a1 = "/bin/sh -i"
        $a2 = "/bin/bash -i"
        $a3 = "socket.SOCK_STREAM"
        $a4 = "os.dup2"
        $a5 = "ncat -e"
        $a6 = "bash -c 'bash -i"
    condition:
        any of them
}

rule Crypto_Wallet_Keywords
{
    meta:
        description = "Strings present in cryptocurrency stealers / wallets"
        severity    = "info"
    strings:
        $a1 = "wallet.dat"
        $a2 = "BEGIN BITCOIN PRIVATE KEY"
        $a3 = "electrum"
        $a4 = "MetaMask"
    condition:
        any of them
}

)YARA";

// One-shot libyara init across the process.
std::once_flag g_yr_init_once;
bool g_yr_init_ok = false;
void ensure_yr_initialized() {
    std::call_once(g_yr_init_once, []() {
        int rc = yr_initialize();
        if (rc != ERROR_SUCCESS) {
            log::warn("yara: yr_initialize failed (rc={})", rc);
            return;
        }
        g_yr_init_ok = true;
        // DELIBERATELY NOT calling std::atexit(yr_finalize).
        //
        // The static CompiledRules cache below has a destructor that
        // calls yr_rules_destroy. Static destructors run in LIFO order
        // mixed with atexit handlers — and because we register the
        // atexit() AFTER the static cache was constructed (init-on-first-
        // use), yr_finalize fires FIRST, then the cache destructor calls
        // yr_rules_destroy on already-finalized state → access violation.
        //
        // The standard libyara docs say yr_finalize is "not strictly
        // required at program exit" — the OS reclaims all memory anyway.
        // Skipping it sidesteps the dtor-order trap.
    });
}

// Build a YR_RULES* from the default ruleset + any user .yar files
// discoverable via env vars / default dirs. Cached at first use.
struct CompiledRules {
    YR_RULES*   rules = nullptr;
    std::string load_summary;       // for header reporting
    ~CompiledRules() { if (rules) yr_rules_destroy(rules); }
};

void try_add_file(YR_COMPILER* c, const std::filesystem::path& path,
                   std::string& summary, int& ok, int& bad)
{
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) return;
    FILE* fp = nullptr;
#ifdef _WIN32
    if (fopen_s(&fp, path.string().c_str(), "rb") != 0 || !fp) return;
#else
    fp = std::fopen(path.string().c_str(), "rb");
    if (!fp) return;
#endif
    // YR_COMPILER tracks accumulated errors; a clean re-add isn't possible
    // once a rule fails. We track best-effort.
    int rc = yr_compiler_add_file(c, fp, /*ns=*/nullptr,
                                   path.string().c_str());
    std::fclose(fp);
    if (rc == 0) { ++ok; summary += fmt::format("\n  + {}", path.string()); }
    else         { ++bad; summary += fmt::format("\n  ! {} ({} error(s))",
                                                  path.string(), rc); }
}

void try_add_directory(YR_COMPILER* c, const std::filesystem::path& dir,
                        std::string& summary, int& ok, int& bad)
{
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) return;
    for (const auto& e : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) break;
        auto ext = e.path().extension().string();
        for (auto& c : ext) c = (char)std::tolower((unsigned char)c);
        if (ext == ".yar" || ext == ".yara")
            try_add_file(c, e.path(), summary, ok, bad);
    }
}

CompiledRules& get_compiled_rules() {
    static CompiledRules cache;
    static std::once_flag once;
    std::call_once(once, []() {
        log::info("yara: ensure_yr_initialized");
        ensure_yr_initialized();
        if (!g_yr_init_ok) { log::warn("yara: init not ok, bailing"); return; }
        log::info("yara: yr_compiler_create");
        YR_COMPILER* c = nullptr;
        int rc_c = yr_compiler_create(&c);
        log::info("yara: yr_compiler_create rc={} c={:p}", rc_c, (void*)c);
        if (rc_c != ERROR_SUCCESS || !c) {
            log::warn("yara: yr_compiler_create failed");
            return;
        }
        // Don't bail on individual rule errors — keep going so a broken
        // user .yar doesn't disable the default ruleset.
        yr_compiler_set_callback(c,
            [](int /*error_level*/, const char* file_name, int line_number,
               const YR_RULE* /*rule*/, const char* message, void* /*user*/) {
                log::warn("yara compile: {}:{}: {}",
                          file_name ? file_name : "<inline>", line_number,
                          message);
            }, nullptr);

        std::string summary = "Default ruleset compiled.";
        int ok = 0, bad = 0;
        // 1) defaults
        log::info("yara: yr_compiler_add_string defaults ({} bytes)",
                  std::strlen(kDefaultRules));
        int rc = yr_compiler_add_string(c, kDefaultRules, /*ns=*/"default");
        log::info("yara: defaults add rc={}", rc);
        if (rc != 0) {
            summary += fmt::format(" (defaults: {} error(s) — see logs)", rc);
        }
        // 2) --yara-rules (CLI): explicit, highest-precedence user source.
        for (const auto& raw : g_user_yara_paths) {
            std::filesystem::path p = raw;
            if (std::filesystem::is_directory(p))
                try_add_directory(c, p, summary, ok, bad);
            else
                try_add_file(c, p, summary, ok, bad);
        }
        // 3) $LMPFS_YARA_RULES env var (':'/';'-separated files or dirs)
        if (const char* env = std::getenv("LMPFS_YARA_RULES")) {
            std::string raw = env;
            std::string acc;
            auto flush = [&](std::string& s) {
                if (s.empty()) return;
                std::filesystem::path p = s;
                if (std::filesystem::is_directory(p))
                    try_add_directory(c, p, summary, ok, bad);
                else
                    try_add_file(c, p, summary, ok, bad);
                s.clear();
            };
            // On Windows ':' is part of drive letters (C:\...); only use
            // ';' as the separator. On POSIX use ':'.
#ifdef _WIN32
            const char kSep = ';';
#else
            const char kSep = ':';
#endif
            for (char ch : raw) {
                if (ch == kSep) flush(acc);
                else            acc.push_back(ch);
            }
            flush(acc);
        }
        // 4) Per-user drop-in dirs — same resolver on Windows and Linux, so
        //    ~/.local/share/memnixfs/yara and ~/.cache/lmpfs/yara both work.
        for (const auto& d : paths::user_dirs("yara"))
            try_add_directory(c, d, summary, ok, bad);
        if (ok > 0)  summary += fmt::format("\nUser rules added: {} OK, {} skipped.", ok, bad);
        else if (bad > 0) summary += fmt::format("\nUser rules: {} skipped.", bad);

        log::info("yara: yr_compiler_get_rules");
        YR_RULES* rules = nullptr;
        rc = yr_compiler_get_rules(c, &rules);
        log::info("yara: yr_compiler_get_rules rc={} rules={:p}", rc, (void*)rules);
        yr_compiler_destroy(c);
        if (rc != 0 || !rules) {
            log::warn("yara: yr_compiler_get_rules failed (rc={})", rc);
            cache.load_summary = "Compilation FAILED — see logs.";
            return;
        }
        cache.rules        = rules;
        cache.load_summary = std::move(summary);
        log::info("yara: compilation complete");
    });
    return cache;
}

// Per-scan accumulator.
struct ScanState {
    u32         pid = 0;
    std::string comm;
    VAddr       vma_start = 0;
    u64         chunk_off = 0;    // offset of the current 4-KiB chunk within VMA
    std::vector<u8> last_buf;     // for hex-preview of the match site

    // Aggregated results.
    struct Hit {
        std::string rule;
        u32         pid;
        std::string comm;
        VAddr       vma_start;
        u64         hit_va;
        std::string preview;
    };
    std::vector<Hit>* sink = nullptr;
};

int yara_match_callback(YR_SCAN_CONTEXT* /*ctx*/, int message, void* msg_data,
                         void* user_data)
{
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;
    auto* state = static_cast<ScanState*>(user_data);
    auto* rule  = static_cast<YR_RULE*>(msg_data);

    ScanState::Hit h;
    h.rule      = rule->identifier ? rule->identifier : "(anon)";
    h.pid       = state->pid;
    h.comm      = state->comm;
    h.vma_start = state->vma_start;
    // We don't get per-string offsets back through this callback without
    // a custom CALLBACK_MSG_TOO_MANY_MATCHES handler — report the chunk
    // base VA as an approximation.
    h.hit_va    = state->vma_start + state->chunk_off;

    // Hex-preview: first 32 bytes of the chunk.
    if (!state->last_buf.empty()) {
        std::size_t n = std::min<std::size_t>(state->last_buf.size(), 32);
        for (std::size_t i = 0; i < n; ++i) {
            h.preview += fmt::format("{:02x}", state->last_buf[i]);
            if (i + 1 < n) h.preview += ' ';
        }
    }
    state->sink->push_back(std::move(h));
    // Cap to keep output manageable.
    if (state->sink->size() >= 5000) return CALLBACK_ABORT;
    return CALLBACK_CONTINUE;
}

// Scan a single process. Walks every readable VMA, reads in 64 KiB
// chunks via the user PGD, and calls yr_rules_scan_mem on each chunk.
// VMAs > 256 MiB are skipped (heap / mmap'd data files).
void scan_process(const Engine& eng, const Process& p, YR_RULES* rules,
                   std::vector<ScanState::Hit>& sink)
{
    if (p.mm == 0) return;
    log::info("yara scan_process pid={} ({})", p.pid, p.comm);
    std::vector<Vma> vmas;
    try { vmas = enumerate_vmas(eng.phys(), eng.isf(), eng.kernel(), p); }
    catch (...) { return; }
    log::info("yara: {} VMAs to scan", vmas.size());

    PAddr pgd = resolve_user_pgd(eng.phys(), eng.isf(), eng.kernel(), p);
    if (pgd == 0) { log::warn("yara: pgd=0"); return; }
    x86_64::PageTable upt(eng.phys(), pgd);

    constexpr std::size_t kChunk = 64 * 1024;
    constexpr u64         kVmaCap = 256ULL << 20;
    std::vector<u8> buf(kChunk);

    ScanState state;
    state.pid  = p.pid;
    state.comm = p.comm;
    state.sink = &sink;

    int vma_idx = 0;
    for (const auto& v : vmas) {
        ++vma_idx;
        if (!(v.vm_flags & 0x1)) continue;          // need VM_READ
        u64 sz = v.vm_end - v.vm_start;
        if (sz == 0 || sz > kVmaCap) continue;

        state.vma_start = v.vm_start;
        u64 remaining = sz;
        u64 off = 0;
        while (remaining > 0 && sink.size() < 5000) {
            std::size_t want = static_cast<std::size_t>(
                std::min<u64>(remaining, kChunk));
            std::size_t got = upt.read(v.vm_start + off, buf.data(), want);
            if (got == 0) {
                u64 step = std::min<u64>(remaining, 4096);
                off       += step;
                remaining -= step;
                continue;
            }
            state.chunk_off = off;
            state.last_buf.assign(buf.begin(), buf.begin() + got);
            int rc = yr_rules_scan_mem(rules, buf.data(), got,
                                        SCAN_FLAGS_FAST_MODE,
                                        yara_match_callback, &state,
                                        /*timeout=*/30);
            if (rc == CALLBACK_ABORT || sink.size() >= 5000) return;
            off       += got;
            remaining -= got;
        }
    }
    log::info("yara: scan_process done, {} hits so far", sink.size());
}

ByteBuf format_results(const std::vector<ScanState::Hit>& hits,
                        const std::string& load_summary,
                        const std::string& scope)
{
    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format(
        "# YARA scan — {}\n"
        "# {} hit(s).\n"
        "# Rule sources:\n"
        "{}\n"
        "#\n",
        scope, hits.size(), load_summary);
    if (hits.empty()) {
        out += "(no rule matched any scanned chunk)\n";
        return ByteBuf(out.begin(), out.end());
    }
    out += "# rule                            pid   comm              vma_start         hit_va            preview (first 32 B of chunk)\n";
    out += "# -------------------------------+-----+-----------------+----------------+-----------------+---------\n";
    for (const auto& h : hits) {
        out += fmt::format("{:<32}  {:>5}  {:<16}  {:#016x}  {:#016x}  {}\n",
                           h.rule.substr(0, 32),
                           h.pid, h.comm.substr(0, 16),
                           h.vma_start, h.hit_va, h.preview);
    }
    return ByteBuf(out.begin(), out.end());
}

// ---- machine-readable exports: same global hits, rendered CSV/JSON ---------
std::vector<ScanState::Hit> collect_global_hits(const Engine& eng, YR_RULES* rules) {
    std::vector<ScanState::Hit> hits;
    for (const auto& p : eng.processes()) {
        scan_process(eng, p, rules, hits);
        if (hits.size() >= 5000) break;
    }
    return hits;
}

std::string csv_field(const std::string& s) {
    bool needs = false;
    for (char ch : s) if (ch == ',' || ch == '"' || ch == '\r' || ch == '\n') { needs = true; break; }
    if (!needs) return s;
    std::string o; o.push_back('"');
    for (char ch : s) { if (ch == '"') o.push_back('"'); o.push_back(ch); }
    o.push_back('"');
    return o;
}

std::string json_field(const std::string& s) {
    std::string o; o.push_back('"');
    for (char ch : s) {
        switch (ch) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20)
                    o += fmt::format("\\u{:04x}",
                                     static_cast<unsigned>(static_cast<unsigned char>(ch)));
                else o.push_back(ch);
        }
    }
    o.push_back('"');
    return o;
}

} // anonymous

ByteBuf format_yara_global(const Engine& eng) {
    auto& cache = get_compiled_rules();
    if (!cache.rules) {
        std::string out =
            "# /search/yara.txt — YARA initialization failed.\n";
        out += "# " + cache.load_summary + "\n";
        return ByteBuf(out.begin(), out.end());
    }
    std::vector<ScanState::Hit> hits;
    for (const auto& p : eng.processes()) {
        scan_process(eng, p, cache.rules, hits);
        if (hits.size() >= 5000) break;
    }
    return format_results(hits, cache.load_summary,
                           "global (every user task's readable VMAs)");
}

ByteBuf format_yara_per_pid(const Engine& eng, const Process& p) {
    auto& cache = get_compiled_rules();
    if (!cache.rules) {
        std::string out = fmt::format(
            "# /proc/{}/yara.txt — YARA initialization failed.\n", p.pid);
        out += "# " + cache.load_summary + "\n";
        return ByteBuf(out.begin(), out.end());
    }
    std::vector<ScanState::Hit> hits;
    scan_process(eng, p, cache.rules, hits);
    return format_results(hits, cache.load_summary,
                           fmt::format("pid {} ({})", p.pid, p.comm));
}

// Public, cached entry point: run the internal global scan and convert its
// hits to the public YaraHit so Engine::global_yara() can memoize one pass
// across the txt/csv/json yara views. (collect_global_hits + get_compiled_rules
// are file-local, so this must live at namespace scope, not in the header.)
std::vector<YaraHit> collect_global_yara_hits(const Engine& eng) {
    std::vector<YaraHit> out;
    auto& cache = get_compiled_rules();
    if (!cache.rules) return out;
    for (const auto& h : collect_global_hits(eng, cache.rules))
        out.push_back({h.rule, h.pid, h.comm, h.vma_start, h.hit_va, h.preview});
    return out;
}

ByteBuf format_yara_csv(const Engine& eng) {
    std::string out = "rule,pid,comm,vma_start,hit_va,preview\r\n";
    for (const auto& h : eng.global_yara())
        out += fmt::format("{},{},{},{:#x},{:#x},{}\r\n",
                           csv_field(h.rule), h.pid, csv_field(h.comm),
                           h.vma_start, h.hit_va, csv_field(h.preview));
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_yara_json(const Engine& eng) {
    std::string out = "[";
    const auto& hits = eng.global_yara();
    for (std::size_t i = 0; i < hits.size(); ++i) {
        const auto& h = hits[i];
        out += fmt::format(
            "{}\n  {{\"rule\":{},\"pid\":{},\"comm\":{},"
            "\"vma_start\":\"{:#x}\",\"hit_va\":\"{:#x}\",\"preview\":{}}}",
            i ? "," : "",
            json_field(h.rule), h.pid, json_field(h.comm),
            h.vma_start, h.hit_va, json_field(h.preview));
    }
    out += "\n]\n";
    return ByteBuf(out.begin(), out.end());
}

// ---- per-rule subdir (v0.25) ---------------------------------------------
//
// Walk the compiled YR_RULES and surface every rule's identifier so the
// VFS layer (engine.cpp) can build one LazyFileNode per rule under
// /search/yara/<rule>.txt. format_yara_per_rule runs the same global scan
// and filters hits by rule name.

std::vector<std::string> list_yara_rule_names(const Engine& /*eng*/) {
    auto& cache = get_compiled_rules();
    std::vector<std::string> names;
    if (!cache.rules) return names;
    // libyara's iteration macro:
    //   yr_rules_foreach(rules, rule) { ... }
    YR_RULE* rule = nullptr;
    yr_rules_foreach(cache.rules, rule) {
        if (rule->identifier) names.emplace_back(rule->identifier);
    }
    return names;
}

ByteBuf format_yara_per_rule(const Engine& eng, const std::string& rule_name) {
    auto& cache = get_compiled_rules();
    if (!cache.rules) {
        std::string out = fmt::format(
            "# /search/yara/{}.txt — YARA initialization failed.\n", rule_name);
        out += "# " + cache.load_summary + "\n";
        return ByteBuf(out.begin(), out.end());
    }
    // Run the same global scan; filter hits by rule_name.
    std::vector<ScanState::Hit> all;
    for (const auto& p : eng.processes()) {
        scan_process(eng, p, cache.rules, all);
        if (all.size() >= 5000) break;
    }
    std::vector<ScanState::Hit> filtered;
    for (auto& h : all) if (h.rule == rule_name) filtered.push_back(std::move(h));
    return format_results(filtered, cache.load_summary,
                           fmt::format("rule '{}' across every user task's VMAs",
                                        rule_name));
}

#endif // LMPFS_HAS_YARA

} // namespace lmpfs::linux

// ---- per-rule stubs when YARA isn't compiled in --------------------------
#ifndef LMPFS_HAS_YARA
namespace lmpfs::linux {

std::vector<std::string> list_yara_rule_names(const Engine&) { return {}; }

ByteBuf format_yara_per_rule(const Engine&, const std::string& rule) {
    auto txt = fmt::format(
        "# /search/yara/{}.txt — YARA not compiled in.\n", rule);
    return ByteBuf(txt.begin(), txt.end());
}

} // namespace lmpfs::linux
#endif
