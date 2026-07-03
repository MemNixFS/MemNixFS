// yara_search.h — YARA rule-scanning over user-process memory.
//
// Two surfaces:
//
//   /search/yara.txt           Global scan across every user task's
//                              readable VMAs. Output groups hits by
//                              rule, then by PID; each row shows the
//                              exact match VA, readable escaped preview,
//                              match length, and byte-exact hex preview.
//
//   /proc/<pid>/yara.txt       Same scanner, scoped to one process.
//
// Rule sources (loaded once at engine init, cached for every scan):
//
//   1. Built-in default rules. Compiled in from `default_rules.inc`
//      (loaded via header text constant). Covers EICAR, common
//      shellcode markers, Mimikatz strings, Cobalt Strike beacons,
//      meterpreter, common packer signatures.
//
//   2. --yara-rules <path> (CLI) — a .yar/.yara file, directory, or wildcard
//      path (wildcards in the final component). Repeatable; highest-precedence.
//
//   3. $LMPFS_YARA_RULES — list of .yar/.yara files or directories
//      (';'-separated on Windows, ':' on Linux). Bad rules are skipped
//      with a warning.
//
//   4. Per-user drop-in dir (same resolver as symbols + plugins, see
//      core/app_paths.h):
//        Windows: %LOCALAPPDATA%\MemNixFS\yara\
//        Linux:   ~/.local/share/memnixfs/yara/  or  ~/.cache/lmpfs/yara/
//
// Build:
//   This file is built only when LMPFS_HAS_YARA is defined (set by
//   CMake when libyara is found). Otherwise the format_* functions
//   return a one-line "(YARA support not built into this binary)"
//   message.
//
// References:
//   MemProcFS:  m_searchyara.c + vmmyarautil.c
//   vol3:       vmayarascan.py
//
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include "os/linux/process.h"
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

namespace detail {
std::string yara_text_preview(const u8* data, std::size_t size);
std::string yara_hex_preview(const u8* data, std::size_t size);
}

// Register extra YARA rule files / directories (from --yara-rules) to compile
// into the ruleset alongside the built-in defaults, $LMPFS_YARA_RULES, and the
// per-user drop-in dir. Each entry is a .yar/.yara file OR a directory. MUST be
// called before the first scan compiles the ruleset — Engine::create does this.
void set_user_yara_paths(std::vector<std::string> paths);

// /search/yara.txt — global scan, all rules, all processes, one file.
ByteBuf format_yara_global(const Engine& eng);

// /proc/<pid>/yara.txt — per-process scope.
ByteBuf format_yara_per_pid(const Engine& eng, const Process& p);

// One YARA hit. The global scan is expensive, so it is cached on the Engine
// (Engine::global_yara()) and the txt/csv/json yara views share one pass.
// Empty when YARA support isn't built into this binary.
struct YaraHit {
    std::string rule;
    std::string string_id;
    u32         pid = 0;
    std::string comm;
    VAddr       vma_start = 0;
    u64         hit_va = 0;
    u32         match_length = 0;
    std::string preview;
    std::string preview_hex;
};
std::vector<YaraHit> collect_global_yara_hits(const Engine& eng);

// Machine-readable exports of the global scan (same hits as yara.txt), for
// /search/yara.{csv,json} and the /csv + /json aggregate folders.
ByteBuf format_yara_csv(const Engine& eng);
ByteBuf format_yara_json(const Engine& eng);

// Per-rule subdir contents (v0.25). Each rule from the loaded ruleset
// gets its own file under /search/yara/<rule>.txt, with ONLY that rule's
// matches. Surfaced through these accessors:
//
//   list_yara_rule_names()     — names known to the loaded ruleset (or
//                                empty if YARA isn't built into this
//                                binary, OR rule compilation failed).
//   format_yara_per_rule(name) — same scan run as the global one, but
//                                filtered to rule == `name`. Returns a
//                                short "(no matches)" body when clean.
std::vector<std::string> list_yara_rule_names(const Engine& eng);
ByteBuf format_yara_per_rule(const Engine& eng, const std::string& rule);

} // namespace lmpfs::linux
