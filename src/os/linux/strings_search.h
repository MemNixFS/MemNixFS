// strings_search.h - printable-string extraction + IOC scan over user
// process memory.
//
// Two surfaces:
//
//   /proc/<pid>/strings.txt          per-process printable ASCII strings
//                                    (>= 6 chars) extracted from every
//                                    scanned readable VMA. One line per string.
//
//   /search/iocs.txt                 global pass that extracts strings
//                                    matching well-known IOC patterns
//                                    (URLs, IPv4, IPv6, emails, JWT
//                                    tokens, AWS access keys) across
//                                    every process.
//
// Bounds:
//   * Per-process strings.txt has no string-count cap.
//   * VMAs larger than 256 MiB are skipped as a guardrail.
//   * Global IOC output remains capped at 50,000 hits.
//   * Min string length: 6 chars by default.
//
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include "os/linux/process.h"
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct StringHit {
    VAddr       vma_start = 0;
    VAddr       hit_va    = 0;     // VA where the string begins
    std::string text;
};

struct StringExtractStats {
    std::size_t scanned_vmas = 0;
    std::size_t skipped_oversized_vmas = 0;
    u64         skipped_oversized_bytes = 0;
    std::size_t unreadable_ranges = 0;
    bool        hit_limit_reached = false;
};

// Per-process: extract printable-ASCII strings >= min_len chars from every
// scanned readable VMA. max_hits == 0 means unlimited.
std::vector<StringHit> extract_strings(const Engine& eng, const Process& p,
                                       int min_len = 6,
                                       std::size_t max_hits = 0,
                                       StringExtractStats* stats = nullptr);

ByteBuf format_proc_strings(const Engine& eng, const Process& p);

// Global IOC scan - runs extract_strings per process, then filters each string
// through the IOC battery (URL, IPv4, IPv6, email, JWT, AWS key). Output groups
// by IOC type, one hit per line.
ByteBuf format_global_iocs(const Engine& eng);

// One extracted IOC row. The global pass is expensive, so it is cached on the
// Engine (Engine::global_iocs()) and the /search, /csv and /json iocs views
// all render from that single scan.
struct IocHit { std::string type, value; u32 pid; std::string comm; };
std::vector<IocHit> collect_global_iocs(const Engine& eng);

// Machine-readable IOC exports: rows of {type, value, pid, comm} from the same
// global pass, for /search/iocs.{csv,json} and the /csv + /json folders.
ByteBuf format_iocs_csv(const Engine& eng);
ByteBuf format_iocs_json(const Engine& eng);

} // namespace lmpfs::linux
