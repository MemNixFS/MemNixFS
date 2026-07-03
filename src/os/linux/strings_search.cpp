// strings_search.cpp — see header.
#include "os/linux/strings_search.h"
#include "os/linux/vma.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "arch/x86_64/paging.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <cctype>
#include <string_view>

namespace lmpfs::linux {

namespace {

constexpr std::size_t kPageSize       = 4096;
constexpr u64         kVmaSizeLimit   = 256ULL << 20;   // skip VMAs > 256 MiB
constexpr std::size_t kReadChunkBytes = 64 * 1024;       // 64 KiB I/O batch
constexpr std::size_t kMaxStringLen   = 512;             // truncate beyond this

inline bool is_printable(u8 c) {
    return (c >= 0x20 && c < 0x7F) || c == '\t';
}

// Forensic-interest ordering for per-process string extraction. The budget is
// finite, so scan the regions an analyst actually cares about FIRST: heap,
// stack and anonymous RW data (commands, env, decrypted secrets), then
// anonymous executable (JIT / injected payloads), then file-backed regions —
// read-only library code LAST, since its strings are static, mostly binary
// noise, and already recoverable from /fs. Without this, a process's first few
// library VMAs (ld.so / libc) exhaust the whole budget on noise and the heap is
// never reached — which made strings.txt useless (all loader bytes, no heap).
int vma_scan_priority(const Vma& v) {
    const bool anon = (v.vm_file == 0);
    if (anon && v.writable())   return 0;   // heap, stack, anon RW data
    if (anon && v.executable()) return 1;   // anon exec — JIT / injected code
    if (anon)                   return 2;   // anon read-only
    if (v.writable())           return 3;   // file-backed writable data segment
    return 4;                               // file-backed read-only code — last
}

// Extract one VMA's strings. Streams 64 KiB at a time so we don't have
// to materialise the whole VMA in memory.
void extract_vma_strings(const Vma& v, const x86_64::PageTable& upt,
                          int min_len, std::vector<StringHit>& out,
                          std::size_t cap,
                          StringExtractStats* stats)
{
    if (!(v.vm_flags & 0x1)) return;             // need VM_READ
    u64 size = v.vm_end - v.vm_start;
    if (size == 0) return;
    if (size > kVmaSizeLimit) {
        if (stats) {
            ++stats->skipped_oversized_vmas;
            stats->skipped_oversized_bytes += size;
        }
        return;
    }
    if (stats) ++stats->scanned_vmas;

    std::vector<u8> buf;
    buf.resize(kReadChunkBytes);

    // Carry-over for strings straddling 64 KiB boundaries: keep the
    // tail of the previous chunk if it looks string-like at the end.
    std::string carry;
    u64 carry_va = 0;

    u64 va = v.vm_start;
    u64 remaining = size;
    auto limited = [&]() { return cap != 0 && out.size() >= cap; };
    while (remaining > 0 && !limited()) {
        std::size_t want = static_cast<std::size_t>(
            std::min<u64>(remaining, kReadChunkBytes));
        std::size_t got = upt.read(va, buf.data(), want);
        if (got == 0) {
            // Skip a page on unreadable; cheaper than burning the whole VMA.
            if (stats) ++stats->unreadable_ranges;
            u64 step = std::min<u64>(remaining, kPageSize);
            va        += step;
            remaining -= step;
            carry.clear();
            continue;
        }
        // Scan the buffer for runs of printable chars.
        std::size_t i = 0;
        if (!carry.empty()) {
            // Try to continue the carry-over from the previous chunk.
            while (i < got && is_printable(buf[i])) {
                if (carry.size() < kMaxStringLen) carry.push_back((char)buf[i]);
                ++i;
            }
            if ((int)carry.size() >= min_len) {
                StringHit h;
                h.vma_start = v.vm_start;
                h.hit_va    = carry_va;
                h.text      = std::move(carry);
                out.push_back(std::move(h));
                if (limited()) return;
            }
            carry.clear();
        }
        // Now scan fresh.
        while (i < got) {
            // Find start of a run.
            while (i < got && !is_printable(buf[i])) ++i;
            if (i >= got) break;
            std::size_t start = i;
            while (i < got && is_printable(buf[i])) ++i;
            std::size_t len = i - start;
            // If the run extends to the end of this buffer, it may
            // continue into the next chunk — carry it over.
            if (i == got && got == want) {
                carry.assign(reinterpret_cast<const char*>(buf.data() + start),
                              std::min(len, kMaxStringLen));
                carry_va = va + start;
                break;
            }
            if ((int)len >= min_len) {
                StringHit h;
                h.vma_start = v.vm_start;
                h.hit_va    = va + start;
                h.text.assign(reinterpret_cast<const char*>(buf.data() + start),
                              std::min(len, kMaxStringLen));
                out.push_back(std::move(h));
                if (limited()) return;
            }
        }
        va        += got;
        remaining -= got;
    }
    // Flush trailing carry if it qualifies.
    if ((int)carry.size() >= min_len && !limited()) {
        StringHit h;
        h.vma_start = v.vm_start;
        h.hit_va    = carry_va;
        h.text      = std::move(carry);
        out.push_back(std::move(h));
    }
}

// ---------- IOC battery ----------------------------------------------------
//
// Each IOC pattern is a hand-rolled DFA — no <regex>, no dependencies.
// Returning the matched substring (so we can echo it back); negative tests
// are deliberately strict to keep the false-positive rate low on dumps with
// gigabytes of process memory.

// "https?://" + run of url-safe chars
std::string find_url(std::string_view s) {
    auto pos = std::string_view::npos;
    if      ((pos = s.find("https://")) != std::string_view::npos) {}
    else if ((pos = s.find("http://"))  != std::string_view::npos) {}
    else if ((pos = s.find("ftp://"))   != std::string_view::npos) {}
    else return {};
    std::size_t end = pos;
    while (end < s.size()) {
        char c = s[end];
        if (c == ' ' || c == '\t' || c == '"' || c == '\'' ||
            c == '<' || c == '>'  || c == '\\' || c == '|' || c < 0x20) break;
        ++end;
    }
    if (end - pos < 10) return {};   // too-short URL: ignore
    return std::string(s.substr(pos, end - pos));
}

// IPv4 dotted-quad: each octet 0..255. Reject 0.0.0.0 and 255.255.255.255
// to suppress null-padding noise.
std::string find_ipv4(std::string_view s) {
    for (std::size_t i = 0; i + 7 <= s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') continue;
        std::size_t j = i;
        unsigned octets[4]{};
        int o_idx = 0;
        bool ok = true;
        for (; o_idx < 4 && j < s.size(); ++o_idx) {
            unsigned v = 0;
            int digits = 0;
            while (j < s.size() && s[j] >= '0' && s[j] <= '9' && digits < 3) {
                v = v * 10 + (s[j] - '0'); ++j; ++digits;
            }
            if (digits == 0 || v > 255) { ok = false; break; }
            octets[o_idx] = v;
            if (o_idx < 3) {
                if (j >= s.size() || s[j] != '.') { ok = false; break; }
                ++j;
            }
        }
        if (!ok || o_idx != 4) continue;
        // Reject all-zero / all-255.
        bool allz = (octets[0] | octets[1] | octets[2] | octets[3]) == 0;
        bool allf = octets[0] == 255 && octets[1] == 255 &&
                    octets[2] == 255 && octets[3] == 255;
        if (allz || allf) continue;
        return std::string(s.substr(i, j - i));
    }
    return {};
}

// Email: simplistic — looks for "user@host.tld" with valid char classes.
std::string find_email(std::string_view s) {
    auto at = s.find('@');
    if (at == std::string_view::npos || at < 2 || at + 4 >= s.size()) return {};
    auto is_local = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '.' || c == '+' || c == '_' ||
               c == '-';
    };
    auto is_host = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '.' || c == '-';
    };
    std::size_t lo = at;
    while (lo > 0 && is_local(s[lo - 1])) --lo;
    std::size_t hi = at + 1;
    while (hi < s.size() && is_host(s[hi])) ++hi;
    // Need a dot in the host part.
    auto host = s.substr(at + 1, hi - at - 1);
    if (host.find('.') == std::string_view::npos) return {};
    if (at - lo < 1 || hi - (at + 1) < 3) return {};
    return std::string(s.substr(lo, hi - lo));
}

// JWT: 3 base64url segments separated by dots, first must start with "eyJ"
// (the JOSE header { ... ).
std::string find_jwt(std::string_view s) {
    auto pos = s.find("eyJ");
    if (pos == std::string_view::npos) return {};
    auto is_b64u = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '-' || c == '_';
    };
    std::size_t i = pos;
    int dots = 0;
    while (i < s.size()) {
        char c = s[i];
        if (is_b64u(c)) ++i;
        else if (c == '.' && dots < 2) { ++i; ++dots; }
        else break;
    }
    if (dots != 2 || i - pos < 30) return {};
    return std::string(s.substr(pos, i - pos));
}

// AWS access-key-ID: "AKIA" + 16 uppercase alphanumerics.
std::string find_aws_key(std::string_view s) {
    auto pos = s.find("AKIA");
    if (pos == std::string_view::npos) return {};
    if (pos + 20 > s.size()) return {};
    for (std::size_t i = pos + 4; i < pos + 20; ++i) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) return {};
    }
    return std::string(s.substr(pos, 20));
}

struct IocCounts {
    std::vector<std::string> urls;
    std::vector<std::string> ipv4s;
    std::vector<std::string> emails;
    std::vector<std::string> jwts;
    std::vector<std::string> aws_keys;
};

void extract_iocs(std::string_view s, IocCounts& c) {
    if (auto v = find_url(s);     !v.empty()) c.urls    .push_back(std::move(v));
    if (auto v = find_ipv4(s);    !v.empty()) c.ipv4s   .push_back(std::move(v));
    if (auto v = find_email(s);   !v.empty()) c.emails  .push_back(std::move(v));
    if (auto v = find_jwt(s);     !v.empty()) c.jwts    .push_back(std::move(v));
    if (auto v = find_aws_key(s); !v.empty()) c.aws_keys.push_back(std::move(v));
}

// ---- machine-readable IOC exports -----------------------------------------
// (collect_global_iocs is defined below at namespace scope, not here in the
//  anonymous namespace, so Engine::global_iocs() can cache it. csv/json escapers
//  follow.)

std::string csv_esc(const std::string& s) {
    bool needs = false;
    for (char ch : s) if (ch == ',' || ch == '"' || ch == '\r' || ch == '\n') { needs = true; break; }
    if (!needs) return s;
    std::string o; o.push_back('"');
    for (char ch : s) { if (ch == '"') o.push_back('"'); o.push_back(ch); }
    o.push_back('"');
    return o;
}

std::string json_esc(const std::string& s) {
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

std::vector<StringHit> extract_strings(const Engine& eng, const Process& p,
                                       int min_len, std::size_t max_hits,
                                       StringExtractStats* stats)
{
    std::vector<StringHit> out;
    if (stats) *stats = {};
    if (p.mm == 0) return out;
    std::vector<Vma> vmas;
    try { vmas = enumerate_vmas(eng.phys(), eng.isf(), eng.kernel(), p); }
    catch (...) { return out; }

    PAddr user_pgd_pa = resolve_user_pgd(eng.phys(), eng.isf(), eng.kernel(), p);
    if (user_pgd_pa == 0) return out;
    x86_64::PageTable upt(eng.phys(), user_pgd_pa);

    // Scan forensically-interesting regions first (see vma_scan_priority).
    // strings.txt is uncapped, but analysts usually inspect the top of a large
    // file first. Stable within a tier to keep address order.
    std::stable_sort(vmas.begin(), vmas.end(),
        [](const Vma& a, const Vma& b) {
            return vma_scan_priority(a) < vma_scan_priority(b);
        });
    for (const auto& v : vmas) {
        if (max_hits != 0 && out.size() >= max_hits) {
            if (stats) stats->hit_limit_reached = true;
            break;
        }
        extract_vma_strings(v, upt, min_len, out, max_hits, stats);
    }
    if (stats && max_hits != 0 && out.size() >= max_hits)
        stats->hit_limit_reached = true;
    return out;
}

ByteBuf format_proc_strings(const Engine& eng, const Process& p) {
    StringExtractStats stats{};
    auto hits = extract_strings(eng, p, /*min_len=*/6, /*max_hits=*/0, &stats);
    std::string out;
    out.reserve(std::min<std::size_t>(64 * 1024 + hits.size() * 64, 8 * 1024 * 1024));
    out += fmt::format(
        "# /proc/{}/strings.txt - printable ASCII strings (>=6 chars) from the\n"
        "# readable VMAs of pid {} ({}).\n"
        "# Scan order is by forensic interest: heap / stack / anonymous data and\n"
        "# anon-executable (commands, env, secrets, injected code) FIRST, then\n"
        "# file-backed regions, read-only library code LAST.\n"
        "# limit: none; oversized VMA guard: > 256 MiB skipped.\n"
        "# {} strings extracted; {} VMA(s) scanned; {} oversized VMA(s) skipped\n"
        "# ({} bytes); {} unreadable page/range skip(s).\n"
        "#\n"
        "# vma_start          hit_va            string\n"
        "# ----------------+----------------+----------\n",
        p.pid, p.pid, p.comm, hits.size(), stats.scanned_vmas,
        stats.skipped_oversized_vmas, stats.skipped_oversized_bytes,
        stats.unreadable_ranges);
    for (const auto& h : hits) {
        out += fmt::format("{:#016x}  {:#016x}  {}\n",
                           h.vma_start, h.hit_va, h.text);
    }
    return ByteBuf(out.begin(), out.end());
}
ByteBuf format_global_iocs(const Engine& eng) {
    // Per-process IOC scan with global hit cap so output stays bounded
    // even on a dump with thousands of processes.
    constexpr std::size_t kGlobalCap = 50000;

    IocCounts agg;
    struct PerPidHit {
        u32 pid;
        std::string comm;
        std::string match;
    };
    std::vector<PerPidHit> per_pid_url, per_pid_ipv4, per_pid_email, per_pid_jwt, per_pid_aws;

    std::size_t total = 0;
    for (const auto& p : eng.processes()) {
        if (p.mm == 0) continue;
        // Per-process budget — keep one process from dominating.
        auto hits = extract_strings(eng, p, /*min_len=*/8, /*max_hits=*/1500);
        for (const auto& h : hits) {
            std::size_t before = agg.urls.size() + agg.ipv4s.size() +
                                  agg.emails.size() + agg.jwts.size() +
                                  agg.aws_keys.size();
            extract_iocs(h.text, agg);
            std::size_t after = agg.urls.size() + agg.ipv4s.size() +
                                 agg.emails.size() + agg.jwts.size() +
                                 agg.aws_keys.size();
            if (after > before) {
                ++total;
                // Track ONE per-pid attribution per category (the first).
                if (agg.urls    .size() > 0 && per_pid_url  .size() < kGlobalCap)
                    per_pid_url.push_back({ p.pid, p.comm, agg.urls.back() });
                if (agg.ipv4s   .size() > 0 && per_pid_ipv4 .size() < kGlobalCap)
                    per_pid_ipv4.push_back({ p.pid, p.comm, agg.ipv4s.back() });
                if (agg.emails  .size() > 0 && per_pid_email.size() < kGlobalCap)
                    per_pid_email.push_back({ p.pid, p.comm, agg.emails.back() });
                if (agg.jwts    .size() > 0 && per_pid_jwt  .size() < kGlobalCap)
                    per_pid_jwt.push_back({ p.pid, p.comm, agg.jwts.back() });
                if (agg.aws_keys.size() > 0 && per_pid_aws  .size() < kGlobalCap)
                    per_pid_aws.push_back({ p.pid, p.comm, agg.aws_keys.back() });
            }
            if (total >= kGlobalCap) break;
        }
        if (total >= kGlobalCap) break;
    }

    // De-dup the aggregated lists for the summary header.
    auto dedup = [](std::vector<std::string>& v) {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    };
    dedup(agg.urls);
    dedup(agg.ipv4s);
    dedup(agg.emails);
    dedup(agg.jwts);
    dedup(agg.aws_keys);

    std::string out;
    out.reserve(64 * 1024);
    out += fmt::format(
        "# /search/iocs.txt — IOC extraction across all user processes\n"
        "# Patterns: URL, IPv4, email, JWT, AWS access-key-id\n"
        "# Counts (unique): {} URL, {} IPv4, {} email, {} JWT, {} AWS-key\n"
        "# (Capped at 50,000 hits; min-string-length 8 for IOC pass.)\n"
        "#\n",
        agg.urls.size(), agg.ipv4s.size(), agg.emails.size(),
        agg.jwts.size(), agg.aws_keys.size());

    auto emit_section = [&](const char* label,
                            const std::vector<PerPidHit>& hits)
    {
        out += fmt::format("\n[{}]\n", label);
        if (hits.empty()) {
            out += "(no hits)\n";
            return;
        }
        out += fmt::format("{:>5}  {:<16}  match\n", "PID", "COMM");
        // Keep at most 500 hits per section.
        std::size_t n = std::min<std::size_t>(hits.size(), 500);
        for (std::size_t i = 0; i < n; ++i) {
            out += fmt::format("{:>5}  {:<16}  {}\n",
                               hits[i].pid, hits[i].comm.substr(0, 16),
                               hits[i].match);
        }
        if (hits.size() > 500) {
            out += fmt::format("... ({} more truncated)\n", hits.size() - 500);
        }
    };
    emit_section("URLs",          per_pid_url);
    emit_section("IPv4",          per_pid_ipv4);
    emit_section("Emails",        per_pid_email);
    emit_section("JWT tokens",    per_pid_jwt);
    emit_section("AWS access keys", per_pid_aws);

    return ByteBuf(out.begin(), out.end());
}

// Global IOC pass: extract strings per process, filter through the IOC battery
// (URL/IPv4/email/JWT/AWS). At namespace scope (moved out of the anonymous
// namespace) so Engine::global_iocs() can cache it across the txt/csv/json views.
std::vector<IocHit> collect_global_iocs(const Engine& eng) {
    std::vector<IocHit> out;
    constexpr std::size_t kCap = 50000;
    for (const auto& p : eng.processes()) {
        if (p.mm == 0) continue;
        if (out.size() >= kCap) break;
        auto hits = extract_strings(eng, p, /*min_len=*/8, /*max_hits=*/1500);
        for (const auto& h : hits) {
            IocCounts c;
            extract_iocs(h.text, c);
            auto add = [&](const char* type, std::vector<std::string>& vals) {
                for (auto& v : vals)
                    out.push_back({type, std::move(v), p.pid, p.comm});
            };
            add("url", c.urls);  add("ipv4", c.ipv4s);  add("email", c.emails);
            add("jwt", c.jwts);  add("aws_key", c.aws_keys);
            if (out.size() >= kCap) break;
        }
    }
    return out;
}

ByteBuf format_iocs_csv(const Engine& eng) {
    std::string out = "type,value,pid,comm\r\n";
    for (const auto& h : eng.global_iocs())
        out += fmt::format("{},{},{},{}\r\n",
                           h.type, csv_esc(h.value), h.pid, csv_esc(h.comm));
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_iocs_json(const Engine& eng) {
    std::string out = "[";
    const auto& hits = eng.global_iocs();
    for (std::size_t i = 0; i < hits.size(); ++i) {
        const auto& h = hits[i];
        out += fmt::format(
            "{}\n  {{\"type\":{},\"value\":{},\"pid\":{},\"comm\":{}}}",
            i ? "," : "",
            json_esc(h.type), json_esc(h.value), h.pid, json_esc(h.comm));
    }
    out += "\n]\n";
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
