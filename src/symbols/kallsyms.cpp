// kallsyms.cpp — see header for design notes.
//
// Wire layout (modern x86_64 kernels, ≥ 4.6, CONFIG_KALLSYMS_BASE_RELATIVE=y):
//
//   [i32 × N]    kallsyms_offsets         signed offsets from relative_base
//   [u64]        kallsyms_relative_base   absolute VA the offsets are relative to
//   [u32 × N]    kallsyms_seqs_of_names   only on ≥ 6.2 kernels
//   [u32]        kallsyms_num_syms        N
//   [u8  × *]    kallsyms_names           length-prefixed sequence of token bytes
//   [u64 × M]    kallsyms_markers         marker[i] = offset in names of (i·256)th symbol
//   [u8  × *]    kallsyms_token_table     256 NUL-terminated short strings
//   [u16 × 256]  kallsyms_token_index     starting offset of token i inside token_table
//
// We scan for token_index (the most distinctive shape), validate token_table
// sitting right before it, then walk backward to recover everything else.
//
#include "symbols/kallsyms.h"
#include "core/log.h"
#include "core/app_paths.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>
#include <vector>

namespace lmpfs::linux {

namespace {

// Tunables --------------------------------------------------------------

// We scan in 4 MiB chunks (matching banner_scan / swapper_scan / btf_probe).
// Token-index hits are dense candidates; we trade scan cost for completeness.
constexpr std::size_t kScanChunk = 4 * 1024 * 1024;

// kallsyms_names is at most a few MiB; markers values can never exceed it.
// 64 MiB is a comfortable bound for any kernel built in the last decade.
constexpr u64 kMaxNamesSize = 64 * 1024 * 1024;

// Largest sane token_table size (256 short strings; typically 600–1500 B).
constexpr u32 kMaxTokenTableSize = 4096;

// Number of symbols (kallsyms_num_syms). Bounded loosely: typical kernels
// have 100k–300k, but small embedded kernels can have ~20k and bleeding-edge
// distro kernels with debug builds approach 500k.
constexpr u32 kMinNumSyms = 5000;
constexpr u32 kMaxNumSyms = 2'000'000;

// Step 1: token_index signature scan -------------------------------------

// Returns true if the 512-byte window at `buf` looks like a kallsyms_token_index.
//
// Constraints on the real article (validated against multiple kernels):
//   - 256 u16 values; first is 0
//   - Monotonically non-decreasing (each token starts at the byte after
//     the previous token's NUL terminator)
//   - v[255] ≥ 256: real token tables are ≥ 600 bytes since most tokens
//     have at least 1 char + NUL = 2 bytes apiece.
//   - v[255] < 2048: real token tables fit comfortably in 2 KiB.
//   - Consecutive deltas ≤ 40 (no individual token longer than ~40 chars)
//   - At least 200 of the 255 deltas are > 1 (i.e., most tokens are non-empty;
//     filters mostly-zero pages whose accidental u16 sequence happens to be
//     monotonic but degenerate).
bool plausible_token_index(const u8* buf) {
    u16 v[256];
    std::memcpy(v, buf, 512);
    if (v[0] != 0)        return false;
    if (v[255] < 256)     return false;
    if (v[255] >= kMaxTokenTableSize) return false;
    std::size_t nonempty = 0;
    for (int i = 1; i < 256; ++i) {
        if (v[i] < v[i - 1]) return false;
        u16 d = static_cast<u16>(v[i] - v[i - 1]);
        if (d > 40) return false;
        if (d > 1)  ++nonempty;
    }
    if (nonempty < 200) return false;
    return true;
}

struct TokenIndexHit {
    PAddr pa;
    u16   indices[256];
};

std::vector<TokenIndexHit> scan_token_index(const PhysicalLayer& phys) {
    std::vector<TokenIndexHit> hits;
    std::vector<u8>            buf(kScanChunk + 512);

    const PAddr maxa = phys.max_address();
    log::debug("kallsyms: scanning {:.1f} MB for kallsyms_token_index...",
              maxa / (1024.0 * 1024));

    PAddr pa = 0;
    while (pa < maxa) {
        std::size_t want = std::min<u64>(kScanChunk + 512, maxa - pa);
        std::size_t got  = phys.read(pa, buf.data(), want);
        if (got < 512) { pa += kScanChunk; continue; }

        const std::size_t scan_end = got - 512;
        // Step by 2 bytes (kallsyms_token_index is `.short`, i.e. u16-aligned).
        // We later filter to 16-byte aligned PAs (`.p2align 4` on x86_64),
        // but keep the 2-byte step here so we can fall back to non-x86 arches
        // (or unusual configs) without re-scanning.
        for (std::size_t i = 0; i <= scan_end; i += 2) {
            if (plausible_token_index(buf.data() + i)) {
                TokenIndexHit h;
                h.pa = pa + i;
                std::memcpy(h.indices, buf.data() + i, 512);
                hits.push_back(h);
            }
        }
        pa += kScanChunk;
    }
    log::debug("kallsyms: {} token_index candidate(s)", hits.size());
    return hits;
}

// Step 2: validate + read token_table ------------------------------------

struct TokenTable {
    PAddr                    pa;
    u32                      size;     // bytes
    std::vector<std::string> tokens;   // 256 entries
};

// Token table lies immediately before token_index. Total size is bounded.
// Validation: for each i ∈ [1..255], the byte at (start + indices[i] - 1)
// must be NUL (i.e. previous token's terminator), and the byte at
// (start + size - 1) must also be NUL (terminator of token 255).
std::optional<TokenTable>
validate_token_table(const PhysicalLayer& phys, const TokenIndexHit& hit) {
    if (hit.pa < kMaxTokenTableSize) return std::nullopt;

    const PAddr tt_pa_max = hit.pa;
    std::vector<u8> buf(kMaxTokenTableSize);
    if (phys.read(tt_pa_max - kMaxTokenTableSize, buf.data(), buf.size())
        != buf.size())
        return std::nullopt;

    // The token table ends exactly at the end of `buf` (i.e. at hit.pa).
    // We don't know where it starts in `buf` — try each possibility.
    //
    // Constraint: size > indices[255] (token 255 must fit). Walk upward
    // through plausible sizes; first one that validates wins.
    for (u32 size = hit.indices[255] + 1; size <= kMaxTokenTableSize; ++size) {
        const std::size_t start = kMaxTokenTableSize - size;
        const u64 candidate_pa = (tt_pa_max - kMaxTokenTableSize) + start;
        // The kernel's `.align 8` directive guarantees kallsyms_token_table
        // starts on an 8-byte boundary. This filter eliminates 99 %+ of the
        // remaining false positives without rejecting any real candidate.
        if (candidate_pa & 7) continue;

        // Every token's last byte (== byte before next token's start)
        // must be NUL. Token 255's last byte (at `start + size - 1`) too.
        bool ok = (buf[kMaxTokenTableSize - 1] == 0);
        for (int i = 1; ok && i < 256; ++i) {
            std::size_t off = start + hit.indices[i];
            if (off == 0 || buf[off - 1] != 0) ok = false;
        }
        if (!ok) continue;

        // Sanity: the bytes between NULs should look like kernel-symbol-name
        // fragments — printable ASCII, mostly [a-z0-9_]. Count how many of the
        // non-NUL bytes look fragment-y.
        std::size_t total_nonnul = 0, fragment_chars = 0;
        for (std::size_t i = start; i < kMaxTokenTableSize; ++i) {
            u8 c = buf[i];
            if (c == 0) continue;
            ++total_nonnul;
            bool ok_char = (c >= 'a' && c <= 'z') ||
                           (c >= 'A' && c <= 'Z') ||
                           (c >= '0' && c <= '9') ||
                           c == '_' || c == '.' || c == '$' || c == ' ';
            if (ok_char) ++fragment_chars;
        }
        // Require ≥ 90 % of non-NUL bytes to look like fragment chars.
        if (total_nonnul == 0) continue;
        if (fragment_chars * 10 < total_nonnul * 9) continue;

        TokenTable tt;
        tt.pa   = (tt_pa_max - kMaxTokenTableSize) + start;
        tt.size = size;
        tt.tokens.resize(256);
        for (int i = 0; i < 256; ++i) {
            const std::size_t s = start + hit.indices[i];
            const std::size_t e = (i < 255) ? (start + hit.indices[i + 1])
                                            : (kMaxTokenTableSize);
            // [s, e-1) is the token bytes; e-1 is the trailing NUL.
            if (e == 0 || e <= s) continue;
            tt.tokens[i].assign(reinterpret_cast<const char*>(buf.data() + s),
                                e - s - 1);
        }
        return tt;
    }
    return std::nullopt;
}

// Step 3: walk backward to find markers, names, num_syms ------------------
//
// kallsyms_markers is `markers_t[M]` right before kallsyms_token_table, with
// M = ceil(num_syms / 256). The element size depends on kernel version:
//   * Older / 32-bit kernels: u32 markers
//   * Older 64-bit kernels (pre ~6.0): u64 markers (one per "unsigned long")
//   * Newer kernels (≥ ~6.0): u32 markers even on 64-bit (kernel commit
//     `kallsyms: switch to relative addressing for all symbols`, plus the
//     subsequent "reduce kallsyms data size" series).
// All flavors share: markers[0] = 0, monotonically increasing, last value
// equals total names size (< ~64 MiB).
//
// We try BOTH widths and pick the one that produces a self-consistent walk.
struct MarkersResult {
    PAddr            pa;
    u32              width;       // 4 or 8 bytes per entry
    std::vector<u64> values;
};

namespace {
std::optional<MarkersResult>
find_markers_width(const PhysicalLayer& phys, PAddr token_table_pa, u32 width) {
    // token_table is `.align 8`; markers must end on a (width)-aligned
    // boundary at or before token_table_pa.
    constexpr u64 kWindow = 16 * 1024 * 1024;
    if (token_table_pa < width) return std::nullopt;

    u64 scan_top = token_table_pa & ~(static_cast<u64>(width) - 1);
    if (scan_top == token_table_pa) scan_top -= width;
    // Pre-condition: alignment-padding between markers and token_table is
    // at most (width - 1) bytes — i.e., at most one slot of leading-zero.

    const u64 read_start = (scan_top > kWindow) ? (scan_top - kWindow + width) : 0;
    const std::size_t span = static_cast<std::size_t>(scan_top + width - read_start);
    std::vector<u8> buf(span);
    if (phys.read(read_start, buf.data(), buf.size()) != span)
        return std::nullopt;

    std::vector<u64> rev;       // markers in reverse order
    bool seen_nonzero = false;
    int  zero_padding = 0;

    for (i64 pos = static_cast<i64>(span) - width; pos >= 0; pos -= width) {
        u64 v = 0;
        std::memcpy(&v, buf.data() + pos, width);   // LE read, zero-extend

        if (!seen_nonzero) {
            if (v == 0) {
                if (++zero_padding > 1) return std::nullopt;
                continue;
            }
            if (v >= kMaxNamesSize) return std::nullopt;
            seen_nonzero = true;
            rev.push_back(v);
            continue;
        }

        if (v == 0) {
            rev.push_back(0);
            break;
        }
        if (v >= kMaxNamesSize)              return std::nullopt;
        if (!rev.empty() && v >= rev.back()) return std::nullopt;
        rev.push_back(v);
    }
    if (rev.empty() || rev.back() != 0) return std::nullopt;
    // Need at least 2 entries (M=1 means num_syms ≤ 256 — implausible kernel).
    if (rev.size() < 2) return std::nullopt;
    // Upper bound: a crafted dump could present a long monotonic run that would
    // inflate num_syms (= 256·M) into a multi-GB offsets allocation downstream.
    // ceil(kMaxNumSyms/256) markers is the most any sane kernel can have.
    if (rev.size() > kMaxNumSyms / 256 + 2) return std::nullopt;

    MarkersResult mr;
    mr.width = width;
    mr.values.assign(rev.rbegin(), rev.rend());
    // The markers array ENDS at (scan_top + width) − (alignment padding we
    // skipped). Then markers_pa = end − width · size. Failing to subtract
    // the skipped padding here is a real bug — the off-by-4 it caused led
    // the names anchor to compute the wrong `names_pa` by a few bytes,
    // which in turn put kallsyms_offsets out of reach.
    const u64 markers_end = (scan_top + width)
                          - static_cast<u64>(width) * zero_padding;
    mr.pa = markers_end - static_cast<u64>(width) * mr.values.size();
    return mr;
}
} // anon

std::optional<MarkersResult>
find_markers(const PhysicalLayer& phys, PAddr token_table_pa) {
    // Modern kernels (≥ ~6.0) use u32 markers — try that first.
    if (auto r = find_markers_width(phys, token_table_pa, 4)) {
        log::debug("kallsyms.markers: u32 layout — {} entries, last = {:#x}",
                   r->values.size(), r->values.back());
        return r;
    }
    // Older 64-bit layout.
    if (auto r = find_markers_width(phys, token_table_pa, 8)) {
        log::debug("kallsyms.markers: u64 layout — {} entries, last = {:#x}",
                   r->values.size(), r->values.back());
        return r;
    }
    return std::nullopt;
}

// Step 4: from markers, identify num_syms and walk kallsyms_names ---------
//
// num_syms is a u32 right before kallsyms_names (with possible 4-byte
// alignment padding). markers.values.size() == ceil(num_syms / 256), so
// num_syms ∈ [(M-1)·256 + 1, M·256].
//
// We locate num_syms by reading 4 bytes immediately before names; the
// candidate must satisfy ceil(N/256) == M and the byte at (names_pa) must
// be a sensible length prefix for the first name.
struct NamesAndCount {
    PAddr names_pa;
    PAddr num_syms_pa;
    u32   num_syms;
    u32   names_size;
};

std::optional<NamesAndCount>
find_names_and_count(const PhysicalLayer&    phys,
                     PAddr                   markers_pa,
                     u32                     num_markers,
                     const std::vector<u64>& marker_values)
{
    if (num_markers == 0) return std::nullopt;
    const u32 n_min       = (num_markers - 1) * 256 + 1;
    const u32 n_max       = num_markers * 256;
    const u64 last_marker = marker_values.back();
    const u64 first_marker_after_zero =
        (marker_values.size() >= 2) ? marker_values[1] : 0;

    // Strategy: anchor on the LAST batch.
    //
    // markers[M-1] is the offset within kallsyms_names where the last 256-
    // symbol batch (entries 256*(M-1) … N-1) begins. The last batch
    // contains 1–256 entries and is typically 256 × ~12B ≈ 3 KB.
    //
    // We don't need to walk all 200k entries (which would cross dump gaps
    // for AVML/sparse formats). Instead:
    //   1. Try each (padding ∈ [0..7], batch_byte_size K ∈ [2..16384]) pair.
    //   2. Walk forward exactly K bytes from (markers_pa − padding − K),
    //      counting entries; require ending exactly at markers_pa − padding
    //      and entry count ∈ [1..256].
    //   3. Compute nsyms = 256·(M−1) + cnt; reject if out of [n_min, n_max].
    //   4. Compute names_pa = markers_pa − padding − last_marker − K.
    //   5. **Cross-validate** with the FIRST batch: walk 256 entries from
    //      names_pa; they should total exactly markers[1] bytes. This
    //      filters out coincidental last-batch matches.
    // Worst-case work: 8 × 16k × O(256) ≈ 30 M ops, fast.

    auto walk_block = [](const u8* buf, std::size_t span,
                         u32 max_entries,
                         std::size_t& out_cur, u32& out_cnt) -> bool {
        std::size_t cur = 0;
        u32 cnt = 0;
        while (cur < span && cnt < max_entries) {
            u8 b0 = buf[cur];
            u32 len, hdr;
            if (b0 & 0x80) {
                if (cur + 1 >= span) return false;
                len = (b0 & 0x7F) | (u32(buf[cur + 1]) << 7);
                hdr = 2;
            } else {
                len = b0;
                hdr = 1;
            }
            if (len == 0)               return false;
            if (cur + hdr + len > span) return false;
            cur += hdr + len;
            ++cnt;
        }
        out_cur = cur;
        out_cnt = cnt;
        return true;
    };

    constexpr u32 kMaxLastBatchSize = 16384;
    for (int padding = 0; padding < 8; ++padding) {
        if (markers_pa < kMaxLastBatchSize + padding) continue;
        const u64 last_batch_end_pa = markers_pa - padding;

        // Read the last 16 KB right before markers (last batch always fits).
        std::vector<u8> lbuf(kMaxLastBatchSize);
        if (phys.read(last_batch_end_pa - kMaxLastBatchSize, lbuf.data(),
                      lbuf.size()) != lbuf.size())
            continue;

        // For each K (batch bytes), walk forward from (size - K).
        for (u32 K = 2; K <= kMaxLastBatchSize; ++K) {
            const std::size_t off = lbuf.size() - K;
            std::size_t cur = 0;
            u32 cnt = 0;
            if (!walk_block(lbuf.data() + off, K, 256, cur, cnt)) continue;
            if (cur != K)                continue;
            if (cnt == 0 || cnt > 256)   continue;

            const u32 nsyms = 256 * (num_markers - 1) + cnt;
            if (nsyms < n_min || nsyms > n_max) continue;
            if (nsyms > kMaxNumSyms)            continue;  // crafted-dump guard

            const u64 names_pa = last_batch_end_pa - K - last_marker;

            // Cross-validate with first batch: walk 256 entries from names_pa;
            // they should total exactly markers[1] bytes. Also serves as the
            // primary filter for spurious K values.
            if (first_marker_after_zero > 0 &&
                first_marker_after_zero < 65536)
            {
                std::vector<u8> fbuf(first_marker_after_zero);
                if (phys.read(names_pa, fbuf.data(), fbuf.size())
                    != fbuf.size())
                    continue;
                std::size_t fcur = 0;
                u32 fcnt = 0;
                if (!walk_block(fbuf.data(), fbuf.size(), 256, fcur, fcnt))
                    continue;
                if (fcur != first_marker_after_zero || fcnt != 256) continue;
            }

            // Locate the actual `kallsyms_num_syms` u32 by scanning backward
            // from names_pa for our known value. There can be 0–15 bytes of
            // `.p2align 4` padding between num_syms and names; assuming a
            // fixed 4 is the classic off-by-N bug (and is wrong on Alpine).
            u64 num_syms_pa = 0;
            for (int back = 4; back <= 16; back += 4) {
                if (names_pa < (u64)back) continue;
                u32 v;
                if (phys.read(names_pa - back, &v, 4) != 4) continue;
                if (v == nsyms) { num_syms_pa = names_pa - back; break; }
            }
            if (num_syms_pa == 0) continue;     // false anchor, try next K

            NamesAndCount r;
            r.names_pa    = names_pa;
            r.num_syms_pa = num_syms_pa;
            r.num_syms    = nsyms;
            r.names_size  = static_cast<u32>(last_marker + K);
            log::debug("kallsyms.names: anchored on last batch K={} cnt={} "
                       "padding={} nsyms={} names_pa={:#x} num_syms_pa={:#x} "
                       "(num_syms→names gap = {} B)",
                       K, cnt, padding, nsyms, names_pa, num_syms_pa,
                       names_pa - num_syms_pa - 4);
            return r;
        }
    }
    return std::nullopt;
}

// Step 5: read offsets[N] and relative_base ------------------------------
//
// Right before num_syms (with possible 4–8 byte alignment padding) lives
// either kallsyms_seqs_of_names[N] (u32 × N, ≥ 6.2 kernels) or
// kallsyms_relative_base (u64) — directly. Then offsets[N] (i32 × N).
//
// Disambiguation: try the BASE_RELATIVE layout first. We expect a u64
// relative_base just before num_syms, then i32 offsets[N] preceding that.
//
// Validation: offsets[0] should typically be 0 (the kernel image text base
// is exactly at relative_base on many kernels) or a small positive value.
// All offsets should be in [-2^30, 2^30] range when interpreted as i32.
struct OffsetsResult {
    PAddr offsets_pa;
    PAddr relative_base_pa;
    VAddr relative_base;
    bool  has_seqs_of_names;
    std::vector<i32> offsets;
};

std::optional<OffsetsResult>
find_offsets(const PhysicalLayer& phys, PAddr num_syms_pa, u32 num_syms,
             PAddr token_index_end_pa = 0)
{
    // Defensive: num_syms gates two `4·num_syms`-byte allocations below. It is
    // already capped in find_names_and_count, but guard here too so this stays
    // safe if ever called with an unvalidated count.
    if (num_syms == 0 || num_syms > kMaxNumSyms) return std::nullopt;

    // kallsyms_relative_base is a u64 kernel image VA: top 4 bytes are
    // 0xFFFFFFFF on x86_64. It sits at an 8-byte boundary somewhere before
    // (possibly with kallsyms_seqs_of_names[N] in between) num_syms_pa.
    //
    // Kernel scripts/kallsyms.c emits each label with `ALGN`. On x86_64,
    // `__ALIGN` = `.p2align 4` = 16-byte alignment, so the relative_base
    // could sit 0–15 bytes padding before num_syms_pa minus its own 8 bytes.
    //
    // Strategy: try both layouts (with / without seqs_of_names) and for each,
    // sweep 8-byte-aligned positions in a small window looking for a u64
    // whose top 4 bytes are 0xFFFFFFFF.

    auto find_rb_pa = [&](u64 window_end) -> std::optional<u64> {
        // Sweep down in 8-byte steps. relative_base is u64-aligned. The
        // padding between (offsets+seqs+num_syms) and relative_base is
        // bounded by `ALGN` — at most 15 bytes on x86_64 (`.p2align 4`).
        // We cap slack at 24 bytes to avoid catching stray kernel pointers
        // that live inside surrounding structures (which produced false
        // positives in early testing).
        for (int slack = 0; slack <= 24; slack += 8) {
            if (window_end < 8 + slack) continue;
            const u64 cand = (window_end - 8 - slack) & ~7ULL;
            u64 rb;
            if (phys.read(cand, &rb, 8) != 8) continue;
            if ((rb >> 32) == 0xFFFFFFFFu) return cand;
        }
        return std::nullopt;
    };

    auto try_layout = [&](bool with_seqs) -> std::optional<OffsetsResult> {
        u64 window_end = num_syms_pa;
        if (with_seqs) {
            if (window_end < 4ULL * num_syms) return std::nullopt;
            window_end -= 4ULL * num_syms;
        }
        auto rb_pa_opt = find_rb_pa(window_end);
        if (!rb_pa_opt) return std::nullopt;
        const u64 rb_pa = *rb_pa_opt;

        u64 rb;
        phys.read(rb_pa, &rb, 8);

        // offsets[N] is right before rb_pa (possibly with up to 15 bytes
        // alignment padding). Sweep to find offsets_pa.
        for (int slack = 0; slack <= 32; ++slack) {
            if (rb_pa < (4ULL * num_syms + slack)) break;
            const u64 offsets_pa = (rb_pa - 4ULL * num_syms - slack) & ~3ULL;
            if (offsets_pa & 3) continue;
            if (rb_pa - offsets_pa - 4ULL * num_syms > 31) break;

            std::vector<i32> offs(num_syms);
            if (phys.read(offsets_pa, offs.data(), 4ULL * num_syms)
                != 4ULL * num_syms)
                continue;

            // Sanity check.
            std::size_t in_range = 0, non_neg = 0, nonzero = 0;
            for (i32 o : offs) {
                if (o >= -(1 << 30) && o < (1 << 30)) ++in_range;
                if (o >= 0)                          ++non_neg;
                if (o != 0)                          ++nonzero;
            }
            // Be tolerant of dump gaps: some offsets may read as 0 if their
            // page is missing. Require: ≥ 50 % in-range non-zero values.
            if (nonzero  < num_syms / 2) continue;
            if (in_range < num_syms * 9 / 10) continue;
            log::debug("kallsyms.offsets: accepted offsets_pa={:#x} (slack {}): "
                       "{}/{} in-range, {}/{} non-neg, {}/{} non-zero",
                       offsets_pa, slack, in_range, num_syms,
                       non_neg, num_syms, nonzero, num_syms);

            OffsetsResult r;
            r.offsets_pa        = offsets_pa;
            r.relative_base_pa  = rb_pa;
            r.relative_base     = rb;
            r.has_seqs_of_names = with_seqs;
            r.offsets           = std::move(offs);
            return r;
        }
        return std::nullopt;
    };

    if (auto r = try_layout(false)) return r;   // pre-6.2
    if (auto r = try_layout(true))  return r;   // ≥ 6.2 (kallsyms_seqs_of_names)

    // -------- Alpine-style "trailing" layout --------------------------
    // Some kernel builds (notably Alpine's `linux-virt`) place
    //   kallsyms_offsets[N]  immediately after  kallsyms_token_index
    //   kallsyms_relative_base immediately after  offsets[N] (with 0–15 B pad)
    // and `linux_banner` is interposed between offsets/relative_base and
    // kallsyms_num_syms — exactly the opposite of the scripts/kallsyms.c
    // textual order. This appears to be a linker artefact (each
    // `output_label` opens its own `.section ".rodata"` block, and the
    // linker can reorder them when other compilation units contribute
    // .rodata in between).
    if (token_index_end_pa != 0) {
        const u64 offsets_pa = token_index_end_pa;
        std::vector<i32> offs(num_syms);
        if (phys.read(offsets_pa, offs.data(), 4ULL * num_syms)
            == 4ULL * num_syms)
        {
            std::size_t in_range = 0, nonzero = 0;
            for (i32 o : offs) {
                if (o >= -(1 << 30) && o < (1 << 30)) ++in_range;
                if (o != 0)                          ++nonzero;
            }
            // Same gap-tolerance thresholds as the standard branch.
            if (nonzero >= num_syms / 2 &&
                in_range >= num_syms * 9 / 10)
            {
                const u64 after_offsets = offsets_pa + 4ULL * num_syms;
                for (int slack = 0; slack <= 24; ++slack) {
                    const u64 rb_pa = (after_offsets + slack) & ~7ULL;
                    if (rb_pa < after_offsets) continue;
                    u64 rb;
                    if (phys.read(rb_pa, &rb, 8) != 8) continue;
                    if ((rb >> 32) != 0xFFFFFFFFu) continue;
                    log::debug("kallsyms.offsets: alpine-style layout — "
                               "offsets_pa={:#x} rb_pa={:#x} rb={:#x}",
                               offsets_pa, rb_pa, rb);
                    OffsetsResult r;
                    r.offsets_pa        = offsets_pa;
                    r.relative_base_pa  = rb_pa;
                    r.relative_base     = rb;
                    r.has_seqs_of_names = false;
                    r.offsets           = std::move(offs);
                    return r;
                }
            }
        }
    }
    return std::nullopt;
}

// Step 6: decode kallsyms_names + materialize the symbols ----------------

std::vector<KallsymsEntry>
decode_names(const PhysicalLayer&            phys,
             const NamesAndCount&            nc,
             const std::vector<std::string>& tokens,
             const std::vector<i32>&         offsets,
             VAddr                           relative_base)
{
    std::vector<u8> buf(nc.names_size);
    phys.read(nc.names_pa, buf.data(), nc.names_size);

    std::vector<KallsymsEntry> out;
    out.reserve(nc.num_syms);

    std::size_t cur = 0;
    for (u32 i = 0; i < nc.num_syms; ++i) {
        if (cur >= buf.size()) break;
        u8 b0 = buf[cur];
        u32 len;
        if (b0 & 0x80) {
            // 2-byte length encoding (kernel ≥ 6.7)
            if (cur + 1 >= buf.size()) break;
            len = (b0 & 0x7F) | (u32(buf[cur + 1]) << 7);
            cur += 2;
        } else {
            len = b0;
            cur += 1;
        }
        if (len == 0 || cur + len > buf.size()) break;

        // Concatenate tokens. First byte = type code (after decoding via
        // the token table); remaining bytes = symbol name itself.
        std::string decoded;
        decoded.reserve(len * 4);
        for (u32 j = 0; j < len; ++j) {
            u8 idx = buf[cur + j];
            decoded += tokens[idx];
        }
        cur += len;

        KallsymsEntry e;
        e.type    = decoded.empty() ? '?' : decoded[0];
        e.name    = decoded.empty() ? std::string() : decoded.substr(1);
        // Address decode (CONFIG_KALLSYMS_BASE_RELATIVE=y). From the kernel's
        // own `kallsyms_sym_address` in <kernel/kallsyms_internal.h>:
        //   if (kallsyms_offsets[idx] >= 0)
        //       return kallsyms_relative_base + (u32)kallsyms_offsets[idx];
        //   return kallsyms_relative_base - 1 - kallsyms_offsets[idx];
        // The negative branch handles CONFIG_KALLSYMS_ABSOLUTE_PERCPU symbols
        // (percpu / absolute VAs outside [_text, _etext)). The unsigned ALU
        // wraps cleanly: `−1 − offset` ≡ relative_base + (~offset_low_32),
        // so we can write it as a single expression for both branches.
        if (offsets[i] >= 0) {
            e.address = relative_base + static_cast<u64>(
                            static_cast<u32>(offsets[i]));
        } else {
            // -1 - (i64)offsets[i] computed in unsigned 64-bit so it doesn't
            // overflow into UB territory.
            e.address = relative_base +
                static_cast<u64>(-1LL - static_cast<i64>(offsets[i]));
        }
        out.push_back(std::move(e));
    }
    return out;
}

} // anonymous

// Public API ------------------------------------------------------------

KallsymsResult extract_kallsyms(const PhysicalLayer& phys) {
    KallsymsResult r;

    auto idx_hits = scan_token_index(phys);
    if (idx_hits.empty()) {
        r.error = "no plausible kallsyms_token_index found in the dump's "
                  "accessible bytes — kernel rodata region is likely "
                  "absent from this capture";
        log::warn("kallsyms: {}", r.error);
        return r;
    }

    // Prefer hits that are 16-byte aligned (kernel `ALGN` = `.p2align 4` on
    // x86_64), then 8-aligned, then by PA. The CORRECT token_index_pa is
    // 16-aligned; near-misses (PA±2, PA±4) often pass our heuristics because
    // they hit alignment-padding NULs that look like additional empty tokens.
    std::sort(idx_hits.begin(), idx_hits.end(),
        [](const TokenIndexHit& a, const TokenIndexHit& b) {
            auto rank = [](u64 pa) {
                if ((pa & 15) == 0) return 0;
                if ((pa &  7) == 0) return 1;
                if ((pa &  3) == 0) return 2;
                return 3;
            };
            int ra = rank(a.pa), rb = rank(b.pa);
            if (ra != rb) return ra < rb;
            return a.pa < b.pa;
        });

    // Per-stage counters. Surfaced in a single line at the end so a failed
    // extraction tells the user *where* it failed — instead of just "0 of N
    // candidates worked", they see e.g. "token_table OK on 25/321, but
    // markers walk rejected every one" → that's the AVML-skip-of-rodata
    // fingerprint, not a parser bug.
    std::size_t n_tt_ok      = 0;
    std::size_t n_markers_ok = 0;
    std::size_t n_names_ok   = 0;
    std::size_t n_decode_ok  = 0;

    for (const auto& hit : idx_hits) {
        auto tt = validate_token_table(phys, hit);
        if (!tt) continue;
        ++n_tt_ok;
        // Demote initial hit log to debug — early validation gives us
        // many near-miss candidates (e.g. the PA 0x21b7… false-positive
        // cluster on Ubuntu dumps) that quickly fail at the markers walk.
        // Promoting to info only once markers succeed keeps the user-visible
        // log clean.
        log::debug("kallsyms: token_index candidate @ PA {:#x}; token_table "
                   "@ PA {:#x} (size {} B), sample tokens: '{}' '{}' '{}' '{}' '{}'",
                   hit.pa, tt->pa, tt->size,
                   tt->tokens[1], tt->tokens[2], tt->tokens[3],
                   tt->tokens[4], tt->tokens[5]);

        auto markers = find_markers(phys, tt->pa);
        if (!markers) {
            log::debug("kallsyms: marker walk failed at this hit");
            continue;
        }
        ++n_markers_ok;
        log::debug("kallsyms: token_index @ PA {:#x}; token_table @ PA {:#x} "
                  "(size {} B)", hit.pa, tt->pa, tt->size);
        log::debug("kallsyms: markers @ PA {:#x} (count = {}, last = {:#x})",
                  markers->pa, markers->values.size(), markers->values.back());

        auto nc = find_names_and_count(phys, markers->pa,
                                       static_cast<u32>(markers->values.size()),
                                       markers->values);
        if (!nc) {
            log::debug("kallsyms: names/count walk failed at this hit");
            continue;
        }
        ++n_names_ok;
        log::debug("kallsyms: num_syms @ PA {:#x} = {}; names @ PA {:#x} "
                  "(size {} B)", nc->num_syms_pa, nc->num_syms,
                  nc->names_pa, nc->names_size);

        // token_index is 256 × u16 = 512 bytes long; its END is the natural
        // anchor for the Alpine-style layout where kallsyms_offsets follows.
        const PAddr token_index_end_pa = hit.pa + 512;
        auto off = find_offsets(phys, nc->num_syms_pa, nc->num_syms,
                                token_index_end_pa);
        std::vector<i32> offsets;
        VAddr            relative_base = 0;
        bool             have_offsets  = false;
        if (off) {
            log::debug("kallsyms: offsets @ PA {:#x}; relative_base @ PA {:#x} "
                      "= {:#x} (seqs_of_names: {})",
                      off->offsets_pa, off->relative_base_pa, off->relative_base,
                      off->has_seqs_of_names ? "yes" : "no");
            offsets       = std::move(off->offsets);
            relative_base = off->relative_base;
            have_offsets  = true;
        } else {
            // Degraded mode: dump format (e.g. AVML sparse) doesn't preserve
            // kallsyms_offsets / kallsyms_relative_base — they're in pages the
            // dump skipped. We can still decode every symbol's NAME from
            // kallsyms_names; the addresses are reported as 0 and the caller
            // is responsible for filling them in via another mechanism
            // (e.g. cross-referencing with init_task / banner / per-symbol
            // scans). For kdump / vmcore / live targets this branch won't fire.
            log::warn("kallsyms: offsets/relative_base unrecoverable (dump gap); "
                      "extracting names only — symbol addresses set to 0");
            offsets.assign(nc->num_syms, 0);
            relative_base = 0;
        }

        auto syms = decode_names(phys, *nc, tt->tokens, offsets, relative_base);
        if (syms.size() < kMinNumSyms) {
            log::debug("kallsyms: decoded only {} symbols, looks wrong",
                       syms.size());
            continue;
        }
        ++n_decode_ok;
        (void)have_offsets;

        // Index by name (first-occurrence wins).
        std::unordered_map<std::string, std::size_t> by_name;
        by_name.reserve(syms.size());
        for (std::size_t i = 0; i < syms.size(); ++i)
            by_name.try_emplace(syms[i].name, i);

        r.ok              = true;
        r.symbols         = std::move(syms);
        r.by_name         = std::move(by_name);
        r.token_table_pa  = tt->pa;
        r.token_index_pa  = hit.pa;
        r.markers_pa      = markers->pa;
        r.names_pa        = nc->names_pa;
        r.num_syms_pa     = nc->num_syms_pa;
        r.offsets_pa      = off ? off->offsets_pa       : 0;
        r.relative_base_pa = off ? off->relative_base_pa : 0;
        r.num_syms        = nc->num_syms;
        r.num_markers     = static_cast<u32>(markers->values.size());
        r.names_size      = nc->names_size;
        r.token_table_size = tt->size;
        r.base_relative   = true;
        r.relative_base   = relative_base;

        log::debug("kallsyms: extracted {} symbols (relative_base = {:#x})",
                  r.symbols.size(), r.relative_base);
        // Quick sanity-trace: log the first few decoded symbols so we can
        // spot decoding regressions at a glance during development.
        for (std::size_t i = 0; i < r.symbols.size() && i < 3; ++i)
            log::debug("kallsyms[{}]: type={} name='{}'",
                       i, r.symbols[i].type, r.symbols[i].name);
        return r;
    }

    // No candidate validated all the way through. Give the user a single
    // line they can act on: where exactly each stage drained off.
    //
    // Reading the funnel:
    //   * scanner ≫ tt_ok  → most candidates were noise (e.g. x86 disassembler
    //     mnemonic tables in `arch/x86/lib/insn.c` happen to match the u16
    //     monotonicity shape). Normal — the real candidate just needs to
    //     also be present.
    //   * tt_ok = 0         → kernel rodata is missing from the dump. Most
    //     likely cause: AVML captured a subset of E820 ranges that excluded
    //     the kernel image's rodata pages. Cross-check by searching for
    //     `linux_banner` — if banner is present but token_table absent, the
    //     intermediate rodata pages were skipped by the capture.
    //   * markers_ok = 0    → token_table found but no markers array fits in
    //     front of it. Same diagnosis as above; markers live in the same
    //     rodata section.
    //   * names_ok = 0      → markers walk OK but num_syms/names anchor
    //     unrecoverable. Suggests partial capture inside the rodata pages.
    //   * decode_ok = 0     → got through anchors but couldn't decode the
    //     compressed symbol names. Almost always means we picked a near-miss
    //     candidate; raise scanner specificity.
    r.error = fmt::format(
        "no token_index candidate produced a valid kallsyms layout "
        "(scanner: {} candidates → token_table validated: {} → "
        "markers walk: {} → names anchor: {} → name decode: {})",
        idx_hits.size(), n_tt_ok, n_markers_ok, n_names_ok, n_decode_ok);
    log::warn("kallsyms: extraction failed — {}", r.error);
    log::warn("kallsyms: downstream features that need kernel-VA reads "
              "(modules, dmesg, full DTB walk) will be degraded. To recover, "
              "supply a symbol-rich ISF: run with --auto-fetch, or --vmlinux "
              "<path>, or place a known-good ISF in {}.",
              paths::user_dir_hint("symbols"));
    return r;
}

const KallsymsEntry* find_symbol(const KallsymsResult& r, const std::string& name) {
    auto it = r.by_name.find(name);
    if (it == r.by_name.end()) return nullptr;
    return &r.symbols[it->second];
}

} // namespace lmpfs::linux
