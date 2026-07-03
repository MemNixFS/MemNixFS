// forensic_warmer.cpp — see header.
#include "vfs/forensic_warmer.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>

namespace lmpfs::vfs {

namespace {
// A file tagged "small" that nonetheless produces more than this is logged as
// a guardrail against mis-tagging — it still gets warmed, but the warning
// flags that forensic mode is holding more memory than the tag promised.
constexpr u64 kWarnBytes = 16ull * 1024 * 1024;   // 16 MiB
}

namespace detail {
std::string format_warm_duration(double seconds) {
    if (seconds < 60.0)
        return fmt::format("{:.1f}s", seconds);
    const int total = static_cast<int>(seconds);
    return fmt::format("{}m {:02d}s", total / 60, total % 60);
}
}  // namespace detail

ForensicWarmer::~ForensicWarmer() { join(); }

void ForensicWarmer::collect(const NodePtr& node, bool heavy_subtree) {
    if (!node) return;
    if (node->is_dir()) {
        // Entering one of these marks the subtree as "heavy" and pure
        // --precompute skips it (each is a corpus-wide pass — many seconds to
        // minutes — that shouldn't run on every mount; use --forensic / open
        // on demand instead):
        //   proc      — per-process analytics (hundreds of pids × costly)
        //   files / fs — recovered-file content (self-sizing; GB-scale in bulk)
        //   search    — iocs/yara scanners (full pass over every process)
        //   forensic  — timeline/snapshot aggregators (re-run findevil + heaps)
        //   pagecache — index over every cached inode (tens of thousands)
        const std::string& nm = node->name();
        bool heavy = heavy_subtree ||
                     nm == "proc"   || nm == "files"    || nm == "fs" ||
                     nm == "search" || nm == "forensic" || nm == "pagecache";
        for (auto& e : node->list()) collect(e.node, heavy);
        return;
    }
    if (!node->is_file()) return;
    const auto& c = node->cost();
    bool want;
    if (warm_all_) {
        // precompute: warm the light, system-wide analysis files so the tree
        // shows real sizes and opens instantly. Excluded as "heavy" (warmed
        // only if the user opts them in via --forensic's category mask):
        //   * Mem::Large           — per-process strings.txt (GB-scale in bulk)
        //   * heavy subtrees        — /proc, /files, /fs, /search (handled above)
        //   * ThreatHunt/PerProcess/Yara categories — findevil + per-process +
        //     YARA scans, each a full pass over the dump / every process.
        const bool heavy_cat =
            c.category == FileCost::Category::ThreatHunt  ||
            c.category == FileCost::Category::PerProcess  ||
            c.category == FileCost::Category::Yara;
        if (!node->warmable() || c.mem == FileCost::Mem::Large) {
            want = false;
        } else if (heavy_subtree || heavy_cat) {
            // Opt-in only: warm if this heavy category was enabled via --forensic.
            want = heavy_cat && (mask_ & warm_bit(c.category)) != 0;
        } else {
            want = true;   // SystemInfo / None, system-wide → light, warm it
        }
    } else {
        // forensic: only expensive+small files in enabled categories.
        want = c.worth_warming() && (mask_ & warm_bit(c.category));
    }
    if (want) targets_.push_back(node);
}

void ForensicWarmer::worker() {
    for (;;) {
        std::size_t i = next_.fetch_add(1, std::memory_order_relaxed);
        if (i >= targets_.size()) break;   // out of work → fall through to report
        const auto& n = targets_[i];
        try {
            n->warm();                            // runs producer, fills cache
            const u64 sz = n->size_hint();        // cached size now it's warmed
            total_bytes_.fetch_add(sz, std::memory_order_relaxed);
            // A small-tagged file over the budget is a mis-tag (forensic only;
            // precompute deliberately warms Large files too, so don't warn there).
            if (!warm_all_ && sz > kWarnBytes) {
                oversized_.fetch_add(1, std::memory_order_relaxed);
                log::warn("forensic: '{}' tagged small but produced {} bytes "
                          "— consider retagging Large", n->name(), sz);
            }
        } catch (const std::exception& e) {
            log::debug("warm '{}' failed: {}", n->name(), e.what());
        }
        warmed_.fetch_add(1, std::memory_order_relaxed);
    }
    // The last worker out of the pool reports completion, so the user sees it
    // mid-mount instead of only at unmount (when join() runs).
    if (remaining_workers_.fetch_sub(1, std::memory_order_acq_rel) == 1)
        report_summary();
}

void ForensicWarmer::report_summary() {
    if (reported_.exchange(true)) return;   // log exactly once
    if (warmed_.load(std::memory_order_relaxed) == 0) return;
    // Elapsed since launch(): seconds for a quick precompute, m:ss once
    // --forensic=full's corpus scans push it into the minutes.
    const double secs = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start_).count();
    const std::string elapsed = detail::format_warm_duration(secs);
    log::note("{}: warming complete in {} — {} files cached (~{} MB resident){}",
              label_, elapsed,
              warmed_.load(std::memory_order_relaxed),
              total_bytes_.load(std::memory_order_relaxed) / (1024 * 1024),
              oversized_.load(std::memory_order_relaxed)
                  ? fmt::format(" ({} exceeded the small-memory budget)",
                                oversized_.load(std::memory_order_relaxed))
                  : std::string{});
}

void ForensicWarmer::start(const NodePtr& root, unsigned category_mask,
                           unsigned jobs) {
    if (started_) return;
    started_ = true;
    mask_ = category_mask;
    if (mask_ == 0) return;   // no categories selected → nothing to warm
    collect(root, /*heavy_subtree=*/false);
    launch("forensic", jobs);
}

void ForensicWarmer::start_precompute(const NodePtr& root, unsigned extra_mask,
                                      unsigned jobs, const char* label) {
    if (started_) return;
    started_ = true;
    warm_all_ = true;
    mask_ = extra_mask;   // opt-in per-process/yara when --forensic also given
    collect(root, /*heavy_subtree=*/false);
    launch(label, jobs);
}

void ForensicWarmer::launch(const char* label, unsigned jobs) {
    label_ = label;
    start_ = std::chrono::steady_clock::now();
    if (targets_.empty()) {
        log::info("{}: nothing to warm — browsing is already cheap", label);
        return;
    }
    // Warm cheapest-first so the small system/analysis files (e.g. /sys/*)
    // populate within moments, and heavy per-process producers (strings.txt,
    // yara.txt — Expensive+Large) trickle in last instead of starving them.
    auto rank = [](const NodePtr& n) {
        const auto& c = n->cost();
        int r = 0;
        if (c.compute == FileCost::Compute::Expensive) r += 1;
        if (c.mem == FileCost::Mem::Large)             r += 2;   // Large → last
        return r;
    };
    std::stable_sort(targets_.begin(), targets_.end(),
        [&](const NodePtr& a, const NodePtr& b) { return rank(a) < rank(b); });

    unsigned hw = std::thread::hardware_concurrency();
    unsigned n  = jobs ? jobs : std::min<unsigned>(hw ? hw : 2u, 4u);
    n = std::min<unsigned>(n, static_cast<unsigned>(targets_.size()));

    log::info("{}: pre-warming {} file(s) on {} background thread(s); "
              "mount stays responsive", label, targets_.size(), n);

    remaining_workers_.store(n, std::memory_order_relaxed);
    threads_.reserve(n);
    for (unsigned t = 0; t < n; ++t)
        threads_.emplace_back([this] { worker(); });
}

void ForensicWarmer::join() {
    for (auto& t : threads_)
        if (t.joinable()) t.join();
    threads_.clear();
    // The last worker normally reports completion mid-mount; this is a fallback
    // for an early unmount that joins before the pool drained (idempotent).
    if (started_) report_summary();
}

} // namespace lmpfs::vfs
