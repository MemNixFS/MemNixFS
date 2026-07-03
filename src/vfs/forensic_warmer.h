// forensic_warmer.h — background pre-warming of expensive-but-small VFS files.
//
// Forensic mode trades a bit of background CPU for instant browsing. After the
// VFS tree is built, the warmer walks it, finds every file node whose
// FileCost says `worth_warming()` (expensive to compute, small in memory), and
// runs each producer on a small thread pool so the node's cache is populated
// before the user opens it. Mount is NOT blocked — warming runs in the
// background, and a file opened before it's warmed simply computes on demand
// (same per-node cache, so no double work).
//
// Thread-safety: producers read the engine's shared state, which is already
// concurrency-safe — kva_reader uses atomics, the socket index uses
// std::call_once, kallsyms is built at open (read-only thereafter), and YARA
// 4.x scans the shared YR_RULES with an internally-created per-call scanner.
// Each LazyFileNode guards its own load with a mutex, so a node being warmed
// while simultaneously opened by a WinFsp dispatcher is safe.
#pragma once
#include "vfs/vfs.h"
#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

namespace lmpfs::vfs {

namespace detail {
// Format an elapsed warm time for the "warming complete in ..." line: one
// decimal of seconds under a minute ("12.3s"), "Nm SSs" beyond (so a long
// --forensic=full run reads as "4m 07s" rather than "247.6s"). Exposed here so
// both branches can be unit-tested without a live mount.
std::string format_warm_duration(double seconds);
}  // namespace detail

class ForensicWarmer {
public:
    ~ForensicWarmer();

    // Collect warm-worthy nodes under `root` whose category is enabled in
    // `category_mask` (bits from warm_bit()), and start background warming.
    // `jobs == 0` → auto (min(hardware_concurrency, 4)). Call once.
    void start(const NodePtr& root, unsigned category_mask, unsigned jobs = 0);

    // `--precompute`: warm every system-wide analysis file under `root` so the
    // whole tree shows real sizes and opens instantly — all warmable() files
    // that are Mem::Small, across the SystemInfo/ThreatHunt/None categories.
    // The heavy per-process and YARA categories are warmed ONLY if their bit is
    // set in `extra_mask` (i.e. the user also passed --forensic), and Mem::Large
    // files (per-process strings.txt) always stay on-demand — eagerly
    // extracting all of them is GB-scale. Background, like start(). Call once.
    void start_precompute(const NodePtr& root, unsigned extra_mask = 0,
                          unsigned jobs = 0, const char* label = "precompute");

    // Block until warming finishes. Also called by the destructor, so the
    // owning Engine must outlive the warmer (declare it last in Engine).
    void join();

private:
    // `heavy_subtree` is true once we descend into /proc, /files or /fs — the
    // per-process and recovered-file trees that pure --precompute skips.
    void collect(const NodePtr& node, bool heavy_subtree);
    void launch(const char* label, unsigned jobs);
    void worker();
    void report_summary();   // logs the one-line completion summary, once

    unsigned mask_ = 0;
    bool     warm_all_ = false;   // precompute: warm every warmable() node
    std::string label_ = "warming";
    std::chrono::steady_clock::time_point start_;   // set when warming launches

    std::vector<NodePtr>     targets_;
    std::atomic<std::size_t> next_{0};
    std::atomic<std::size_t> warmed_{0};
    std::atomic<std::size_t> oversized_{0};
    std::atomic<u64>         total_bytes_{0};
    std::atomic<unsigned>    remaining_workers_{0};
    std::atomic<bool>        reported_{false};
    std::vector<std::thread> threads_;
    bool                     started_ = false;
};

} // namespace lmpfs::vfs
