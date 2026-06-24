#pragma once
#include "formats/physical_layer.h"
#include "symbols/isf_symbols.h"
#include "symbols/kallsyms.h"
#include "arch/x86_64/paging.h"
#include "os/linux/kernel_resolver.h"
#include "os/linux/process.h"
#include "os/linux/netstat.h"
#include "vfs/vfs.h"
#include "vfs/forensic_warmer.h"
#include <filesystem>
#include <memory>
#include <mutex>

namespace lmpfs {

// Top-level façade. Owns every layer and exposes the assembled VFS root.
class Engine {
public:
    struct Options {
        std::filesystem::path dump_path;
        std::filesystem::path symbols_path;   // .json / .json.xz / dir / empty (auto)
        std::filesystem::path vmlinux_path;   // --vmlinux (generate ISF from this)
        std::filesystem::path symbol_cache_dir; // --symbol-cache (where to save fetched ISFs)
        bool                  auto_fetch_symbols = false;
        bool                  http_symbol_cache  = true;
        // Forensic mode: after the tree is built, pre-warm expensive-but-small
        // files in the background so browsing/opening them is instant.
        bool                  forensic           = false;
        // Bitmask of vfs::FileCost::Category (via vfs::warm_bit) selecting
        // which categories to warm. Resolved from --forensic[=mode] +
        // --forensic-include/exclude by the CLI. 0 → warm nothing.
        unsigned              forensic_mask      = 0;
        // --precompute: exhaustively warm EVERY materializable file in the
        // background (supersedes forensic_mask). Streaming files are skipped.
        bool                  precompute         = false;
    };

    static std::unique_ptr<Engine> create(const Options& opts);

    const std::vector<linux::Process>& processes() const { return processes_; }
    const linux::KernelContext&        kernel()    const { return kctx_; }
    const vfs::NodePtr&                vfs_root()  const { return root_; }
    // Kernel-space page-table walker (CR3-rooted). Only safe to use if
    // `kernel().dtb_validated` — otherwise reads may be garbage.
    const x86_64::PageTable&           kernel_pt() const { return *pt_; }
    const PhysicalLayer&               phys()      const { return *phys_; }
    const IsfSymbols&                  isf()       const { return *isf_; }

    // Cached kallsyms result (may be empty if extraction failed or wasn't
    // attempted). Used by /sys/kallsyms to produce the /proc/kallsyms-style
    // listing with full type chars (T/D/d/t/B/b/r/R/a/A, etc.). The ISF
    // symbols section is a thinned-down subset (build-artefact names like
    // __pfx_* are filtered out); this preserves the full unfiltered table.
    const linux::KallsymsResult&       kallsyms()  const { return kallsyms_; }

    // Lazy-built socket index. Used by fdtable to label socket fds with
    // their actual TCP/UDP endpoints instead of just `socket:[N]`. Building
    // it walks the TCP + UDP hash tables (~50 ms on the test dump), so we
    // only do it on first need. Thread-safe.
    const linux::SocketIndex& socket_index() const;

    // Refresh-state hook for the future (live targets); for snapshot dumps it's a no-op.
    void refresh();

private:
    Engine() = default;

    std::unique_ptr<PhysicalLayer>      phys_;
    std::unique_ptr<IsfSymbols>         isf_;
    std::unique_ptr<x86_64::PageTable>  pt_;
    linux::KernelContext                kctx_;
    std::vector<linux::Process>         processes_;
    linux::KallsymsResult               kallsyms_;
    vfs::NodePtr                        root_;

    // Lazy socket-index cache. mutable so the const accessor can populate.
    mutable std::once_flag              sockets_once_;
    mutable linux::SocketIndex          sockets_;

    // Forensic-mode background warmer. MUST be the last member: members are
    // destroyed in reverse declaration order, so this one is torn down first,
    // joining its worker threads before phys_/isf_/etc. (which the producers
    // capture by raw pointer) are destroyed.
    vfs::ForensicWarmer                 warmer_;
};

} // namespace lmpfs
