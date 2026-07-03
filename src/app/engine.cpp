#include "app/engine.h"
#include "io/memory_source.h"
#include "formats/format_factory.h"
#include "formats/phys_raw_stream.h"
#include "symbols/symbol_resolver.h"
#include "symbols/kallsyms.h"
#include "vfs/sys_module.h"
#include "os/linux/pagecache.h"
#include "os/linux/timeline.h"
#include "os/linux/kern_va_stream.h"
#include "os/linux/v2p_misc.h"
#include "os/linux/forensic_snapshot.h"
#include "os/linux/csv_export.h"
#include "os/linux/json_export.h"
#include "os/linux/findevil.h"
#include "os/linux/strings_search.h"
#include "os/linux/yara_search.h"
#include "core/log.h"
#include "core/app_paths.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <vector>

namespace lmpfs {

std::unique_ptr<Engine> Engine::create(const Options& opts) {
    auto eng = std::unique_ptr<Engine>(new Engine());

    // Register any --yara-rules paths before the VFS (and its lazy YARA
    // scanners) are built.
    linux::set_user_yara_paths(opts.yara_rules);

    log::note("Opening dump: {}", opts.dump_path.string());
    auto src   = open_best_memory_source(opts.dump_path);   // mmap if available
    eng->phys_ = open_physical_layer(std::move(src));

    // Resolve symbols. Either the user-provided file, an auto-discovered ISF
    // from a directory / cache that matches the dump's banner, or freshly
    // auto-fetched via tools/fetch_symbols.sh when --auto-fetch is on.
    SymbolResolveOptions sro{};
    sro.user_path    = opts.symbols_path;
    sro.vmlinux_path = opts.vmlinux_path;
    sro.cache_dir    = opts.symbol_cache_dir;
    sro.auto_fetch   = opts.auto_fetch_symbols;
    sro.http_cache   = opts.http_symbol_cache;
    auto sym = resolve_symbols(*eng->phys_, sro);
    log::note("Loading symbols: {} ({})", sym.isf_path.string(), sym.how);
    eng->isf_ = IsfSymbols::load(sym.isf_path);

    eng->kctx_ = linux::resolve_kernel(*eng->phys_, *eng->isf_);
    eng->pt_   = std::make_unique<x86_64::PageTable>(*eng->phys_, eng->kctx_.dtb);

    // Cache the unfiltered kallsyms table for /sys/kallsyms. We may have
    // already extracted it during the ISF-resolution chain, but doing it
    // again here is cheap (~1 s) and keeps the engine self-contained so
    // /sys/kallsyms works even with externally-supplied ISFs.
    eng->kallsyms_ = linux::extract_kallsyms(*eng->phys_);

    eng->processes_ = linux::list_processes(*eng->phys_, *eng->pt_, *eng->isf_, eng->kctx_);

    auto root = std::make_shared<vfs::DirNode>("");

    // /proc/<pid>-<comm>/... — per-process files
    auto proc = vfs::build_proc_tree(eng->processes_, *eng->phys_, *eng->pt_,
                                     *eng->isf_, eng->kctx_, *eng);
    root->add(proc);

    // /mem/phys.raw     — entire physical address space, streamed 1:1.
    // /mem/kern_va.raw  — 128 TiB sparse view of the canonical kernel half,
    //                     page-by-page-translated through the multi-strategy
    //                     kva_reader (direct-map / image-shift / PGD-walk).
    // (MemProcFS exposes analogous views under /pmem and /mem.kmem; we
    // group both under /mem so the layout reads top-down: physical first,
    // virtual second.)
    auto mem = std::make_shared<vfs::DirNode>("mem");
    auto phys_stream = std::make_shared<PhysRawStream>(*eng->phys_);
    mem->add(std::make_shared<vfs::StreamFileNode>("phys.raw", phys_stream));
    auto kva_stream = std::make_shared<linux::KernVaRawStream>(*eng);
    mem->add(std::make_shared<vfs::StreamFileNode>("kern_va.raw", kva_stream));
    {
        // Tiny readme so users know what these are when they open the folder.
        auto txt = fmt::format(
            "/mem/ — raw memory windows\n"
            "\n"
            "phys.raw    entire physical address space of the dump\n"
            "            Format: {}\n"
            "            Source: {}\n"
            "            Size:   {} bytes ({:.2f} GiB)\n"
            "            Holes / unmapped regions are zero-filled.\n"
            "            Open in HxD / FTK Imager / dd; safe concurrent reads.\n"
            "\n"
            "kern_va.raw 128 TiB sparse view of the canonical kernel half.\n"
            "            File-offset 0  →  VA 0xffff_8000_0000_0000\n"
            "            File-offset 2^47 (end)  →  VA 0xffff_ffff_ffff_ffff\n"
            "            Coverage:\n"
            "              * direct-map / physmap (linear; subtract direct_map_base)\n"
            "              * kernel image          (linear; apply kaslr_phys_shift)\n"
            "              * vmalloc / modules     (PGD-walked via init_mm.pgd)\n"
            "            Reads are 4-KiB-granular; pages that don't resolve\n"
            "            come back as zeros (sparse-file semantics).\n"
            "            DO NOT try to read it end-to-end — only the actually-\n"
            "            mapped pages are interesting. Use this for poking at\n"
            "            specific kernel symbols by VA, not bulk extraction.\n",
            eng->phys_->format_name(), eng->phys_->source_name(),
            eng->phys_->max_address(),
            eng->phys_->max_address() / double(1ull<<30));
        auto bytes = ByteBuf(txt.begin(), txt.end());
        mem->add(std::make_shared<vfs::LazyFileNode>("README.txt",
            [bytes]() { return bytes; }));
    }
    root->add(mem);

    // /misc/{virt2phys,phys2virt} — ad-hoc address translators. The query is
    // encoded in the path (e.g. /misc/virt2phys/0xffffffffa7fb3580) so we
    // don't need a writable file + per-handle state; every translation is a
    // pure read of a synthesised LazyFileNode. (MemProcFS uses the write+read
    // pattern; ours is friendlier to scripting and concurrent access.)
    {
        auto misc = std::make_shared<vfs::DirNode>("misc");
        misc->add(linux::build_virt2phys_dir(*eng));
        misc->add(linux::build_phys2virt_dir(*eng));
        {
            auto txt = ByteBuf{};
            const char* readme =
                "/misc/ — ad-hoc utilities\n"
                "\n"
                "virt2phys/<hex-va>[.txt]    kernel-VA → PA + strategy\n"
                "phys2virt/<hex-pa>[.txt]    PA       → direct-map / image aliases\n"
                "\n"
                "See virt2phys/README.txt or phys2virt/README.txt for examples.\n";
            txt.assign(readme, readme + std::strlen(readme));
            misc->add(std::make_shared<vfs::LazyFileNode>("README.txt",
                [txt]() { return txt; }));
        }
        root->add(misc);
    }

    // /sys/* — system-wide kernel views; will grow as the kernel page-table
    // walker unlocks more kernel-VA reads (kallsyms, modules, dmesg, …).
    root->add(vfs::build_sys_tree(*eng));

    // /fs/* — the kernel's view of the entire filesystem tree, reconstructed
    //         from every inode the kernel page cache currently has, with
    //         GLOBAL paths (mount-point-composed via mountinfo). The
    //         primary "browse the system's filesystem" UX.
    //
    // /files/* — **orphan-only** view: inodes the page cache holds but
    //            which have NO resolvable global path. The forensically-
    //            interesting cases are:
    //              * deleted-but-cached files (unlink()'d while still
    //                referenced — content recoverable, no path)
    //              * inodes from filesystems we couldn't tie to a mount
    //              * anonymous inodes whose dentry never had a name
    //            Files with valid global paths live under /fs/ instead.
    {
        auto fs_dir     = std::make_shared<vfs::DirNode>("fs");
        auto files_dir  = std::make_shared<vfs::DirNode>("files");
        auto by_ino_dir = std::make_shared<vfs::DirNode>("by-ino");
        auto inodes     = linux::enumerate_cached_inodes(*eng);

        // Overlayfs and bind mounts can expose several inodes at the same
        // global path. Regular files are collected and resolved per path below,
        // using exact recovery stats so /fs surfaces the inode with readable
        // bytes instead of the first duplicate encountered.
        // File-CONTENT recovery turns cached folios into bytes, which needs
        // `vmemmap_base` to map a struct-page address to a physical frame.
        // When the ISF has no such symbol (BTF/types-only mode) we derive it
        // symbol-free from the cached folio addresses (1 GiB-aligned; valid for
        // RAM < 64 GiB), so content still recovers. Note that once here.
        // Either way, individual reclaimed / non-resident pages read as zeros —
        // inherent to memory forensics, not a defect.
        if (!eng->isf_->find_symbol("vmemmap_base")) {
            log::debug("/fs: no `vmemmap_base` symbol (BTF/types-only mode) — "
                      "deriving it from cached folios for file-content recovery "
                      "(assumes RAM < 64 GiB). Resident pages recover; reclaimed "
                      "pages read as zeros. For the most complete symbols, "
                      "--auto-fetch or --vmlinux <path>.");
        }

        // README at the top of /files/ — explains the new scope so users
        // don't go hunting for /usr/bin/bash here (it's in /fs/).
        {
            std::string txt =
                "/files/ — page-cache content WITHOUT a resolvable global path.\n"
                "\n"
                "What lives here:\n"
                "  by-ino/<fs>-<ino>.bin   inodes whose path couldn't be\n"
                "                          composed back to /. The two most\n"
                "                          forensically-useful cases:\n"
                "    * Deleted-but-cached: a file unlink()'d while still\n"
                "      held open by a process. The dentry is gone, but the\n"
                "      page cache still has the content. (i_state & I_FREEING.)\n"
                "    * Anonymous / unresolvable: inodes whose dentry chain\n"
                "      can't be walked back to a global path (no mount\n"
                "      context, dentry never named, etc.).\n"
                "\n"
                "For everything WITH a path, see /fs/.\n"
                "For the full catalog of every cached inode (with paths,\n"
                "sizes, fs, etc.), see /sys/pagecache/index.txt.\n";
            auto bytes = ByteBuf(txt.begin(), txt.end());
            files_dir->add(std::make_shared<vfs::LazyFileNode>("README.txt",
                [bytes]() { return bytes; }));
        }

        // /files/index.txt — orphan-scoped catalog (one row per inode WE
        // expose under by-ino/). Distinct from /sys/pagecache/index.txt
        // (which is the full system-wide catalog).
        files_dir->add(std::make_shared<vfs::LazyFileNode>("index.txt",
            [engp = eng.get()]() -> ByteBuf {
                auto all = linux::enumerate_cached_inodes(*engp);
                std::string out;
                out.reserve(8 * 1024);
                out += "# /files/ — orphan-only catalog (inodes with no /fs/ path).\n"
                       "# fs           ino   state    cached  size           hint\n"
                       "#------------+-----+--------+-------+--------------+-----\n";
                std::size_t n = 0;
                for (const auto& ci : all) {
                    if ((ci.i_mode & 0170000) != 0100000) continue;
                    if (ci.nr_cached == 0) continue;
                    if (!linux::inode_is_orphan(ci)) continue;
                    const char* hint =
                        linux::inode_is_dying(ci) ? "deleted (I_FREEING)" : "anon/no-name";
                    out += fmt::format("{:<12} {:>6} {:#08x} {:>6} {:>14}  {}\n",
                                       ci.sb_fs, ci.i_ino, ci.i_state,
                                       ci.nr_cached, ci.i_size, hint);
                    ++n;
                }
                std::string header = fmt::format(
                    "# {} orphan inodes with cached content (regular files only).\n",
                    n);
                std::string combined = header + out;
                return ByteBuf(combined.begin(), combined.end());
            }));

        // /fs is evidence-facing: do not rewrite suspicious names into
        // plausible-looking underscores. Components must already be display
        // safe; untrusted paths stay in /sys/pagecache/path_quality.txt.
        auto sanitise_component = [](std::string s) -> std::string {
            if (!linux::validate_recovered_fs_path("/" + s).ok) return {};
            return s;
        };

        // Walk-or-create a directory chain under `root` for a /-separated
        // global path; returns the deepest dir. Returns `root` if any
        // component is unsalvageable (signals the caller to skip this entry).
        auto get_or_make_dir = [&](std::shared_ptr<vfs::DirNode> root,
                                   const std::string& path,
                                   bool& ok)
            -> std::shared_ptr<vfs::DirNode>
        {
            ok = true;
            std::shared_ptr<vfs::DirNode> cur = root;
            std::size_t i = 0;
            while (i < path.size()) {
                while (i < path.size() && path[i] == '/') ++i;
                std::size_t j = i;
                while (j < path.size() && path[j] != '/') ++j;
                if (i == j) break;
                std::string comp = sanitise_component(path.substr(i, j - i));
                if (comp.empty()) { ok = false; return root; }
                // Reuse-or-create the directory for this component. A file of
                // the same name (from an inconsistently-resolved sibling path)
                // is replaced by a directory so the whole subtree survives,
                // and names stay unique so WinFsp's paged enumeration can't
                // loop on a duplicate.
                cur = cur->ensure_dir_child(comp);
                i = j;
            }
            return cur;
        };
        auto expose_in_fs_tree = [](const linux::CachedInode& ci) {
            // Keep /fs focused on recovered filesystem content. Kernel pseudo
            // and runtime filesystems remain in the full pagecache index but
            // are not useful as recovered files.
            static const char* kPseudo[] = {
                "sysfs", "proc", "procfs", "cgroup", "cgroup2",
                "securityfs", "debugfs", "tracefs", "configfs",
                "bpf", "pstore", "efivarfs", "devtmpfs", "devpts",
                "tmpfs", "mqueue", "hugetlbfs", "autofs", "rpc_pipefs",
                "fusectl", "fuse", "selinuxfs", "nsfs", "binfmt_misc"
            };
            for (const char* fs : kPseudo)
                if (ci.sb_fs == fs) return false;
            return true;
        };
        auto normalise_fs_path = [](const linux::CachedInode& ci) {
            std::string path = ci.path;
            if (path == "/systemd" || path.rfind("/systemd/", 0) == 0)
                return std::string{};
            if (path == "/root") return std::string{};
            if (path.rfind("/root/", 0) != 0) return path;

            // Fedora live/pivot-root captures can compose non-root mounts
            // below /root even though analysts expect the recovered system
            // root directly under /fs. Only strip that synthetic prefix for
            // disk-backed system roots, leaving real /root user files alone.
            std::string rest = path.substr(6);
            std::size_t slash = rest.find('/');
            std::string first = slash == std::string::npos ? rest : rest.substr(0, slash);

            // These are runtime/pseudo mount points in the Fedora live-root
            // layout. Their mount metadata stays visible in pagecache/index
            // and mountinfo, but the browsable /fs tree should stay focused
            // on recovered disk-backed filesystem content.
            static const char* kRuntimeRoots[] = {
                "dev", "media", "mnt", "proc", "root", "run", "sys", "tmp"
            };
            for (const char* r : kRuntimeRoots) {
                if (first == r) return std::string{};
            }

            static const char* kSystemRoots[] = {
                "bin", "boot", "etc", "home", "lib", "lib64",
                "opt", "sbin", "srv", "usr", "var"
            };
            for (const char* r : kSystemRoots) {
                if (first == r) return "/" + rest;
            }
            return path;
        };
        auto unavailable_file_bytes = [](const linux::CachedInode& ci,
                                         const linux::RecoveredFileStats* st) -> ByteBuf {
            std::string body = fmt::format(
                "unavailable: inode metadata was recovered for this file, but no readable cached content bytes were recovered.\n"
                "path: {}\n"
                "filesystem: {}\n"
                "inode: {}\n"
                "logical_size: {} bytes\n"
                "cached_pages: {}\n"
                "copied_pages: {}\n"
                "dropped_pages: {}\n"
                "nonzero_bytes: {}\n"
                "\n"
                "The original file bytes are not present in the memory dump page cache. "
                "MemNixFS is not returning synthetic zero-filled bytes for this file because that would be misleading. "
                "See /sys/pagecache/index.txt and /sys/pagecache/recovery.txt for the recovered inode metadata.\n",
                ci.path.empty() ? "(unresolved)" : ci.path,
                ci.sb_fs.empty() ? "?" : ci.sb_fs,
                ci.i_ino,
                ci.i_size,
                ci.nr_cached,
                st ? st->pages_copied : 0,
                st ? st->pages_dropped : 0,
                st ? st->bytes_nonzero : 0);
            return ByteBuf(body.begin(), body.end());
        };
        auto recovered_file_bytes = [unavailable_file_bytes](Engine* engp,
                                                             const linux::CachedInode& ci) -> ByteBuf {
            if (ci.i_size > 0 && ci.nr_cached == 0)
                return unavailable_file_bytes(ci, nullptr);
            auto rf = linux::recover_file_with_stats(*engp, ci);
            if (ci.i_size > 0 && rf.stats.pages_copied == 0)
                return unavailable_file_bytes(ci, &rf.stats);
            return std::move(rf.bytes);
        };

        struct RegularCandidate {
            linux::CachedInode ci;
            std::string dirname;
            std::string basename;
        };
        struct RegularScore {
            u64 pages_copied = 0;
            u64 bytes_nonzero = 0;
            u64 bytes_copied = 0;
            u64 pages_dropped = 0;
            u64 nr_cached = 0;
            bool sane_size = false;
            bool non_pseudo = false;
        };
        auto score_regular = [&](const linux::CachedInode& ci) {
            RegularScore s;
            s.nr_cached = ci.nr_cached;
            s.sane_size = ci.i_size > 0 && ci.i_size <= (4ULL * 1024 * 1024 * 1024);
            s.non_pseudo = expose_in_fs_tree(ci);
            if (ci.i_size > 0 && ci.nr_cached > 0) {
                auto st = linux::recover_file_stats(*eng, ci, true);
                s.pages_copied = st.pages_copied;
                s.bytes_nonzero = st.bytes_nonzero;
                s.bytes_copied = st.bytes_copied;
                s.pages_dropped = st.pages_dropped;
            }
            return s;
        };
        auto better_regular = [&](const linux::CachedInode& a,
                                  const linux::CachedInode& b) {
            auto as = score_regular(a);
            auto bs = score_regular(b);
            if (as.pages_copied != bs.pages_copied) return as.pages_copied > bs.pages_copied;
            if (as.bytes_nonzero != bs.bytes_nonzero) return as.bytes_nonzero > bs.bytes_nonzero;
            if (as.bytes_copied != bs.bytes_copied) return as.bytes_copied > bs.bytes_copied;
            if (as.pages_dropped != bs.pages_dropped) return as.pages_dropped < bs.pages_dropped;
            if (as.sane_size != bs.sane_size) return as.sane_size;
            if (as.non_pseudo != bs.non_pseudo) return as.non_pseudo;
            return as.nr_cached > bs.nr_cached;
        };
        std::unordered_map<std::string, RegularCandidate> regular_candidates;

        std::size_t reg_count = 0, lnk_count = 0, dir_count = 0,
                    nopath = 0, pseudo_skipped = 0, untrusted_path = 0;
        for (auto& ci : inodes) {
            auto* engp = eng.get();
            const u16 type = ci.i_mode & 0170000;
            const bool is_reg = type == 0100000;
            const bool is_dir = type == 0040000;
            const bool is_lnk = type == 0120000;

            // /files/by-ino — ORPHANS only (regular files with cached pages
            // that have no resolvable global path). Files visible under
            // /fs/ entries are not duplicated here; the analyst can find them by path.
            if (is_reg && ci.nr_cached > 0 && linux::inode_is_orphan(ci)) {
                const char* kind = linux::inode_is_dying(ci) ? "deleted" : "orphan";
                by_ino_dir->add(std::make_shared<vfs::SizedLazyFileNode>(
                    fmt::format("{}-{}-{}.bin",
                        kind, ci.sb_fs.empty() ? "fs" : ci.sb_fs, ci.i_ino),
                    [engp, ci, recovered_file_bytes]() {
                        return recovered_file_bytes(engp, ci).size();
                    },
                    [engp, ci, recovered_file_bytes]() {
                        return recovered_file_bytes(engp, ci);
                    }));
            }

            // /fs — the navigable global tree. Skip anonymous inodes.
            if (ci.path.empty() || ci.path == "/" || ci.path == "(null)") {
                ++nopath;
                continue;
            }
            if (!expose_in_fs_tree(ci)) {
                ++pseudo_skipped;
                continue;
            }
            std::string fs_path = normalise_fs_path(ci);
            // Reject paths still in the legacy fs-local placeholder format.
            if (fs_path.empty() || fs_path[0] != '/') { ++nopath; continue; }
            auto trust = linux::validate_recovered_fs_path(fs_path);
            if (!trust.ok) { ++untrusted_path; continue; }

            // Split path into dir + basename.
            std::size_t slash = fs_path.find_last_of('/');
            std::string dirname = (slash == 0) ? ""  // top-level entry
                                  : fs_path.substr(0, slash);
            std::string basename = sanitise_component(fs_path.substr(slash + 1));
            if (basename.empty()) { ++nopath; continue; }
            bool dir_ok = true;
            auto parent_dir = dirname.empty()
                ? fs_dir
                : get_or_make_dir(fs_dir, dirname, dir_ok);
            if (!dir_ok) { ++nopath; continue; }

            if (is_dir) {
                // Ensure this directory exists in the tree (replacing a
                // same-named file if one slipped in). Unique by construction.
                parent_dir->ensure_dir_child(basename);
                ++dir_count;
            } else if (is_reg) {
                // Keep one candidate per normalized path; duplicates are
                // scored by recovered bytes before insertion into /fs.
                auto found = regular_candidates.find(fs_path);
                RegularCandidate cand{ci, dirname, basename};
                if (found == regular_candidates.end() ||
                    better_regular(ci, found->second.ci)) {
                    regular_candidates[fs_path] = std::move(cand);
                }
            } else if (is_lnk) {
                if (parent_dir->find(basename)) continue;
                auto target = linux::recover_symlink_target(*engp, ci);
                std::string body;
                if (target.ok) {
                    body = fmt::format("{}\n", target.target);
                } else {
                    body = fmt::format(
                        "unavailable: symlink target could not be recovered.\n"
                        "path: {}\n"
                        "filesystem: {}\n"
                        "inode: {}\n"
                        "reason: {}\n"
                        "See /sys/pagecache/index.txt for inode metadata.\n",
                        fs_path,
                        ci.sb_fs.empty() ? "?" : ci.sb_fs,
                        ci.i_ino,
                        target.reason.empty() ? "unknown" : target.reason);
                }
                auto bytes = ByteBuf(body.begin(), body.end());
                parent_dir->add(std::make_shared<vfs::LazyFileNode>(
                    basename, [bytes]() { return bytes; }));
                ++lnk_count;
            }
        }
        for (const auto& [fs_path, candidate] : regular_candidates) {
            bool dir_ok = true;
            auto parent_dir = candidate.dirname.empty()
                ? fs_dir
                : get_or_make_dir(fs_dir, candidate.dirname, dir_ok);
            if (!dir_ok) {
                ++nopath;
                continue;
            }
            if (parent_dir->find(candidate.basename)) continue;

            const auto ci = candidate.ci;
            auto* engp = eng.get();
            if (ci.i_size > 0 && ci.nr_cached == 0) {
                parent_dir->add(std::make_shared<vfs::SizedLazyFileNode>(
                    candidate.basename,
                    [ci, unavailable_file_bytes]() {
                        return unavailable_file_bytes(ci, nullptr).size();
                    },
                    [ci, unavailable_file_bytes]() {
                        return unavailable_file_bytes(ci, nullptr);
                    }));
            } else {
                parent_dir->add(std::make_shared<vfs::SizedLazyFileNode>(
                    candidate.basename,
                    [engp, ci, recovered_file_bytes]() {
                        return recovered_file_bytes(engp, ci).size();
                    },
                    [engp, ci, recovered_file_bytes]() {
                        return recovered_file_bytes(engp, ci);
                    }));
            }
            ++reg_count;
        }

        log::note("/fs: {} dirs, {} regular files, {} symlinks ({} inodes "
                  "skipped — no resolvable path, {} pseudo-fs skipped)",
                  dir_count, reg_count, lnk_count, nopath, pseudo_skipped);

        log::debug("/fs: {} untrusted recovered path(s) skipped; see "
                  "/sys/pagecache/path_quality.txt", untrusted_path);

        files_dir->add(by_ino_dir);
        root->add(files_dir);
        root->add(fs_dir);
    }

    // /forensic/ — aggregated forensic artefacts. MemProcFS m_fc_* concept.
    //   timeline.{txt,csv}     v0.17 — chronological merge of dmesg /
    //                           bash_history / eBPF load times
    //   snapshot.{txt,json}    v0.20 — one-stop env + threat-hunt summary
    //                           (the file to read first when triaging a dump)
    {
        auto forensic = std::make_shared<vfs::DirNode>("forensic");
        forensic->add(std::make_shared<vfs::LazyFileNode>("timeline.txt",
            [engp = eng.get()]() { return linux::format_timeline_txt(*engp); }));
        forensic->add(std::make_shared<vfs::LazyFileNode>("timeline_summary.txt",
            [engp = eng.get()]() { return linux::format_timeline_summary_txt(*engp); }));
        forensic->add(std::make_shared<vfs::LazyFileNode>("timeline.csv",
            [engp = eng.get()]() { return linux::format_timeline_csv(*engp); }));
        {
            auto timeline = std::make_shared<vfs::DirNode>("timeline");
            for (const char* domain : {"all", "process", "network", "shell", "kernel", "findevil"}) {
                std::string d = domain;
                timeline->add(std::make_shared<vfs::LazyFileNode>(d + ".txt",
                    [engp = eng.get(), d]() { return linux::format_timeline_domain_txt(*engp, d); }));
                timeline->add(std::make_shared<vfs::LazyFileNode>(d + ".csv",
                    [engp = eng.get(), d]() { return linux::format_timeline_domain_csv(*engp, d); }));
            }
            forensic->add(timeline);
        }
        forensic->add(std::make_shared<vfs::LazyFileNode>("snapshot.txt",
            [engp = eng.get()]() { return linux::format_forensic_snapshot_txt(*engp); }));
        forensic->add(std::make_shared<vfs::LazyFileNode>("snapshot.json",
            [engp = eng.get()]() { return linux::format_forensic_snapshot_json(*engp); }));
        root->add(forensic);
    }

    // /csv/ — every machine-readable CSV under one flat directory, so an
    // ingester (Splunk, pandas, a SIEM file-input) can watch a single folder
    // instead of walking /sys, /forensic and /search for the pieces. The same
    // data is also exposed co-located; these nodes are lazy, so the folder
    // costs nothing until a file is read.
    {
        auto csv = std::make_shared<vfs::DirNode>("csv");
        auto add_csv = [&](const std::string& name, ByteBuf (*fn)(const Engine&),
                           vfs::FileCost cost = {}) {
            csv->add(std::make_shared<vfs::LazyFileNode>(name,
                [engp = eng.get(), fn]() { return fn(*engp); }, cost));
        };
        // Heavy producers (findevil scan, timeline build) carry the threat-hunt
        // cost so --precompute stays light — it skips them, matching the
        // co-located /sys/findevil and /forensic copies. --forensic with
        // threat-hunt enabled (smart/full) still warms them.
        const vfs::FileCost heavy{vfs::FileCost::Compute::Expensive,
                                  vfs::FileCost::Mem::Small,
                                  vfs::FileCost::Category::ThreatHunt};
        add_csv("pslist.csv",              linux::format_pslist_csv);
        add_csv("net_tcp.csv",             linux::format_tcp_csv);
        add_csv("net_udp.csv",             linux::format_udp_csv);
        add_csv("findevil.csv",            linux::format_findevil_csv,            heavy);
        add_csv("findevil_indicators.csv", linux::format_findevil_indicators_csv, heavy);
        add_csv("malfind.csv",             linux::format_malfind_csv,             heavy);
        add_csv("timeline.csv",            linux::format_timeline_csv,            heavy);
        add_csv("yara.csv",                linux::format_yara_csv,                heavy);
        add_csv("iocs.csv",                linux::format_iocs_csv,                heavy);
        for (const char* domain : {"process", "network", "shell", "kernel", "findevil"}) {
            std::string d = domain;
            csv->add(std::make_shared<vfs::LazyFileNode>("timeline_" + d + ".csv",
                [engp = eng.get(), d]() { return linux::format_timeline_domain_csv(*engp, d); },
                heavy));
        }
        {
            const char* readme =
                "/csv/ — all machine-readable CSV exports in one flat folder\n"
                "\n"
                "A convenience aggregate for integrations (Splunk, pandas, SIEM file\n"
                "inputs): every CSV MemNixFS produces, under stable names, so you can\n"
                "ingest a single directory instead of walking the tree. The same data\n"
                "is also exposed co-located (e.g. /sys/net/tcp.csv,\n"
                "/sys/processes/pslist.csv, /forensic/timeline.csv). Generated on read.\n"
                "\n"
                "  pslist.csv                 processes\n"
                "  net_tcp.csv / net_udp.csv  sockets\n"
                "  findevil.csv               threat-hunt findings\n"
                "  findevil_indicators.csv    per-indicator rows\n"
                "  malfind.csv                injected / anomalous memory regions\n"
                "  yara.csv                   YARA rule hits across process memory\n"
                "  iocs.csv                   extracted IOCs (URL/IPv4/email/JWT/AWS)\n"
                "  timeline.csv               merged forensic timeline\n"
                "  timeline_<domain>.csv      per-domain timeline splits\n";
            auto bytes = ByteBuf(readme, readme + std::strlen(readme));
            csv->add(std::make_shared<vfs::LazyFileNode>("README.txt",
                [bytes]() { return bytes; }));
        }
        root->add(csv);
    }

    // /json/ — the same aggregate as /csv, but JSON, for tools that prefer it.
    {
        auto json = std::make_shared<vfs::DirNode>("json");
        auto add_json = [&](const std::string& name, ByteBuf (*fn)(const Engine&),
                            vfs::FileCost cost = {}) {
            json->add(std::make_shared<vfs::LazyFileNode>(name,
                [engp = eng.get(), fn]() { return fn(*engp); }, cost));
        };
        const vfs::FileCost heavy{vfs::FileCost::Compute::Expensive,
                                  vfs::FileCost::Mem::Small,
                                  vfs::FileCost::Category::ThreatHunt};
        add_json("pslist.json",              linux::format_pslist_json);
        add_json("net_tcp.json",             linux::format_tcp_json);
        add_json("net_udp.json",             linux::format_udp_json);
        add_json("findevil.json",            linux::format_findevil_json,            heavy);
        add_json("findevil_indicators.json", linux::format_findevil_indicators_json, heavy);
        add_json("malfind.json",             linux::format_malfind_json,             heavy);
        add_json("yara.json",                linux::format_yara_json,                heavy);
        add_json("iocs.json",                linux::format_iocs_json,                heavy);
        {
            const char* readme =
                "/json/ — all machine-readable JSON exports in one flat folder\n"
                "\n"
                "The JSON counterpart of /csv, for tools that prefer JSON. Same data\n"
                "as the co-located files; generated on read.\n"
                "\n"
                "  pslist.json                  processes\n"
                "  net_tcp.json / net_udp.json  sockets\n"
                "  findevil.json                threat-hunt findings\n"
                "  findevil_indicators.json     per-indicator rows\n"
                "  malfind.json                 injected / anomalous memory regions\n"
                "  yara.json / iocs.json        YARA hits + extracted IOCs\n"
                "\n"
                "(timeline is CSV/text only for now -- see /forensic and /csv.)\n";
            auto bytes = ByteBuf(readme, readme + std::strlen(readme));
            json->add(std::make_shared<vfs::LazyFileNode>("README.txt",
                [bytes]() { return bytes; }));
        }
        root->add(json);
    }

    // /search/ — corpus-wide scanners. Each file is lazy-loaded; first
    // access triggers a full pass over every process's user memory, so
    // these can take 10s+ on a typical desktop dump.    v0.21 (Tier 4)
    {
        auto search = std::make_shared<vfs::DirNode>("search");
        search->add(std::make_shared<vfs::LazyFileNode>("iocs.txt",
            [engp = eng.get()]() { return linux::format_global_iocs(*engp); }));
        search->add(std::make_shared<vfs::LazyFileNode>("iocs.csv",
            [engp = eng.get()]() { return linux::format_iocs_csv(*engp); }));
        search->add(std::make_shared<vfs::LazyFileNode>("iocs.json",
            [engp = eng.get()]() { return linux::format_iocs_json(*engp); }));
        // v0.22 — YARA scan over every user task's readable VMAs
        search->add(std::make_shared<vfs::LazyFileNode>("yara.txt",
            [engp = eng.get()]() { return linux::format_yara_global(*engp); }));
        search->add(std::make_shared<vfs::LazyFileNode>("yara.csv",
            [engp = eng.get()]() { return linux::format_yara_csv(*engp); }));
        search->add(std::make_shared<vfs::LazyFileNode>("yara.json",
            [engp = eng.get()]() { return linux::format_yara_json(*engp); }));
        // v0.25 — per-rule subdir: /search/yara/<rule>.txt. One file per
        // compiled rule, containing ONLY that rule's matches. Lets analysts
        // grep / pipe per-rule without re-reading the merged yara.txt.
        {
            auto yara_dir = std::make_shared<vfs::DirNode>("yara");
            auto rule_names = linux::list_yara_rule_names(*eng);
            for (const auto& rule : rule_names) {
                std::string fname = rule + ".txt";
                yara_dir->add(std::make_shared<vfs::LazyFileNode>(fname,
                    [engp = eng.get(), rule]() {
                        return linux::format_yara_per_rule(*engp, rule);
                    }));
            }
            if (!rule_names.empty()) {
                search->add(yara_dir);
            }
        }
        {
            std::string readme = fmt::format(
                "/search/ — corpus-wide scanners\n"
                "\n"
                "iocs.txt   URLs, IPv4 addresses, emails, JWT tokens,\n"
                "           AWS access-key IDs extracted from every user\n"
                "           process's readable VMAs. Each section reports\n"
                "           up to 500 hits with PID + comm attribution.\n"
                "\n"
                "yara.txt   YARA rule scan across every user task's\n"
                "           readable VMAs. Built-in ruleset covers EICAR,\n"
                "           Mimikatz, Cobalt Strike, Meterpreter, common\n"
                "           shellcode markers, UPX, reverse-shell strings\n"
                "           + crypto-wallet keywords. Add your own with\n"
                "           --yara-rules <path>, $LMPFS_YARA_RULES, or the\n"
                "           per-user drop-in dir:\n"
                "             {}\n"
                "\n"
                "Per-process scopes: /proc/<pid>/strings.txt and\n"
                "                    /proc/<pid>/yara.txt.\n",
                paths::user_dir_hint("yara"));
            auto txt = ByteBuf(readme.begin(), readme.end());
            search->add(std::make_shared<vfs::LazyFileNode>("README.txt",
                [txt]() { return txt; }));
        }
        root->add(search);
    }

    eng->root_ = root;

    // Forensic / precompute mode: kick off background pre-warming now that the
    // tree exists. Non-blocking — Engine::create returns immediately and warming
    // proceeds on worker threads. The warmer is the last-declared Engine member,
    // so its destructor joins those threads before any captured engine state is
    // torn down. --precompute warms EVERY materializable file and supersedes
    // --forensic (which warms only the expensive+small subset by category).
    if (opts.precompute)
        // System-wide analysis files always; per-process/yara only if the user
        // also passed --forensic (those bits arrive in forensic_mask). When
        // forensic is what enabled precompute, it's --forensic=full — label the
        // background warming accordingly so the log matches the flag the user gave.
        eng->warmer_.start_precompute(eng->root_, opts.forensic_mask, opts.warm_jobs,
                                      opts.forensic ? "forensic=full" : "precompute");
    else if (opts.forensic)
        eng->warmer_.start(eng->root_, opts.forensic_mask, opts.warm_jobs);

    // Plugin scan (v0.25) is NOT done here — it lives in src/api/lmpfs.cpp
    // (`lmpfs_internal_scan_plugins`). Callers wanting plugins call it
    // explicitly after Engine::create. Both `lmpfs_open` (the DLL path)
    // and the CLI's main.cpp do so. Keeping the call out of Engine
    // avoids a circular dependency: memnixfs_core would otherwise need
    // a symbol that lives in memnixfs_dll.

    return eng;
}

void Engine::refresh() {
    processes_ = linux::list_processes(*phys_, *pt_, *isf_, kctx_);
}

const linux::SocketIndex& Engine::socket_index() const {
    std::call_once(sockets_once_, [this] {
        sockets_ = linux::build_socket_index(*this);
    });
    return sockets_;
}

const std::vector<linux::TimelineEvent>& Engine::timeline() const {
    std::call_once(timeline_once_, [this] {
        timeline_ = linux::build_timeline(*this);
    });
    return timeline_;
}

const std::vector<linux::IocHit>& Engine::global_iocs() const {
    std::call_once(iocs_once_, [this] {
        global_iocs_ = linux::collect_global_iocs(*this);
    });
    return global_iocs_;
}

const std::vector<linux::YaraHit>& Engine::global_yara() const {
    std::call_once(yara_once_, [this] {
        global_yara_ = linux::collect_global_yara_hits(*this);
    });
    return global_yara_;
}

} // namespace lmpfs
