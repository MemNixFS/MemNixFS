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
#include "os/linux/strings_search.h"
#include "os/linux/yara_search.h"
#include "core/log.h"
#include <fmt/format.h>
#include <cstring>

namespace lmpfs {

std::unique_ptr<Engine> Engine::create(const Options& opts) {
    auto eng = std::unique_ptr<Engine>(new Engine());

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
        auto unavailable_file_bytes = [](const linux::CachedInode& ci) -> ByteBuf {
            std::string body = fmt::format(
                "unavailable: inode metadata was recovered for this file, but no cached content pages were recovered.\n"
                "path: {}\n"
                "filesystem: {}\n"
                "inode: {}\n"
                "logical_size: {} bytes\n"
                "cached_pages: {}\n"
                "\n"
                "The original file bytes are not present in the memory dump page cache. "
                "MemNixFS is not returning synthetic zero-filled bytes for this file because that would be misleading. "
                "See /sys/pagecache/index.txt and /sys/pagecache/recovery.txt for the recovered inode metadata.\n",
                ci.path.empty() ? "(unresolved)" : ci.path,
                ci.sb_fs.empty() ? "?" : ci.sb_fs,
                ci.i_ino,
                ci.i_size,
                ci.nr_cached);
            return ByteBuf(body.begin(), body.end());
        };

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
                    [engp, ci]() { return linux::recover_file_size(*engp, ci); },
                    [engp, ci]() { return linux::recover_file(*engp, ci); }));
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
                // Don't add duplicates — if another inode resolved to the
                // same path (bind mount), keep the first.
                if (parent_dir->find(basename)) continue;
                if (ci.i_size > 0 && ci.nr_cached == 0) {
                    parent_dir->add(std::make_shared<vfs::SizedLazyFileNode>(
                        basename,
                        [ci, unavailable_file_bytes]() {
                            return unavailable_file_bytes(ci).size();
                        },
                        [ci, unavailable_file_bytes]() {
                            return unavailable_file_bytes(ci);
                        }));
                } else {
                    parent_dir->add(std::make_shared<vfs::SizedLazyFileNode>(
                        basename,
                        [engp, ci]() { return linux::recover_file_size(*engp, ci); },
                        [engp, ci]() { return linux::recover_file(*engp, ci); }));
                }
                ++reg_count;
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

    // /search/ — corpus-wide scanners. Each file is lazy-loaded; first
    // access triggers a full pass over every process's user memory, so
    // these can take 10s+ on a typical desktop dump.    v0.21 (Tier 4)
    {
        auto search = std::make_shared<vfs::DirNode>("search");
        search->add(std::make_shared<vfs::LazyFileNode>("iocs.txt",
            [engp = eng.get()]() { return linux::format_global_iocs(*engp); }));
        // v0.22 — YARA scan over every user task's readable VMAs
        search->add(std::make_shared<vfs::LazyFileNode>("yara.txt",
            [engp = eng.get()]() { return linux::format_yara_global(*engp); }));
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
            const char* readme =
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
                "           + crypto-wallet keywords. Drop additional\n"
                "           rules in $LMPFS_YARA_RULES or in\n"
                "           %LOCALAPPDATA%\\MemNixFS\\yara\\*.yar.\n"
                "\n"
                "Per-process scopes: /proc/<pid>/strings.txt and\n"
                "                    /proc/<pid>/yara.txt.\n";
            auto txt = ByteBuf(readme, readme + std::strlen(readme));
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
        eng->warmer_.start_precompute(eng->root_, opts.forensic_mask, 0,
                                      opts.forensic ? "forensic=full" : "precompute");
    else if (opts.forensic)
        eng->warmer_.start(eng->root_, opts.forensic_mask);

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

} // namespace lmpfs
