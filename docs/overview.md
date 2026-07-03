# Overview

## What is MemNixFS?

MemNixFS is a Windows-native tool that opens a Linux memory dump
(`.lime`, `.lime.compressed`, `.avml`, raw, or any contiguous physical
RAM image) and exposes everything inside it — processes, VMAs, kernel
symbols, the kernel banner, all of physical memory — as a virtual
filesystem you can `cd` into, `cat`, `grep`, or open in Explorer.

Concretely:

```powershell
memnixfs.exe --dump suspicious.lime.compressed mount M:
```

…makes `M:\` show up in Windows like any other drive, populated with:

```
M:\fs\                    ← THE RECONSTRUCTED ROOT FILESYSTEM. Browse it
                            exactly like the running Linux machine's `/`.
        bin   boot  dev   etc   home  lib    lib64  media  mnt
        opt   proc  root  run   sbin  snap   srv    sys    tmp
        usr   var   swap.img    (every standard Linux dir + actual swap file)

        home\ubuntu\Downloads\avml                  ← user's binaries
        home\ubuntu\Downloads\output.lime.compressed   ← the dump itself!
        run\systemd\resolve\stub-resolv.conf
        snap\core22\2045\usr\bin\bash
        snap\firefox\7423\usr\lib\firefox\firefox
        usr\lib\os-release
        ...
        (5k+ dirs, 14k+ regular files, 2.9k symlinks on a real Ubuntu dump)

M:\proc\1-systemd\        ← per-process analysis (NOT Linux's /proc — that
        maps                lives at M:\fs\proc\)
        cmdline
        environ
        status, stat, statm, limits, capabilities, …
        fd_table.txt      ← open fds w/ mount-resolved paths (/dev/null, …)
        shell_history.txt ← bash/zsh/fish/POSIX history candidates
        kstack.txt        ← kernel call-stack symbolised via kallsyms
        threads.txt       ← every thread of this thread-group leader
        malfind.txt       ← suspicious VMAs (RWX anon, exec stack)
        entropy.txt       ← Shannon entropy of EXEC VMAs (v0.14)
        proc.dmp          ← ELF64 core of just this process's memory
M:\sys\              ← kernel diagnostics (NOT Linux's /sys — that lives
                            at M:\fs\sys\)
        banner.txt        ← Linux version line, read via the kernel PGD
        dtb.txt           ← DTB diagnostics + KASLR shifts + init_task PA/VA
        kallsyms          ← /proc/kallsyms-compatible — 150k+ symbols
        btf.txt           ← BTF blob diagnostics
        dmesg             ← printk ringbuffer parsed (1.7k lines)
        modules\<name>\info.txt
        pagecache\index.txt     ← every cached inode catalog
        pagecache\recovery.txt  ← fast recovered-file gap-confidence catalog
        mem_ranges.txt          ← captured physical ranges for sparse-gap review
        mountinfo         ← every mount in the init namespace, /proc/mountinfo style
        mounts            ← /proc/mounts shape variant (v0.27)
        hostname          ← init_uts_ns.name.nodename (v0.27)
        uptime            ← jiffies_64 / HZ (v0.27)
        users.txt         ← UID → name table from /etc/passwd (v0.27)
        cpuinfo           ← boot_cpu_data (v0.28)
        meminfo           ← totalram_pages × 4 KiB (v0.28)
        iomem             ← iomem_resource tree (v0.28)
        boottime          ← uptime + derivation recipe (v0.28)
        dns.txt           ← resolver config via page-cache reads (v0.28)
        pidhashtable      ← init_pid_ns anchor + deferral note (v0.28)
        shell_history.txt ← aggregate shell history from bash/zsh/fish/POSIX sources
        crash\            ← crash/failure evidence with checked/partial/unavailable states
        journal\          ← cached syslog/journald/filesystem-journal candidates
        net\
            tcp           ← every TCP socket (listeners + ESTABLISHED endpoints)
            tcp.csv       ← same, RFC 4180 CSV (v0.15)
            udp           ← every UDP socket (DNS, DHCP, etc.)
            udp.csv       ← same, RFC 4180 CSV (v0.15)
            interfaces    ← `ip addr` style: lo + ens33 + IPv4 + IPv6 (v0.28)
            listening     ← TCP LISTEN + UDP-bound + sock_va (v0.27)
            arp           ← full neigh_hash_table walk — IP/MAC/state/iface (v0.29)
            unix          ← 805 UNIX sockets aggregated from fd_tables (v0.29)
            routes        ← fib_table anchor + path documentation (v0.29)
            netfilter     ← netfilter capability probe + path doc (v0.29)
            summary.txt   ← cross-protocol single-glance listing
        findevil\
            findevil.txt  ← aggregated MemProcFS-style threat-hunt verdict
            malfind.txt   ← anonymous executable VMAs (★ HIGH-SEVERITY for RWX)
            psscan.txt    ← phys-mem task_struct scan, cross-view vs visible list
            hidden_modules.txt  ← kallsyms diff vs `modules` list walk
            check_syscall.txt   ← sys_call_table integrity (#1 rootkit hook)
            tty_check.txt       ← tty_operations vtable audit (keylogger)
            keyboard_notifiers.txt  ← keyboard-notifier chain audit (keylogger)
            check_idt.txt       ← Interrupt Descriptor Table integrity (v0.13)
            check_afinfo.txt    ← /proc/net seq_ops vtable audit (v0.13)
            check_creds.txt     ← root-cred sharing audit (v0.13)
            check_modules.txt   ← modules-list × mod_tree cross-view (v0.13)
            ebpf.txt            ← every loaded eBPF program (v0.14)
            entropy.txt         ← high-entropy executable VMAs (v0.14)
            modxview.txt        ← three-source modules cross-view (v0.15)
            malfind.csv         ← RFC 4180 SIEM-ingest sibling (v0.15)
            findevil.csv        ← single-row verdict CSV (v0.15)
            kprobes.txt         ← every kernel kprobe + handler audit (v0.16)
            tracepoints.txt     ← active tracepoints + handler audit (v0.26)
            av_edr.txt          ← AV / EDR signature scan (v0.20)
            malfind.json        ← JSON sibling (v0.20)
            findevil.json       ← single-row aggregated JSON (v0.20)
M:\forensic\
        timeline.txt            ← merged events: dmesg + crash evidence + bash + eBPF
        timeline.csv            ← same, RFC 4180 CSV
        snapshot.txt            ← one-stop dump-triage report (v0.20)
        snapshot.json           ← same data, machine-readable
M:\search\                      ← corpus-wide scans (v0.21+)
        iocs.txt                ← URLs / IPv4 / emails / JWT / AWS keys
        iocs.csv  iocs.json     ← machine-readable IOC exports (v0.37)
        yara.txt                ← libyara scan w/ built-in + user rules (v0.22)
        yara.csv  yara.json     ← machine-readable YARA-hit exports (v0.37)
        yara\                   ← per-rule outputs (v0.26)
            <rule>.txt
        README.txt
M:\csv\                         ← every CSV export in one flat folder (v0.37)
        pslist.csv  net_tcp.csv  net_udp.csv  findevil.csv  malfind.csv
        timeline.csv  timeline_<domain>.csv  yara.csv  iocs.csv  README.txt
M:\json\                        ← same aggregate as \csv, but JSON (v0.37)
        pslist.json  net_tcp.json  findevil.json  malfind.json
        yara.json  iocs.json  README.txt
M:\plugins\                     ← third-party DLL drop-ins (v0.25)
        <plugin>\               ← one subdir per loaded plugin
        README.txt
        processes\
            pslist.txt    ← flat `ps -ef` view of every process + cmdline
            pslist.csv    ← same data, RFC 4180 CSV (v0.15)
            pslist.json   ← same data, JSON (v0.20)
            pstree.txt    ← hierarchical tree by ppid (ASCII box characters)
            psaux.txt     ← `ps aux` style with VSZ + cmdline + uid
            threads.txt   ← every thread across every process (890 on test dump)
M:\files\                 ← ORPHAN view (deleted-but-cached / unresolvable
        README.txt          paths). Files with paths live under M:\fs\ instead.
        index.txt
        by-ino\
            deleted-<fs>-<ino>.bin    ← unlink()'d but still in cache
            orphan-<fs>-<ino>.bin     ← no dentry / no mount context
M:\mem\
        phys.raw          ← entire physical address space, streamed 1:1
        kern_va.raw       ← 128 TiB sparse view of the canonical kernel
                            half (direct-map + kernel image + vmalloc),
                            page-by-page-translated through kva_reader
        README.txt
M:\misc\
        virt2phys\        ← path-encoded VA→PA translator
            <hex-va>      ← cat any name parsing as hex → translation report
            README.txt
        phys2virt\        ← PA→VA reverse map (direct-map + image aliases)
            <hex-pa>
            README.txt
        README.txt
```

## Who is this for?

- **DFIR analysts** doing post-incident Linux memory forensics on a
  Windows workstation. No need to spin up a Linux VM just to read a dump.
- **Reverse engineers** investigating compromised hosts, looking for
  rootkits, hooked syscalls, or persistence in kernel data structures.
- **Security researchers** validating Volatility 3 results against an
  independent implementation.
- **Tool builders** who need a programmatic VFS over a dump (the C++
  engine is layered so each subsystem is a small interface — you can
  build CLI tools, a Python binding, or a GUI on top).

## Why does it exist?

[MemProcFS](https://github.com/ufrisk/MemProcFS) is the gold standard for
Windows memory forensics. Its big idea — *expose the analysis as a
filesystem* — is brilliant: it means every tool you already have (HxD,
FTK, `strings`, `grep`, `cat`, your editor, your scripts) is now a
memory-forensics tool. But MemProcFS is Windows-only; Linux dumps are
analysed with [Volatility 3](https://github.com/volatilityfoundation/volatility3),
which is great but has a different workflow (Python plugins, no
filesystem view).

MemNixFS is the Linux equivalent of MemProcFS, running on Windows.
**Same UX, Linux-correct algorithms.**

## Key value propositions

### 1. Truly offline

You can run MemNixFS against a Linux dump **with no internet, no
distro repos, no vmlinux file, no externally-supplied ISF, no toolchain**
— and still get a fully-functional VFS with:

- 100,000+ kernel symbol addresses (from kallsyms)
- 10,000+ kernel struct definitions with byte-exact field offsets (from BTF)
- All running processes
- Per-process memory, command line, environment, mapped files
- Kernel banner, DTB, kallsyms listing

The synthesis happens from the dump's own bytes — modern Linux kernels
ship `.BTF` (type info) and `kallsyms` (symbols + addresses) directly
inside the image, and MemNixFS extracts both. See
[BTF → ISF](features/btf-to-isf.md) and [kallsyms](features/kallsyms.md).

### 2. MemProcFS-compatible UX

Same folder names, same file formats where it makes sense. If you've
used MemProcFS on a Windows dump, the Linux dump experience is
near-identical. The mounted tree gives you `cat`, `grep`, `head`, `tail`,
`find`, `strings`, `xxd`, `hexdump`, your editor, FTK Imager, HxD —
every existing tool just works.

### 3. Production-grade engine

- C++17, clean layered architecture, well-defined module boundaries
- Streaming I/O — `proc.dmp` files for 8 GB processes don't materialise
  in RAM; they're produced byte-range-on-demand
- Mmap-backed memory source (833 MB/s on the test dump)
- LRU page cache for per-process PGD walks
- WinFsp mount with stateless callbacks (no per-Open allocation;
  immune to WinFsp's double-Close behaviour)

### 4. Cross-checked against Volatility 3

Every feature is validated byte-for-byte against `vol3` output on the
same dump. The bundled test dump has bash's first VMA (192 KB ELF
header + rodata) and `.text` segment matching our `proc.dmp` `PT_LOAD`
entries exactly — same SHA-256 hashes.

## Current status (v0.37)

What works end-to-end:

- ✅ AVML / LiME / raw / **kdump** dump reading (kdump = ELF64 ET_CORE,
  v0.12; auto-detected, PT_LOAD → PA mapping, VMCOREINFO captured)
- ✅ Offline ISF synthesis via BTF + kallsyms (zero external files)
- ✅ ISF auto-discovery from caches
- ✅ Symbol auto-fetch via `dwarf2json` pipeline (Ubuntu, Debian, Fedora,
  RHEL, Arch, openSUSE — six distros)
- ✅ Community ISF mirror lookup over HTTPS
- ✅ Process enumeration (x86_64)
- ✅ Maple-tree VMA walk (kernels ≥ 6.1)
- ✅ User-PGD page-table walk with LRU cache
- ✅ Per-process ELF64 core dump
- ✅ Per-process `/proc/<pid>/` files (cmdline, environ, status, stat,
  statm, limits, maps, exe, cwd, root, capabilities, …)
- ✅ Per-process `fd_table.txt` — open fds with mount-aware path resolution
- ✅ Per-process `environ` — recovered process environment
- ✅ Per-process `shell_history.txt`
- ✅ System-wide `/sys/` views: banner.txt, dtb.txt, kallsyms, btf.txt,
  **dmesg**, **modules/**, **pagecache/**, **mountinfo**, **net/**
- ✅ `/sys/net/{tcp,udp,interfaces,summary.txt}` — network state via the
  TCP/UDP hash tables + `init_net.dev_base_head`. Real connections (Google,
  GitHub, …), listeners (CUPS, systemd-resolved), DNS conversations.
  Socket fds in `/proc/<pid>/fd_table.txt` carry their endpoint info
  (`socket:TCP a:b -> c:d ESTABLISHED`, `socket:UNIX path=/run/...`).
  See [features/network.md](features/network.md).
- ✅ `/sys/findevil/{findevil.txt, malfind.txt, psscan.txt, hidden_modules.txt, check_syscall.txt}`
  — threat-hunt. Malfind flags ★ HIGH-SEVERITY RWX/exec-stack mappings;
  psscan does physical-memory `task_struct` cross-view with multi-stage
  validation (0 false-positives on a clean Ubuntu dump); hidden_modules
  uses kallsyms vs visible-module diff. **check_syscall (v0.8)** verifies
  every `sys_call_table` entry against kallsyms — the #1 rootkit primitive
  detector. 468/468 OK on the clean dump. findevil.txt aggregates all four.
  `check_syscall` first validates that the recovered table looks like a
  kernel function-pointer table; if not, it reports unavailable rather than
  claiming hooks. See [features/findevil.md](features/findevil.md).
- ✅ `/sys/processes/{pslist.txt, pstree.txt, psaux.txt}` — `ps`-style
  text renderings of the canonical process list. `pstree.txt` shows the
  full ancestry chain (e.g. `gnome-terminal → bash → sudo → avml`);
  `psaux.txt` carries cmdline + VSZ. See
  [features/process-views.md](features/process-views.md).
- ✅ `/sys/shell_history.txt` — aggregate bash/zsh/fish/POSIX shell history;
  `/sys/shell_history.txt` is the canonical aggregate shell-history view.
- ✅ `/files/` refocused (v0.7) — orphan-only: `deleted-<fs>-<ino>.bin`
  for `unlink()`'d-but-cached files (detected via `inode.i_state &
  I_FREEING`), `orphan-<fs>-<ino>.bin` for inodes with no resolvable
  path. Everything else lives in `/fs/`.
- ✅ `/files/by-ino/<fs>-<ino>.bin` — flat per-inode page-cache recovery
- ✅ **`/fs/` — the entire root filesystem reconstructed at global paths.**
  Built via the global `inode_hashtable` (13 448 ext4 inodes recovered on
  the test dump vs 1 from `s_inodes`). Page-cache contents reassembled,
  every directory the kernel had cached, symlinks exposed as best-effort
  target text files, mount
  points composed via `init_task.nsproxy.mnt_ns`. Browse the dump's
  filesystem exactly as it appeared on the running system — including
  `/fs/home/ubuntu/Downloads/avml` (the AVML binary), `output.lime.compressed`
  (the dump file itself), and the full `/home/`, `/etc/`, `/snap/`, etc.
  trees. Pseudo-filesystems such as sysfs/procfs/cgroups are catalogued in
  `/sys/pagecache/index.txt` but filtered from the browsable `/fs/` tree
  so synthetic sysfs paths do not appear as top-level Linux files. Stale or
  malformed dentry names are also kept out of `/fs`; review
  `/sys/pagecache/path_quality.txt` for rejected recovered paths. See
  [features/pagecache.md](features/pagecache.md).
- ✅ `/sys/mountinfo` — `/proc/mountinfo`-style listing of every mount
- ✅ `/mem/phys.raw` streamed access to all of physical memory
- ✅ `/mem/kern_va.raw` 128 TiB sparse view of the canonical kernel half;
  HxD-friendly view onto direct-map / kernel-image / vmalloc by VA
- ✅ `/misc/virt2phys/<hex-va>` & `/misc/phys2virt/<hex-pa>` — path-encoded
  address translators (no writable files needed; scriptable in one shot)
- ✅ `/sys/findevil/av_edr.txt` — AV / EDR fingerprinting (50-pattern scan
  covering ~30 endpoint products)
- ✅ JSON sibling exports — `pslist.json`, `tcp.json` / `udp.json`,
  `malfind.json`, `findevil.json`
- ✅ `/forensic/snapshot.{txt,json}` — one-stop dump-triage report
  (env + processes + network + threat hunt + AV/EDR + verdict)
- ✅ `/proc/<pid>/strings.txt` & `/search/iocs.txt` — printable-string
  extraction + IOC scanner (URLs, IPv4, emails, JWT, AWS keys)
- ✅ `/proc/<pid>/yara.txt` & `/search/yara.txt` — embedded libyara scan
  with built-in default ruleset (EICAR/Mimikatz/CS/Meterpreter/UPX/...)
  and user .yar/.yara drop-ins via `$LMPFS_YARA_RULES`
- ✅ **`memnixfs.dll` — C API** — any language with a C FFI can drive the
  same engine that powers the WinFsp mount. See `src/api/lmpfs.h` for the
  surface.
- ✅ **MemProcFS `VMMDLL_*` surface** — the same DLL also exports a
  MemProcFS-shaped C API (`src/api/vmmdll_compat.h`).
- ✅ **Plugin SDK** — third-party `.dll` / `.so` modules register VFS
  paths at engine init. Sample plugin in `tests/c_api/sample_plugin.cpp`.
- ✅ **Kernel tracepoint enumeration** — `/sys/findevil/tracepoints.txt`
  walks every `__tracepoint_*` symbol's handler list with per-handler
  classify_ptr audit.
- ✅ **System-info files** — `/sys/hostname`, `/sys/uptime`,
  `/sys/mounts`, `/sys/users.txt`, `/sys/net/listening` (v0.27).
- ✅ **System-info wider sweep** — `/sys/cpuinfo`, `/sys/meminfo`,
  `/sys/iomem`, `/sys/boottime`, `/sys/dns.txt`, IPv6 per interface (v0.28).
- ✅ `/proc/<pid>/libs.txt` — shared libraries grouped by resolved path
- ✅ `/proc/<pid>/ptrace.txt` — ptrace relationships (real_parent vs parent +
  victim list)
- ✅ Multi-strategy kernel-VA reader (direct-map / image / vmalloc, with
  `init_mm.pgd` fallback for module memory)
- ✅ Live mount: WinFsp on Windows, FUSE on Linux
- ✅ `export` to a real folder for tools that don't speak WinFsp
- ✅ `cat <vfs-path>` CLI subcommand for selective triage

## Tested kernels

| Distro | Kernel | Dump format | Result |
|---|---|---|---|
| Ubuntu 24.04 | 6.14.0-36-generic | AVML (snappy compressed) | 331 procs, 190k symbols, all `/proc/<pid>/maps` byte-correct vs vol3 |
| Alpine 3.21 | 6.12.1-3-virt | raw (QEMU `pmemsave`) | 63 procs, 122k symbols, full kallsyms with VAs |

Both run **fully offline** — no `--symbols`, no `--vmlinux`, no
internet, no toolchain. Just the dump.
