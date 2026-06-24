# CLI Reference

## Synopsis

```
memnixfs --dump <file> [options] [command]
```

Only `--dump` is mandatory. Default command is `list`.

## Commands

### `list` (default)
Prints a table of processes found in the dump.

```powershell
memnixfs --dump output.lime.compressed list
```

Output:
```
   PID    TGID    PPID    UID    GID  COMM
─────────────────────────────────────────────
     1       1       0      0      0  systemd
     2       2       0      0      0  kthreadd
   …
  4849    4849    4839   1000   1000  bash

Total: 331 processes
```

### `tree`
Prints the entire VFS tree (recursively). Useful to see what would
be available if you mounted the dump.

```powershell
memnixfs --dump output.lime.compressed tree
```

Output:
```
[DIR]
  [DIR] proc
    [DIR] 1-systemd
            info.txt
            memmap.txt
            cmdline
            …
            proc.dmp
    [DIR] 2-kthreadd
    …
  [DIR] sys
        banner.txt
        dtb.txt
        kallsyms
        btf.txt
  [DIR] mem
        phys.raw
        kern_va.raw
        README.txt
  [DIR] misc
        README.txt
    [DIR] virt2phys
          README.txt
          <hex-va>           ← synthesised, not listed
    [DIR] phys2virt
          README.txt
          <hex-pa>           ← synthesised, not listed
  [DIR] forensic
        timeline.txt         ← v0.17 chronological event merge
        timeline.csv
        snapshot.txt         ← v0.20 one-stop triage report
        snapshot.json
  [DIR] search             ← v0.21+
        README.txt
        iocs.txt             ← URLs / IPv4 / emails / JWT / AWS keys
        yara.txt             ← libyara scan + default + user rules (v0.22)
  [DIR] sys
    [DIR] findevil
          ...                ← every plugin (malfind, psscan, …)
          av_edr.txt         ← v0.20 AV/EDR fingerprint scan
          pslist.json        ← v0.20 JSON sibling
          ...
```

### `cat <vfs-path> [--offset OFF] [--length LEN]`
Dump a single VFS file to stdout. Pair with `--offset` / `--length` to
window into huge sparse streams without trying to read the whole thing.
Both flags accept decimal, `0x...` hex, or a `K/M/G/T` suffix:

```powershell
# Read 256 bytes from linux_banner's runtime VA via the kernel-VA stream
memnixfs --dump out.lime.compressed cat /mem/kern_va.raw `
  --offset 0x7fffa7fb3580 --length 256

# Carve a 4 MiB chunk of physical memory starting 2 GiB in
memnixfs --dump out.lime.compressed cat /mem/phys.raw `
  --offset 2G --length 4M > slice.bin

# Stream the whole physical image (sparse gaps synthetic-zero-filled)
memnixfs --dump out.lime.compressed cat /mem/phys.raw > phys.raw
```

Length `0` (default) keeps the legacy behavior of reading to EOF, which
is what you want for finite files like `/sys/kallsyms` or `/proc/1234/status`.

`cat /mem/phys.raw` now produces the **full** physical image: the AVML reader
presents physical memory as a contiguous sparse image, so interior gaps are
synthetic-zero-filled rather than stopping the stream at the first gap (the old
behavior). Use `/sys/mem_ranges.txt` to see which physical ranges were actually
captured.

### `export <dir>`
Walks the entire VFS and writes every file to a real directory.
Large `proc.dmp` files are materialised as-is. Useful for tools that
can't mount filesystems.

```powershell
memnixfs --dump output.lime.compressed export C:\mnt\memdump
```

Then browse `C:\mnt\memdump\` in Explorer. The directory layout mirrors
the mount layout exactly.

### `mount <point>`
Mounts the dump as a live read-only filesystem. Windows builds use WinFsp;
Linux builds use FUSE.

```powershell
memnixfs --dump output.lime.compressed mount M:
# or
memnixfs --dump output.lime.compressed mount C:\some\empty\dir
```

```bash
mkdir -p /tmp/memnixfs
memnixfs --dump output.lime.compressed --forensic mount /tmp/memnixfs
fusermount3 -u /tmp/memnixfs   # Linux
```

The mounted FS is read-only. On Windows, unmount by stopping `memnixfs.exe`
(Ctrl-C in the console). On Linux, use the platform unmount command
shown above.

**Tip:** add [`--forensic`](#--forensic) to pre-warm expensive analytic
files in the background, so browsing the mount stays snappy when you click
through `findevil` and per-process files.

**Note:** WinFsp mounts are visible to the **logon session** that creates
them. If you mount from cmd / PowerShell, Explorer in that desktop sees
the drive. Spawning the EXE from a service or a different sandbox makes
the mount invisible to your desktop. See [WinFsp mount](features/mount.md)
for details.

### `kallsyms [name]`
Extracts kernel symbols straight from the dump, **bypassing the engine
entirely**. Useful for triage when other parts of the pipeline fail.

```powershell
# Bulk: shows totals + sanity-check well-known symbols
memnixfs --dump output.lime.compressed kallsyms

# Lookup one symbol
memnixfs --dump output.lime.compressed kallsyms init_task
# → 0xffffffff9c810940 D init_task
```

This command does not require the ISF, banner, or kernel resolution to
succeed first. It's the cheapest way to verify the dump's kernel is
recognisable.

## Flags

### `--dump <file>` (required)
Path to the dump file. Format is auto-detected (AVML / LiME / raw).

### Symbol resolution

`--symbols` is **optional**. The resolver runs a multi-stage chain
(see [Symbol resolution](features/symbol-resolution.md)). These flags
control the chain:

| Flag | Effect |
|---|---|
| `--symbols PATH` | Explicit ISF `.json[.xz]` file, or a directory to walk for matches. |
| `--vmlinux PATH` | Run `dwarf2json` against this vmlinux (offline). Uses WSL on Windows. |
| `--symbol-cache DIR` | Directory where auto-downloaded / generated ISFs are **saved** (and searched first on the next run). Overrides `$LMPFS_SYMBOL_CACHE` and the default `%LOCALAPPDATA%\MemNixFS\symbols`. Created if absent. Alias: `--symbols-cache`. |
| `--auto-fetch` | Run `tools/fetch_symbols.sh` to download the matching distro kernel-debug package and produce an ISF. |
| `--no-http-cache` | Disable HTTP lookups against community symbol mirrors. Pair with `--vmlinux` or rely on BTF+kallsyms for fully offline runs. |

**BTF-only dumps (no kernel symbols):** `/fs` file **content** still recovers.
The page-cache path derives `vmemmap_base` symbol-free, so folios can be turned
into physical pages without a `vmemmap_base` symbol. Reclaimed (non-resident)
pages cannot be recovered: files with no cached content pages report
`unavailable`, while partially cached files may contain synthetic zero-filled
gaps. For the most complete symbols (and richest `/fs` enumeration), use
`--auto-fetch` or `--vmlinux`.

### `--forensic[=MODE]`, `--forensic-include`, `--forensic-exclude`

Off by default. Turns on **forensic mode**: once the VFS tree is built,
the tool pre-warms (computes + caches) the files that are *expensive to
compute but small in memory* on a background thread pool (min(cores, 4)
threads). The mount/command returns immediately — warming runs in the
background, and a file opened before it's warmed just computes on demand
against the same cache (no double work).

**Modes** (`--forensic=MODE`, default `smart`):

| Mode | Warms |
|---|---|
| `quick` | system-wide only — `/sys/findevil/*`, `/sys/dmesg`, `/sys/processes/*` |
| `smart` (default) | quick **+** per-process analytics (`threads`, `kstack`, `fd_table`, `malfind`, `entropy`, `libs`, `ptrace`, `shell_history.txt`) for real user processes |
| `full` | smart **+** per-process `yara.txt` **+** every light system-wide file (also does what [`--precompute`](#--precompute) does — the maximal mode) |

The `/sys/processes/*` views (`pslist`, `pstree`, `psaux`, `threads`, `.csv`,
`.json`) are core triage artefacts, tagged `system-info`, so **every** mode —
including the default `smart` — pre-warms them.

**Categories** (toggle with comma lists): `system-info` (always on),
`threat-hunt`, `per-process`, `yara`.

```powershell
memnixfs --dump dump.lime --forensic mount M:                       # smart
memnixfs --dump dump.lime --forensic=full mount M:                  # everything
memnixfs --dump dump.lime --forensic=full --forensic-exclude yara mount M:
memnixfs --dump dump.lime --forensic=quick --forensic-include yara mount M:
```

Kept lazy regardless of mode (to bound memory): `strings.txt` (large),
`proc.dmp` and `/mem/*.raw` (streamed, never materialised), and cheap files
that are already instant. A memory guardrail warns if a file expected to be
small produces more than 16 MiB. Kernel threads are skipped for per-process
warming. Unknown category tokens are warned about and ignored.

Without `--forensic`, behaviour is unchanged **except** that browsing a
folder is now always cheap: directory listings no longer run each file's
full producer. Trivial-to-produce files (small `/sys` scalars like
`hostname`, `cpuinfo`, `meminfo`, `uptime`, `dtb.txt`, …) show their real
size immediately; heavier files (`kallsyms`, `dmesg`, per-process `yara.txt`,
strings, `findevil/*`, …) show **0 KB until you open them**, at which point
the real size and content resolve. That 0 KB is cosmetic — the file is
complete once opened; it just isn't computed merely to draw the listing.

### `--precompute`

Off by default. Background-warms **every light, system-wide analysis file** so
the whole tree shows real sizes and opens instantly — `/sys/*` (including
`kallsyms`, `dmesg`, `shell_history.txt`, `/sys/processes/*`), `/sys/net/*`, and
`modules`. Cheapest-first, so the small files populate within moments; the mount
stays responsive throughout.

Where `--forensic` targets **analysis depth** (the expensive findevil /
per-process / YARA scans), `--precompute` targets **browse completeness** (no
0-byte files when you look around). It deliberately leaves the heavy
corpus/per-process work on-demand: the `/proc`, `/files`, `/fs`, `/search`,
`/forensic` and `/sys/pagecache` subtrees, the `Mem::Large` files (per-process
`strings.txt`), and the threat-hunt/per-process/YARA categories are **not**
warmed — so a full 2 GB / all-process scan never runs on every mount.

```powershell
memnixfs --dump dump.lime --precompute mount M:              # browse-complete
memnixfs --dump dump.lime --precompute --forensic=smart mount M:  # + per-process
```

The two compose, and `--forensic=full` already implies `--precompute` (it's the
maximal mode: `full ⊇ precompute ⊇ quick/smart`). See
[Forensic mode](features/forensic-mode.md) for the full policy.

Typical wins: opening `/sys/findevil/*` and per-process `yara.txt` /
`threads.txt` is instant after warming, instead of pausing to compute on
first open.

### Verbosity

| Flag | Level |
|---|---|
| (default) | INFO |
| `-v` | DEBUG |
| `-vv` | TRACE |

`-v` shows the resolver's per-step decisions, kallsyms scan details,
DTB strategy attempts. `-vv` is firehose level — only useful when
chasing a specific bug.

### Help

```powershell
memnixfs -h        # or --help
```

## Environment variables

| Variable | Purpose |
|---|---|
| `LMPFS_SYMBOL_CACHE` | Override the symbol-cache directory for both **saving** fetched ISFs and **searching**. Defaults to `%LOCALAPPDATA%\MemNixFS\symbols` on Windows, `~/.cache/lmpfs/symbols` elsewhere. The `--symbol-cache` flag takes precedence. |
| `LMPFS_ISF_MIRRORS` | Semicolon-separated list of mirror URL templates. Each entry can contain `{KEY}` (banner SHA-256) and `{KEY:0:2}` (first 2 chars). Defaults to the Abyss-W4tcher vol3-symbols repo. |
| `LMPFS_TOOLS_DIR` | Where to find `tools/fetch_symbols.sh` if it's not in a default location. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Operational error (couldn't open dump, no ISF, kernel didn't resolve, …) |
| 2 | Bad command line (unknown flag, missing required arg) |

## Complete example: forensic triage workflow

```powershell
# 1. Quick "what's in this dump" (5 seconds)
memnixfs --dump suspicious.lime kallsyms

# 2. Process listing
memnixfs --dump suspicious.lime list

# 3. VFS structure
memnixfs --dump suspicious.lime tree | head -50

# 4. Pull everything to a folder for offline analysis
memnixfs --dump suspicious.lime export D:\analysis\case-1234\

# 5. Or mount and browse live
memnixfs --dump suspicious.lime mount M:

# Then in another shell:
type M:\sys\banner.txt
type M:\sys\dtb.txt
type M:\sys\kallsyms | findstr /R "T do_init_module"
M:\proc\3096-firefox\proc.dmp     # opens in HxD / FTK
```

## Common option combinations

### Fully offline, no toolchain, no network
```powershell
memnixfs --dump <file> --no-http-cache <command>
```
BTF + kallsyms in the dump synthesises the ISF; no external files needed.

### Use a vmlinux you happen to have
```powershell
memnixfs --dump <file> --vmlinux ./vmlinux-6.14 --no-http-cache <command>
```
Runs `dwarf2json` in WSL (if on Windows) to make an ISF from your
vmlinux. Highest-fidelity offline path for unusual kernels.

### Force a re-download of symbols
```powershell
# Clear the cache first
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\MemNixFS\symbols"

# Then run with --auto-fetch
memnixfs --dump <file> --auto-fetch <command>
```

### Snappy browsing of a live mount
```powershell
memnixfs --dump <file> --forensic mount M:
```
Use this for interactive triage where you'll click through many
`findevil` and per-process files — the expensive ones are pre-warmed in
the background so opens don't pause to compute.
