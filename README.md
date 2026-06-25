# MemNixFS

![Language: C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)
![Platform: Windows · Linux](https://img.shields.io/badge/platform-Windows%20%C2%B7%20Linux-lightgrey.svg)

**Mount a Linux memory dump as a filesystem and investigate it with the tools you already use.**

Point MemNixFS at an AVML / LiME / raw / kdump image and the live kernel state at the
moment of capture — processes, open files, sockets, loaded modules, the page cache,
threat-hunt findings, a forensic timeline — shows up as ordinary files and folders. Then
you `cd`, `ls`, `grep`, `cat`, open it in your editor, or feed it to any script. It's the
[MemProcFS](https://github.com/ufrisk/MemProcFS) idea — *memory as a filesystem* — brought
to **Linux** dumps, running natively on **Windows** and **Linux**.

<p align="center">
  <img src="docs/img/mounted-drive.png" width="660"
       alt="A Linux memory dump mounted as a Windows drive (M:) and browsed in File Explorer, showing the proc, sys, fs, forensic, search and mem folders">
</p>
<p align="center"><em>A Linux memory image, mounted as a Windows drive and browsed in Explorer — no exporting, no special viewer.</em></p>

```console
$ memnixfs --dump memory.lime mount M:
$ cat M:/sys/findevil/triage.txt        # one-shot "is this box owned?" verdict
$ cat M:/forensic/timeline.txt          # everything that happened, on one UTC axis
$ rg -i 'password|BEGIN PRIVATE KEY' M:/fs   # your tools, on memory
```

---

## Why a filesystem?

Memory forensics usually means learning a query tool and reading walls of tabular output.
MemNixFS takes a different bet: if the dump *is* a filesystem, then **every tool you already
know becomes a memory-forensics tool.** `grep` searches kernel structures. `find -newer`
filters the page cache by mtime. `diff` compares two captures. Your SIEM's file-ingest
pipeline indexes `/sys` and `/forensic` with zero new integration. Explorer, `less`, HxD,
ripgrep, Python's `os.walk` — they all just work, because the hard part (parsing the dump)
has already been turned into paths.

There's no new query language to learn. If you can navigate a directory tree, you can
navigate a crashed kernel.

## Works even with no symbols

The usual wall in Linux memory forensics is symbols: without the *exact* debug profile
(ISF) for the captured kernel, most tools stall. MemNixFS treats symbols as optional. It
will auto-discover or `--auto-fetch` an ISF if it can — but if it can't, it **generates
what it needs from the dump's own BTF type information**, which modern kernels embed. An
air-gapped analyst with an oddball kernel still gets a browsable `/fs`, recovered file
contents, and process analysis. No internet, no matching profile, still useful.

## What's in the mount

Everything the kernel had at capture time, laid out as folders you can browse,
`grep`, and `cat` however you like:

```
M:\
├── proc\<pid>\      per-process: maps, fds, threads, kstack, environ, strings, ELF core
├── sys\             system-wide: shell history, banner, dmesg, modules, net\, processes\, findevil\, etc
├── fs\              reconstructed root filesystem (recovers cached file contents)
├── forensic\        timeline.{txt,csv} + per-domain splits + JSON/CSV snapshot
├── search\          yara\, iocs, strings, entropy
├── mem\             phys.raw + windowed kernel-VA streams
└── plugins\         third-party file producers
```

See the [CLI reference](docs/cli-reference.md) and the [feature docs](docs/README.md) for
the full path map.

## Supported inputs

| Dump format | Notes |
|---|---|
| **AVML** | Microsoft Azure Memory Loader (framed Snappy) |
| **LiME** | Linux Memory Extractor |
| **raw** | flat physical dumps (`dd`, padded) |
| **kdump / vmcore** | ELF64 with VMCOREINFO |

Targets x86-64 Linux. Symbols are optional — supply an ISF, let it `--auto-fetch`, or rely
on BTF-only mode.

## Quick start

Grab a build (or [build from source](docs/building.md)), then:

```console
$ memnixfs --dump memory.lime list                 # list processes (no symbols needed)
$ memnixfs --dump memory.lime mount M:             # mount the whole tree (Windows: WinFsp)
$ memnixfs --dump memory.lime cat /sys/findevil/findevil.txt   # read one file, no mount
$ memnixfs --dump memory.lime export ./out         # or export everything to a folder
```

> **Windows — the `mount` command requires [WinFsp](https://winfsp.dev/rel/).** It is a
> kernel-mode filesystem driver, so it cannot be bundled in the download; install it once
> (default `.msi` options are fine) and `mount` works. Prefer not to install anything? Use
> `cat` to read a single file or `export` to copy files out to a folder — neither needs WinFsp.

A normal run is quiet — a few status lines (and how long the load took), then your
output. Add `-v` / `--verbose` to see the full diagnostic pipeline (symbol resolution,
page-table and DTB scans, warnings), or `-q` for critical errors only.

No symbol file is needed for a first look: MemNixFS scans the dump to identify the kernel
and recovers what it can. Add `--auto-fetch` to pull matching symbols, or `--vmlinux <path>`
to point at your own.

## Options

`--dump <file>` is the only required argument; with no command it prints a short
overview. Everything else is optional — most useful first:

| Option | What it does |
|---|---|
| `--symbols <path>` | Use this ISF (`.json`/`.json.xz`) file, or search this directory. Omit to auto-discover from the local cache. |
| `--auto-fetch` | Download the matching kernel-debug symbols automatically (Ubuntu/Debian/Fedora/RHEL/Arch/openSUSE). |
| `--vmlinux <path>` | Generate symbols from your own `vmlinux` — the escape hatch for custom or unusual kernels. |
| `--forensic[=MODE]` | Pre-warm expensive-but-small files in the background so opening them is instant. `MODE` = `quick` \| `smart` (default) \| `full`. |
| `--no-http-cache` | Don't consult the community symbol mirrors over HTTP. Use for air-gapped / offline runs. |
| `--precompute` | Background-warm the system-wide analysis files so the tree shows real sizes and opens instantly. |
| `--offset OFF` / `--length LEN` | Window into a huge file with `cat` (e.g. `/mem/phys.raw`). Accept `0x…` hex, decimal, or `K/M/G/T` suffixes. |
| `--forensic-include CATS` / `--forensic-exclude CATS` | Add or drop forensic categories (`system-info`, `threat-hunt`, `per-process`, `yara`). |
| `-v`, `--verbose` | Show the full diagnostic pipeline, including warnings. `-vv` adds trace. |
| `-q`, `--quiet` | Print critical errors only. |
| `-h`, `--help` | Full command and option reference. |

## Programmable

`memnixfs.dll` exposes the engine through a **stable C ABI** (`extern "C" lmpfs_*`,
see [`src/api/lmpfs.h`](src/api/lmpfs.h)) — the CLI is just one consumer, so any language
with C FFI can drive the same code.

## Build

**Windows** needs MSVC 2022, CMake ≥ 3.20, vcpkg, and ninja. WinFsp is needed only for the
live `mount` backend. The `msvc-x64` preset finds vcpkg through the `VCPKG_ROOT` environment
variable:

```powershell
[Environment]::SetEnvironmentVariable('VCPKG_ROOT', 'C:\path\to\vcpkg', 'User')
$env:VCPKG_ROOT = 'C:\path\to\vcpkg'

cmake --preset msvc-x64
cmake --build build/msvc-x64 --config Release
```

This pulls `snappy`, `liblzma`, `nlohmann-json`, `fmt`, and `yara` (which brings `openssl`)
via vcpkg. For the live mount backend, install [WinFsp](https://winfsp.dev/rel/) and add
`-DLMPFS_BUILD_MOUNT_WINFSP=ON`.

**Linux** uses FUSE for the mount backend; see the [build guide](docs/building.md):

```bash
sudo apt install build-essential cmake ninja-build pkg-config \
  fuse3 libfuse3-dev libsnappy-dev liblzma-dev nlohmann-json3-dev libfmt-dev libyara-dev

cmake -S . -B build/linux-release -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DLMPFS_BUILD_MOUNT_FUSE=ON -DLMPFS_BUILD_MOUNT_WINFSP=OFF
cmake --build build/linux-release --target memnixfs
```

## Documentation

- **[Documentation wiki](docs/README.md)** — architecture, every feature explained,
  recipes, troubleshooting, glossary.
- **[Overview](docs/overview.md)** · **[CLI reference](docs/cli-reference.md)** ·
  **[Build guide](docs/building.md)**

## Responsible use

MemNixFS is a defensive forensics and incident-response tool: it reads a memory image you
already have and presents it for analysis. Only analyze dumps you are authorized to handle.
The parser is hardened against malformed and hostile inputs (bounds-checked headers,
allocation caps, cycle guards on kernel data-structure walks) — but a dump from a
compromised host is still untrusted data, so treat unknown images accordingly.

## Authors

Built by two friends who wanted MemProcFS-style memory forensics on Linux:

- **Youssef Ayman** — [@ELJoOker2004](https://github.com/ELJoOker2004)
- **Tarek Salama** — [@Immortal-ibr](https://github.com/Immortal-ibr)

## Acknowledgements

An independent project inspired by, and interoperable with,
[MemProcFS](https://github.com/ufrisk/MemProcFS) and
[Volatility 3](https://github.com/volatilityfoundation/volatility3) — not affiliated with or
endorsed by either. Symbol auto-fetch uses the community
[Volatility 3 symbol mirrors](https://github.com/Abyss-W4tcher/volatility3-symbols).

If working without external symbols interests you, check out [mquire](https://github.com/trailofbits/mquire) and this cool article [*Linux memory forensics without external dependencies*](https://blog.trailofbits.com/2026/02/25/mquire-linux-memory-forensics-without-external-dependencies/).
