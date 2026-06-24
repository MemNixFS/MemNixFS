# Symbol resolution

`--symbols` is **optional**. MemNixFS reads kernel-banner candidates
directly from the dump, rejects non-kernel text such as format templates
(`Linux version %s (%s)`) and article snippets (`Linux version of ...`),
then parses the selected canonical release string (for example
`6.14.0-36-generic`). It uses that release in a 6-step resolution chain
to find or synthesise a matching ISF (Volatility-3 Intermediate Symbol
File).

## The 6-step chain

| # | Step | When it fires | When it skips |
|---|---|---|---|
| 1 | **User-supplied file** | `--symbols path/to/file.json.xz` | No `--symbols`, or path is a directory |
| 2 | **Local cache** | Always | After step 1 if step 1 succeeded |
| 3 | **BTF + kallsyms from the dump** | Cache miss | If kernel has no `.BTF` section |
| 4 | **`--vmlinux` runs dwarf2json** | `--vmlinux` supplied | When flag is absent |
| 5 | **Community HTTP mirror** | Default ON | `--no-http-cache` |
| 6 | **`--auto-fetch`** runs `tools/fetch_symbols.sh` | `--auto-fetch` supplied | When flag is absent |

If steps 1–6 all fail, MemNixFS exits with a clear error message
containing the exact `wsl bash -lc "tools/fetch_symbols.sh '<release>'"`
command you can copy-paste.

## Step-by-step details

### Step 1 — `--symbols PATH`

If `PATH` is a regular `.json` or `.json.xz` file:
- Use it directly. The banner-vs-ISF mismatch check later in
  `resolve_kernel()` still runs, so feeding the wrong file gets a
  loud `[ERR]` warning before silent corruption.

If `PATH` is a directory:
- Recursively walk it for any `.json[.xz]` file whose
  `metadata.linux.symbols[0].name` matches the dump's release.

### Step 2 — Local cache

Searched in order:
1. `<--symbol-cache DIR>/<release>.json[.xz]` (if the flag was given)
2. `./symbols/linux/<release>.json[.xz]`
3. `$LMPFS_SYMBOL_CACHE/<release>.json[.xz]`
4. `%LOCALAPPDATA%\MemNixFS\symbols\<release>.json[.xz]` (Windows)
5. `~/.cache/lmpfs/symbols/<release>.json[.xz]` (Unix)

Whenever a later step **downloads or generates** an ISF (BTF+kallsyms,
HTTP mirror, `--vmlinux`, `--auto-fetch`), it is saved to the
`--symbol-cache` directory if given, else `$LMPFS_SYMBOL_CACHE`, else the
platform default — so it is reused on subsequent runs.

Each candidate's `metadata.linux.symbols[0].name` is verified against
the dump's release. Mismatches are skipped (a previous run might have
cached a wrong file).

### Step 3 — **BTF + kallsyms from the dump itself** (the offline path)

This is the headline feature. Two extractors run against the dump's
physical memory:

1. **kallsyms** ([details](kallsyms.md)) — signature-scans for the
   kernel's compressed symbol table. Produces 100k–210k entries of
   `(name, type_char, kernel_VA)`.

2. **BTF** ([details](btf-to-isf.md)) — scans for the kernel's `.BTF`
   section (a few MB of type info). Produces 5k–15k `user_types`
   (structs/unions with byte-exact field offsets) + base types + enums.

The two get merged into a single ISF JSON: BTF supplies `user_types` /
`base_types` / `enums`, kallsyms supplies `symbols`. The result is
xz-compressed and written to the cache for next time.

**Zero external files. No network. No toolchain.** Works on any modern
distro kernel (every kernel built with `CONFIG_KALLSYMS=y` and
`CONFIG_DEBUG_INFO_BTF=y` — i.e. essentially all of them since Ubuntu
20.04 / Fedora 32 / RHEL 8.2 / Alpine 3.16+).

### Step 4 — `--vmlinux PATH`

You supply a vmlinux (or `vmlinuz` extracted by `extract-vmlinux`).
The resolver invokes `dwarf2json` against it (via WSL on Windows) to
produce a full DWARF-based ISF. Highest fidelity available; useful for
unusual kernels (custom builds, embedded, distro kernels not on the
community mirrors).

### Step 5 — Community HTTP mirror

Looks up the ISF by SHA-256 of the kernel banner, against a list of
mirror URLs:

- Default: Abyss-W4tcher's vol3-symbols repo (community-maintained)
- Override: set `LMPFS_ISF_MIRRORS` to a semicolon-separated list of
  URL templates, e.g.
  `https://mirror.example/{KEY:0:2}/{KEY}.json.xz;https://backup/{KEY}.json.xz`

Disable with `--no-http-cache`.

### Step 6 — `--auto-fetch`

Runs `tools/fetch_symbols.sh <release>` (via WSL on Windows, native
elsewhere). The script:

1. Detects the dump's distro from the banner.
2. Installs the matching `linux-image-*-dbgsym` (Ubuntu/Debian),
   `kernel-debuginfo` (Fedora/RHEL/Rocky/Alma), `linux-debug` (Arch),
   or equivalent (openSUSE/Manjaro).
3. Extracts the vmlinux.
4. Runs `dwarf2json` against it.
5. xz-compresses and stores in the cache.

**Needs network + the matching distro repo accessible.** ~1–2 minutes
on a fast connection.

## Order rationale

Steps are ordered to prefer cheaper + more authoritative sources:

1. **User file first** — explicit user choice wins
2. **Cache next** — same release? reuse it (free)
3. **BTF + kallsyms** — fully local, only depends on the dump (~3 seconds)
4. **vmlinux** — local but needs external file (a few seconds)
5. **HTTP** — network, but no toolchain needed
6. **auto-fetch** — slowest, biggest dependencies, but full DWARF fidelity

If you're working offline, step 3 wins for every modern kernel without
you doing anything. If you need 100% DWARF fidelity (e.g. a kernel
struct field that's only visible in DWARF), use `--vmlinux` or
`--auto-fetch`.

## Logging

At `-v` you get a log line per attempted step:

```
[INF] Scanning dump for banner to identify kernel release...
[INF] Detected kernel release: 6.14.0-36-generic (distro=ubuntu, …)
[INF] Auto-picked ISF from cache C:\…\6.14.0-36-generic.json.xz
[INF] Loading symbols: C:\…\6.14.0-36-generic.json.xz (auto-discover-cache)
```

The trailing parenthesised tag tells you which step succeeded:

| Tag | Step |
|---|---|
| `user-file` | 1 (file) |
| `auto-discover-user-dir` | 1 (dir) |
| `auto-discover-cache` | 2 |
| `btf+kallsyms-from-dump` | 3 |
| `from-vmlinux` | 4 |
| `community-cache` | 5 |
| `auto-fetched` | 6 |

## Banner selection

Memory dumps can contain more than one `Linux version ` string: the real
kernel banner, printk copies, stale cached text, vulnerability text, or
format strings compiled into userland. MemNixFS scores candidates before
symbol resolution. Only kernel-looking releases drive ISF selection and
banner-vs-ISF mismatch warnings; rejected strings remain diagnostic noise,
not evidence of the running kernel.

## What if nothing matches?

If all 6 steps fail, `cannot_resolve()` throws with:

```
Error: No ISF found for kernel release '6.14.0-36-generic' (distro hint: ubuntu).
Searched: (no --symbols path), ./symbols/linux/, $LMPFS_SYMBOL_CACHE,
%LOCALAPPDATA%/MemNixFS/symbols.

  # Ubuntu kernel debug symbols are on the ddebs repo.
  # Pass --auto-fetch to have us run this automatically,
  # OR run the bundled script yourself in WSL:
  wsl bash -lc "tools/fetch_symbols.sh '6.14.0-36-generic'"
```

The error always includes a copy-pasteable command. No guessing required.
