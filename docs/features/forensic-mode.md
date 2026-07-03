# Forensic mode & browse-cheap performance

**Status:** Shipping — the browse-cheap directory listing is always on; the
`--forensic` background pre-warmer is opt-in and defaults off.
**Source:** `ForensicWarmer` (the VFS-tree warmer), the `FileCost` cost tag set
at each file's registration site, and `Node::size_hint()` on the VFS node base.
**Engine wiring:** The VFS tree is built as usual, then — only when `--forensic`
is passed — the warmer walks the tree and runs `worth_warming()` producers on a
background thread pool before the mount/command returns. The pool size is
auto-chosen (conservative) and can be overridden with `--warm-jobs N`; on
compressed dumps warming is decompression-bound rather than CPU-bound, so more
threads don't speed it up. The completion line reports elapsed time, e.g.
`forensic=full: warming complete in 1m 21s`.
**Cross-ref:** MemProcFS forensic mode (`m_fc_*`, one-time SQLite ingest); the
lazy `LazyFileNode` content model documented in
[pagecache.md](pagecache.md) and [findevil.md](findevil.md).

---

## What it solves

MemNixFS generates each VFS file **lazily** — content is produced on first read
and then cached on the node. That keeps memory low and means you only pay for
analysis you actually look at. But two consequences made *browsing* feel slow
compared with MemProcFS:

1. **Browsing a folder triggered processing.** `LazyFileNode::size()` ran the
   file's producer to learn the byte count, and WinFsp asks for *every* child's
   size to fill Explorer's **Size** column. So merely listing a folder ran
   every file's producer in it — YARA scans, strings extraction, entropy — before
   you opened a single file.
2. **No preload.** Expensive analytic files were only ever computed on first
   open, so the first click on each one stalled.

The two capabilities below address these independently: a fix that makes
listing cheap for everyone, and an opt-in mode that pre-computes the expensive
files in the background.

## The browse-cheap fix (always on, no flag)

`Node::size_hint()` is a **cheap** size query that never runs a producer. It
returns the cached size if the node is already loaded, and `0` otherwise.
Directory listing now uses `size_hint()`; **opening** a file still resolves the
authoritative byte count via `size()` (which produces content if needed). The
result: folder browsing is instant whether or not forensic mode is on.

> **Note:** an un-warmed lazy file shows **size 0** in a listing until it's
> opened — the real size resolves on open. This is normal for a synthetic
> filesystem whose contents are computed on demand, and it's the price of never
> blocking a directory listing on analysis.

## Forensic mode (`--forensic`, default off)

High-signal forensic entry points are `/sys/findevil/triage.txt`,
`/sys/findevil/indicators.{txt,csv,json}`,
`/forensic/timeline_summary.txt`, and the split timeline domain files under
`/forensic/timeline/`. Network and FindEvil rows that cannot be given a real
event timestamp are explicitly labeled `snapshot-time-unavailable`.

An opt-in mode that **warms** — in the background, before you touch them — the
files that are *expensive to compute but small in memory*, so that browsing and
opening them is instant. Crucially it does **not** warm the heavy files, so you
don't pay memory for content you may never read. Think of it as
*"like MemProcFS forensic mode, but selective."*

### How it decides what to warm

Each file carries a static, two-axis cost tag set at its registration site:

```
FileCost {
    Compute:  Trivial | Cheap | Expensive,                // is producing it slow?
    Mem:      Small | Large,                              // is the output big in RAM?
    Category: None | SystemInfo | ThreatHunt | PerProcess | Yara
}
```

`Trivial` is a third compute tier added for files cheap enough to run *during a
directory listing*: `Node::size_hint()` produces-and-caches them on first listing
so they show their **real size** in Explorer instead of 0 (e.g. `/sys/hostname`,
`mountinfo`, `users.txt`, `pidhashtable`). Everything heavier stays 0 until
opened or warmed.

The warm **policy** lives in the warmer, not on the file:

```
warm = (Compute == Expensive) AND (Mem == Small)
```

This separation matters: the **tag describes the file**, the **policy decides
what gets preloaded**. The policy can change (warm more, warm less) without
re-tagging every file.

| File(s) | Cost | Warmed? | Why |
|---|---|---|---|
| per-process `fd_table.txt`, `malfind.txt`, `entropy.txt`, `libs.txt`, `yara.txt`, `kstack.txt`, `threads.txt`, `ptrace.txt`, `shell_history.txt` | Expensive + Small | ✅ warmed | Slow to compute, tiny once computed — ideal preload targets |
| system-wide `/sys/findevil/*` (the whole threat-hunt subtree), `/sys/dmesg` | Expensive + Small | ✅ warmed | Same: heavy analysis, small text output |
| `strings.txt` | Expensive + **Large** | ❌ not warmed | Kept lazy — warming it would cost real memory |
| `proc.dmp`, `/mem/phys.raw`, `/mem/kern_va.raw` | streamed | ❌ not warmed | Never materialised; served as a stream, not a cached blob |
| `info.txt`, `maps`, `status`, etc. | **Cheap** | ❌ not warmed | Already instant — nothing to gain |

### Modes & categories (what to warm)

`--forensic` takes an optional **mode**, and the warmed set can be tuned per
**category**. The `Category` tag groups files; a mode selects a default set of
categories; include/exclude adjust it.

| Category | Files | Toggleable |
|---|---|---|
| `system-info` | `/sys/dmesg`, the `/sys/processes/*` views (`pslist`, `pstree`, `psaux`, `threads`, `.csv`/`.json`) (+ global artifacts) | always on |
| `threat-hunt` | `/sys/findevil/*` (the whole subtree) | ✅ |
| `per-process` | per-PID `threads`, `kstack`, `fd_table`, `malfind`, `entropy`, `libs`, `ptrace`, `shell_history.txt` (user tasks only) | ✅ |
| `yara` | per-PID `yara.txt` (the single most expensive category) | ✅ |

> The `/sys/processes/*` views (pstree, pslist, psaux, threads) are core triage
> artefacts, so they're tagged `system-info` and **every** forensic mode —
> including the default `smart` — pre-warms them. Opening `/sys/processes` after
> `--forensic` is instant.

| Mode | Warms | Typical count (lime2, ~130 user procs) |
|---|---|---|
| `--forensic=quick` | system-info + threat-hunt | ~28 files |
| `--forensic` / `=smart` (default) | quick + per-process (no yara) | ~964 files |
| `--forensic=full` | smart + per-process yara **+ every light system-wide file** (i.e. also does what `--precompute` does — the maximal mode) | ~1200 files |

Tune with comma lists:

```powershell
# Everything except per-process YARA scans (fast, still thorough)
memnixfs --dump dump.lime --forensic=full --forensic-exclude yara mount M:

# Minimal system-wide warming, but add YARA on top
memnixfs --dump dump.lime --forensic=quick --forensic-include yara mount M:
```

Unknown category tokens are warned about and ignored. Internally the CLI
resolves mode + include + exclude into a bitmask (`Engine::Options::
forensic_mask`); the warmer warms a node only when `worth_warming()` **and** its
category bit is set.

### `--precompute` (browse-completeness warming)

`--forensic` optimises for **analysis depth** — it warms the *expensive* files
(findevil, per-process, YARA). It deliberately skips cheap/`None`-tier files, so
light system-wide files like `/sys/kallsyms` or `/sys/net/tcp` still show 0 until
opened.

`--precompute` optimises for **browse completeness**: it warms *every light,
system-wide analysis file* (any compute tier) in the background so the whole
tree shows real sizes and opens instantly. It is path-aware — it skips the heavy
subtrees (`/proc`, `/files`, `/fs`, `/search`, `/forensic`, `/sys/pagecache`),
the `Mem::Large` files (per-process `strings.txt`), and the heavy
ThreatHunt/PerProcess/YARA categories. Those stay on-demand, so a full
corpus/YARA scan never runs on every mount.

| | `--forensic` (smart) | `--precompute` |
|---|---|---|
| Goal | analysis depth | browse completeness |
| Warms | Expensive+Small by category (findevil, per-process) | light system-wide files of **any** tier |
| `kallsyms`, `/sys/net/*` | ❌ (cheap-tier) | ✅ |
| per-process `libs`/`yara` | ✅ | ❌ |
| Typical count | ~964 | ~115 |

The two **compose**, and `--forensic=full` runs both policies — it's the maximal
mode (`full ⊇ precompute ⊇ quick/smart`). Use `--precompute` alone when you just
want a fully-populated browse view without paying for the heavy hunt scans.

### How warming runs

After the VFS tree is built, a `ForensicWarmer` walks it, collects the nodes for
which `worth_warming()` is true, and runs their producers on a background thread
pool sized `min(hardware_concurrency, 4)`. The mount (or CLI command) **returns
immediately** — warming proceeds in the background and the mount stays
responsive throughout.

- **No double work.** A file opened before it's been warmed simply computes on
  demand into the *same* per-node cache. The warmer and an on-demand open share
  one cache slot, so content is never produced twice.
- **Scope: real user tasks only.** Per-process warming is limited to tasks with
  `mm != 0`. Kernel threads (kworkers, etc.) are skipped — their per-task files
  are near-empty, so warming them is wasted work.
- **Mis-tag guardrail.** A 16 MiB ceiling logs any file tagged `Small` that
  actually produces more than that, so a mis-tag surfaces in the logs instead of
  silently bloating memory.

### Thread-safety

Producers run concurrently, so the shared engine state they touch was audited:

| Shared state | Why it's safe under concurrency |
|---|---|
| `kva_reader` translation caches | Backed by atomics |
| Socket index | Built once via `std::call_once` |
| kallsyms table | Built at engine-open, read-only afterward |
| YARA 4.x rules | Shared rules scanned via an internally-created **per-call** scanner |
| `LazyFileNode` content | Each node guards its own load with a mutex |

Because each `LazyFileNode` guards its own load, a node being warmed by the
background pool while it is *simultaneously* opened by a WinFsp dispatcher
thread is safe — one of them produces, the other waits and reads the cache.

### Usage

```powershell
# Background pre-warming for snappy interactive triage
memnixfs --dump output.lime.compressed --forensic mount M:
```

Example log (the completion line is logged the moment the warm pool drains —
mid-mount, not at unmount):

```
forensic: pre-warming 1300 file(s) on 4 background thread(s); mount stays responsive
forensic: warming complete — 1300 files cached (~11 MB resident)
```

### When to use it

- **USE it** for interactive triage — when you'll click through many
  `/sys/findevil/*` and per-process files in Explorer and want each one to open
  instantly.
- **SKIP it** for "I just want one file" or scripted single-file `cat` / export
  workflows. Lazy mode already serves those with minimal work; pre-warming a
  thousand files you won't read is pure overhead.

### Trade-offs (vs MemProcFS)

Both tools generate file content lazily — **neither holds all bytes in RAM**.
MemProcFS *feels* preloaded for two reasons: (a) its deep page- and
translation-caching, and (b) its forensic mode's one-time SQLite ingest that
front-loads analysis into a database.

MemNixFS forensic mode is **session-only, in-memory, and selective** by the cost
tags — it warms only the expensive-but-small files and leaves the rest lazy.
Disk-persisted warm results (so a re-mount is instant without re-computing) are
**future work, not implemented** today.

## See also

- [Page-cache + file recovery](pagecache.md) — the lazy file-content model this
  mode pre-warms.
- [Threat-hunt (findevil)](findevil.md) — the `/sys/findevil/*` subtree that
  forensic mode warms wholesale.
- [CLI reference](../cli-reference.md) — the `--forensic` flag and every other
  command.
