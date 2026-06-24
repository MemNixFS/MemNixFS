# Process enumeration

How MemNixFS finds every `task_struct` in the dump, without DTB,
without symbol addresses for `init_task`, and without trusting the
ISF to have the right offsets.

## The challenge

A Linux dump contains thousands of bytes that *look* like `task_struct`
candidates. The right one is `init_task` (PID 0, the "swapper" idle
task). From there, the kernel's circular doubly-linked list `tasks` connects
every process. But finding `init_task` requires either:

1. Its kernel VA (from the ISF's `init_task` symbol), then translate
   that VA to a PA (needs DTB), OR
2. Direct scanning of physical memory for a structure that looks like
   `init_task`.

Approach (1) is the textbook way but assumes a validated DTB and a
trustworthy ISF symbol address. Approach (2) is robust against both.
MemNixFS does (2) primarily, with (1) as a verification cross-check
when symbols are present.

## The swapper-anchored scan

`scan_swapper(phys)` in `src/os/linux/kernel_resolver.cpp` looks for
the byte pattern of `init_task`'s `comm` field. For PID 0 (the idle
thread), `comm` is **`"swapper/0\0\0\0\0\0\0\0"`** (the "/0" suffix is
the CPU number for multi-core kernels; older kernels just had
`"swapper\0\0\0\0\0\0\0\0\0"`).

We scan every byte of physical memory for:

```
[s w a p p e r]  // 7 bytes
[/ 0  |  \0 \0]  // 2 bytes (slash-zero OR two NULs)
[\0 \0 \0 \0 \0 \0 \0]  // 7 NULs
```

i.e. 16 bytes total. The first hit is `init_task`'s `comm` field. The
`task_struct` start is `comm_pa − offset_of(comm)`, where the offset
comes from the ISF (typically 0xCF0 on modern 6.x kernels).

## What we then verify

For each swapper-comm candidate, we read three fields:

```cpp
u32 pid   = read(task_pa + pid_offset);
u64 next  = read(task_pa + tasks_offset + 0);  // tasks.next
u64 prev  = read(task_pa + tasks_offset + 8);  // tasks.prev
```

A valid `init_task` has:
- `pid == 0`
- `next != 0`, `prev != 0` (both point to other tasks)
- Both are kernel VAs in the direct-map range

If any check fails (rare; usually the first hit is genuine), we move
to the next candidate.

## Deriving `direct_map_base`

`init_task.tasks.next` is a kernel VA pointing to the **first real
process** (typically `systemd`'s `task_struct`). Linux maps all of
physical RAM into a contiguous region of kernel virtual address space,
the **direct map** (a.k.a. **physmap**). On x86_64 this base is randomised
by KASLR but aligned to 1 GiB.

We round the sampled VA down to the nearest 1 GiB, then test candidate
bases walking downward. More than one candidate can produce an implied PA
inside the dump, so range-checking alone is not enough. Each candidate is
validated by interpreting `tasks.next - tasks_offset` as the first real
`task_struct` and scoring fields that should make sense:

- `pid` and `tgid` are non-zero and in a sane range.
- `comm` is printable ASCII.
- `tasks.prev` points back to `init_task.tasks` using the runtime VA.
- `tasks.next` points to a second task whose `pid`/`tgid`/`comm` are also
  sane, and that second task's `tasks.prev` points back to the first task.

```cpp
VAddr dm_va_sample = init_task.tasks.next;
VAddr cand_base = dm_va_sample & ~(1 GiB - 1);
for (VAddr base = cand_base; base != 0; base -= 1 GiB) {
    PAddr first_task_pa = (dm_va_sample - base) - tasks_offset;
    score pid/tgid/comm/tasks.prev;
    keep the best validated base;
}
ctx.direct_map_base = best_base;
```

This single value lets us translate any direct-mapped kernel VA to a PA
via subtraction. No DTB walk required.

## Walking the task list

`list_processes()` in `src/os/linux/process_list.cpp` walks
`init_task.tasks` via the direct map:

```cpp
u64 next = read_pod(kctx.init_task_pa + tasks_offset);
while (next != head) {
    VAddr task_va  = next - tasks_offset;
    PAddr task_pa  = task_va - direct_map_base;
    if (task_pa >= max_pa) break;   // wrapped or invalid

    // Read pid, tgid, comm, ppid, mm, cred (uid/gid)
    fill_process(phys, ctx, task_va, offsets, &p);
    if (p.pid != 0 && !p.comm.empty()) processes.push_back(p);

    next = read_pod(direct_map_to_pa(task_va + tasks_offset));
}
```

Termination: we stop when `task_va` falls outside the direct map (this
catches the wrap-around back to `init_task` in the kernel text region).

## Fields we read per task

| Field | Used for |
|---|---|
| `pid` | The PID we display |
| `tgid` | Thread group ID (TGID == PID for the main thread) |
| `comm` | The 15-char process name |
| `tasks` | List link (walked by us) |
| `real_parent` / `parent` | PPID |
| `mm` | Pointer to `mm_struct` (used for VMA walking) |
| `cred` | Pointer to `cred` (UID/GID) |

All offsets come from the ISF (`task_struct` and `cred` types).

### PPID workaround

On some kernel builds (we hit this on 6.14.0-36-generic), `task_struct`
is laid out under `__randomize_layout`, so `real_parent` / `parent`
pointers are offset by `+0x40` from what DWARF says. We handle this
with a runtime check: if the `parent_va` pointer's pointee doesn't
look like a valid task (printable `comm`), try `parent_va + 0x40`.

```cpp
u64 candidate = parent_va;
if (!looks_like_task(candidate)) candidate = parent_va + 0x40;
if (looks_like_task(candidate)) {
    out.ppid = read_u32(candidate + tgid_offset);
}
```

This is heuristic but reliable — the validation reads the candidate's
`comm` field and rejects garbage.

## Why this is robust

The whole pipeline works **without a validated DTB** because:

1. **Swapper scan** is pattern-matching in physical memory, no
   translation needed.
2. **`init_task.tasks.next`** is read directly via PA, no DTB.
3. **Direct map** is computed from the first sample VA. Once we know
   `direct_map_base`, every other kernel-data read is just subtraction.
4. **PGD for per-process address space** is read from `task->mm->pgd`
   (which is in the direct map, so accessible without DTB).

The DTB is only needed for **kernel text** reads (kallsyms, modules,
`/sys/banner.txt`). Process enumeration is independent.

## Output: the `Process` struct

```cpp
struct Process {
    u32 pid;
    u32 tgid;
    u32 ppid;
    u32 uid;
    u32 gid;
    std::string comm;
    VAddr task_va;    // direct-map VA of this task_struct
    VAddr mm;         // VA of mm_struct (0 for kernel threads)
};
```

That's enough to populate `/proc/<pid>/info.txt` and to walk to each
process's VMAs (via `mm->mm_mt` on 6.1+, or the `mm->mmap`/`vm_next`
list on pre-6.1 kernels — see [VMAs & memory](vma-and-memory.md)).

## Numbers from real dumps

| Dump | Total processes | Kernel threads | User processes | Time |
|---|---|---|---|---|
| Ubuntu 6.14.0-36-generic (AVML) | 331 | ~150 | ~180 | < 1 second |
| Alpine 6.12.1-3-virt (raw) | 63 | ~45 | ~18 | < 1 second |

## Reference

- Volatility 3 plugin: `volatility3/framework/plugins/linux/pslist.py`
- Kernel source: `init/init_task.c`, `include/linux/sched.h`
- MemProcFS equivalent: `vmm/modules/m_sys_proc.c`
