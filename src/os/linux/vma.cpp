#include "os/linux/vma.h"
#include "core/error.h"
#include "core/log.h"
#include <algorithm>
#include <unordered_set>

namespace lmpfs::linux {

namespace {

// ---- direct-map helpers (replicated from process_list.cpp) ----
bool dm_pa(VAddr va, const KernelContext& k, PAddr max_pa, PAddr& out) {
    if (va < k.direct_map_base) return false;
    u64 off = va - k.direct_map_base;
    if (off >= max_pa) return false;
    out = off; return true;
}
bool read_dm_u64(const PhysicalLayer& phys, const KernelContext& k, VAddr va, u64& v) {
    PAddr pa; if (!dm_pa(va, k, phys.max_address(), pa)) return false;
    return phys.read_pod(pa, v);
}
bool read_dm_u32(const PhysicalLayer& phys, const KernelContext& k, VAddr va, u32& v) {
    PAddr pa; if (!dm_pa(va, k, phys.max_address(), pa)) return false;
    return phys.read_pod(pa, v);
}
template <typename T>
bool read_dm(const PhysicalLayer& phys, const KernelContext& k, VAddr va, T& v) {
    static_assert(std::is_trivially_copyable_v<T>);
    PAddr pa; if (!dm_pa(va, k, phys.max_address(), pa)) return false;
    return phys.read_pod(pa, v);
}

// ---- Maple tree constants (include/linux/maple_tree.h) ----
constexpr u64 kMapleNodePointerMask = 0xFFULL;
constexpr u64 kMapleNodeTypeShift   = 3;
constexpr u64 kMapleNodeTypeMask    = 0x0F;
enum MapleNodeType : u8 {
    MAPLE_DENSE     = 0,
    MAPLE_LEAF_64   = 1,
    MAPLE_RANGE_64  = 2,
    MAPLE_ARANGE_64 = 3,
};

// Field offsets inside maple_range_64 / maple_arange_64 (from ISF).
constexpr u64 kMR64_SlotOff   = 0x80; // 16 slots × 8 B
constexpr u64 kMR64_SlotCount = 16;
constexpr u64 kMA64_SlotOff   = 0x50; // 10 slots × 8 B
constexpr u64 kMA64_SlotCount = 10;

struct VmaOffsets {
    u64 vm_start, vm_end, vm_flags, vm_pgoff, vm_file;
    u64 vm_next;   // legacy (<6.1) linked-list link; 0 when absent (maple kernels)
};
struct MmOffsets {
    bool maple;  // true: 6.1+ maple tree; false: legacy mmap/vm_next list
    u64  mm_mt;  // maple_tree offset within mm_struct (maple only)
    u64  ma_root;// ma_root offset within maple_tree   (maple only)
    u64  mmap;   // first vm_area_struct* (legacy only)
    u64  pgd;    // mm_struct.pgd (both layouts)
};

VmaOffsets get_vma_offsets(const IsfSymbols& isf) {
    VmaOffsets o{};
    o.vm_start = isf.field_offset("vm_area_struct", "vm_start");
    o.vm_end   = isf.field_offset("vm_area_struct", "vm_end");
    o.vm_flags = isf.field_offset("vm_area_struct", "vm_flags");
    o.vm_pgoff = isf.field_offset("vm_area_struct", "vm_pgoff");
    o.vm_file  = isf.field_offset("vm_area_struct", "vm_file");
    // vm_next only exists pre-6.1; the maple tree removed the VMA linked list.
    o.vm_next  = isf.field_offset_opt("vm_area_struct", "vm_next").value_or(0);
    return o;
}
MmOffsets get_mm_offsets(const IsfSymbols& isf) {
    MmOffsets mo{};
    mo.pgd = isf.field_offset("mm_struct", "pgd");
    // 6.1+ stores VMAs in a maple tree (mm_struct.mm_mt). Pre-6.1 kernels have
    // no mm_mt; they keep a vm_next-linked list rooted at mm_struct.mmap. Probe
    // for mm_mt to pick the layout rather than assuming (and throwing) one.
    if (auto mt = isf.field_offset_opt("mm_struct", "mm_mt")) {
        mo.maple   = true;
        mo.mm_mt   = *mt;
        mo.ma_root = isf.field_offset("maple_tree", "ma_root");
    } else {
        mo.maple = false;
        mo.mmap  = isf.field_offset("mm_struct", "mmap");
    }
    return mo;
}

// Hard cap so corrupt maple-tree walks (e.g. dying processes whose mm slab
// is being reused) don't blow up the vector indefinitely. Real Linux
// processes top out around a few thousand VMAs; 100 000 is generous.
constexpr std::size_t kMaxVmasPerProcess = 100'000;

void read_vma(const PhysicalLayer& phys, const KernelContext& k,
              VAddr vma_va, const VmaOffsets& o, std::vector<Vma>& out)
{
    if (out.size() >= kMaxVmasPerProcess) return;
    Vma v{};
    if (!read_dm(phys, k, vma_va + o.vm_start, v.vm_start)) return;
    if (!read_dm(phys, k, vma_va + o.vm_end,   v.vm_end))   return;
    if (v.vm_end <= v.vm_start)                              return;
    if (v.vm_end - v.vm_start > 0x40000000000ULL)            return; // sanity: <4TB
    read_dm(phys, k, vma_va + o.vm_flags, v.vm_flags);
    read_dm(phys, k, vma_va + o.vm_pgoff, v.vm_pgoff);
    read_dm(phys, k, vma_va + o.vm_file,  v.vm_file);
    out.push_back(v);
}

void walk_maple_node(const PhysicalLayer& phys, const KernelContext& kctx,
                     const VmaOffsets& voff, u64 mte, u64 expected_depth,
                     u64 depth, std::unordered_set<u64>& seen,
                     std::vector<Vma>& out)
{
    if (depth > 16) return; // hard recursion guard
    if (mte == 0)   return;
    if (seen.count(mte)) return;
    seen.insert(mte);

    u64 node_pa_va = mte & ~kMapleNodePointerMask;   // pointer to maple_node (kernel VA, direct-map)
    u8  node_type  = static_cast<u8>((mte >> kMapleNodeTypeShift) & kMapleNodeTypeMask);

    auto walk_slot_array = [&](u64 slot_off, u64 slot_count, bool recurse) {
        for (u64 i = 0; i < slot_count; ++i) {
            if (out.size() >= kMaxVmasPerProcess) return;
            u64 slot = 0;
            if (!read_dm(phys, kctx, node_pa_va + slot_off + i * 8, slot)) continue;
            if (slot == 0) continue;
            if (recurse) {
                walk_maple_node(phys, kctx, voff, slot, expected_depth, depth + 1, seen, out);
            } else {
                // LEAF: slot is a vm_area_struct pointer (no tag bits).
                read_vma(phys, kctx, slot, voff, out);
            }
        }
    };

    switch (node_type) {
        case MAPLE_LEAF_64:   walk_slot_array(kMR64_SlotOff, kMR64_SlotCount, false); break;
        case MAPLE_RANGE_64:  walk_slot_array(kMR64_SlotOff, kMR64_SlotCount, true);  break;
        case MAPLE_ARANGE_64: walk_slot_array(kMA64_SlotOff, kMA64_SlotCount, true);  break;
        case MAPLE_DENSE:     /* allocator pool, never expected for mm_mt */          break;
        default:
            log::debug("maple: unknown node type {} at {:#x}", node_type, node_pa_va);
            break;
    }
}

} // anonymous

std::vector<Vma> enumerate_vmas(const PhysicalLayer& phys,
                                const IsfSymbols&    isf,
                                const KernelContext& kctx,
                                const Process&       p)
{
    std::vector<Vma> out;
    if (p.mm == 0) return out; // kernel thread

    auto vo = get_vma_offsets(isf);
    auto mo = get_mm_offsets(isf);

    std::unordered_set<u64> seen;
    if (mo.maple) {
        // 6.1+: mm->mm_mt is an embedded maple_tree starting at offset mm_mt;
        // ma_root within maple_tree is at mo.ma_root (typically 0x8).
        //
        // For a tree with only one entry, ma_root might be the data pointer
        // directly (low bits 0). For a tree with nodes, ma_root has type bits
        // set in the low byte. Volatility distinguishes by examining the low
        // bits / flags. We treat ma_root as the root mte and recurse.
        u64 ma_root = 0;
        if (read_dm(phys, kctx, p.mm + mo.mm_mt + mo.ma_root, ma_root) && ma_root != 0)
            walk_maple_node(phys, kctx, vo, ma_root, /*expected_depth=*/8, /*depth=*/1, seen, out);
    } else if (vo.vm_next != 0) {
        // Pre-6.1: walk the singly-linked VMA list. mm->mmap points at the
        // first vm_area_struct; follow vm_next until null. `seen` guards
        // against cycles in a corrupt / reused mm slab, and read_vma's own
        // kMaxVmasPerProcess cap bounds the total count.
        u64 vma_va = 0;
        if (read_dm(phys, kctx, p.mm + mo.mmap, vma_va)) {
            while (vma_va != 0 && out.size() < kMaxVmasPerProcess) {
                if (!seen.insert(vma_va).second) break; // cycle guard
                read_vma(phys, kctx, vma_va, vo, out);
                u64 next = 0;
                if (!read_dm(phys, kctx, vma_va + vo.vm_next, next)) break;
                vma_va = next;
            }
        }
    }

    // Sort and de-duplicate by vm_start.
    std::sort(out.begin(), out.end(),
              [](const Vma& a, const Vma& b) { return a.vm_start < b.vm_start; });
    out.erase(std::unique(out.begin(), out.end(),
              [](const Vma& a, const Vma& b) {
                  return a.vm_start == b.vm_start && a.vm_end == b.vm_end;
              }), out.end());
    return out;
}

PAddr resolve_user_pgd(const PhysicalLayer& phys,
                       const IsfSymbols&    isf,
                       const KernelContext& kctx,
                       const Process&       p)
{
    if (p.mm == 0) return 0;
    auto mo = get_mm_offsets(isf);
    u64 pgd_va = 0;
    if (!read_dm(phys, kctx, p.mm + mo.pgd, pgd_va)) return 0;
    if (pgd_va == 0) return 0;
    PAddr pgd_pa = 0;
    if (!dm_pa(pgd_va, kctx, phys.max_address(), pgd_pa)) return 0;
    return pgd_pa;
}

} // namespace lmpfs::linux
