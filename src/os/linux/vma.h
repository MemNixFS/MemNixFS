#pragma once
#include "core/types.h"
#include "formats/physical_layer.h"
#include "symbols/isf_symbols.h"
#include "os/linux/kernel_resolver.h"
#include "os/linux/process.h"
#include <vector>
#include <string>

namespace lmpfs::linux {

struct Vma {
    u64 vm_start = 0;
    u64 vm_end   = 0;
    u64 vm_flags = 0;       // bit 0 = VM_READ, bit 1 = VM_WRITE, bit 2 = VM_EXEC
    u64 vm_pgoff = 0;       // pages
    u64 vm_file  = 0;       // kernel VA of struct file, 0 = anonymous
    u64 size()   const { return vm_end - vm_start; }
    bool readable()   const { return  vm_flags & 0x1; }
    bool writable()   const { return  vm_flags & 0x2; }
    bool executable() const { return  vm_flags & 0x4; }
};

// Enumerate VMAs of a process. On 6.1+ kernels this walks the maple tree
// (mm->mm_mt); on pre-6.1 kernels it follows the mm->mmap / vm_next linked
// list. Returns empty list for kernel threads (mm == 0).
std::vector<Vma> enumerate_vmas(const PhysicalLayer& phys,
                                const IsfSymbols&    isf,
                                const KernelContext& kctx,
                                const Process&       p);

// Find the user PGD physical address for this process (returns 0 if N/A).
PAddr resolve_user_pgd(const PhysicalLayer& phys,
                       const IsfSymbols&    isf,
                       const KernelContext& kctx,
                       const Process&       p);

} // namespace lmpfs::linux
