// pagecache.cpp — see header for design notes.
//
// Layout summary (kernel 6.x, x86_64):
//
//   super_block                       size 0x580
//     .s_list           @0x000        list_head, linked into `super_blocks`
//     .s_dev            @0x010
//     .s_blocksize      @0x018
//     .s_type           @0x028        (struct file_system_type *)
//     .s_magic          @0x060
//     .s_root           @0x068
//     .s_id[32]         @0x3c0        e.g. "sda1", "tmpfs", "proc"
//     .s_inodes         @0x548        list_head of all inodes for this sb
//
//   inode                             size 0x270
//     .i_mode           @0x000        POSIX file type | perms
//     .i_sb             @0x028
//     .i_mapping        @0x030        (address_space *)
//     .i_ino            @0x040
//     .i_size           @0x050
//     .i_state          @0x090
//     .i_sb_list        @0x110        list_head, linked into sb.s_inodes
//     .i_dentry         @0x130        hlist_head — dentries aliasing this inode
//     .i_data           @0x170        inline address_space (i_mapping usually
//                                     points to &i_data for regular files)
//
//   address_space                     size 0xc0
//     .host             @0x000        back-pointer to inode
//     .i_pages          @0x008        xarray (root) of cached folios
//     .nrpages          @0x058
//     .a_ops            @0x068
//
//   xarray                            size 0x10
//     .xa_lock          @0x000
//     .xa_flags         @0x004
//     .xa_head          @0x008        root entry (folio* OR xa_node*-with-low-bit)
//
//   xa_node                           size 0x240
//     .shift            @0x000        bits this level consumes (6 per level)
//     .offset           @0x001        my slot in parent
//     .count            @0x002
//     .parent           @0x008
//     .slots[64]        @0x028        each entry: folio* or xa_node*
//
//   folio                             size 0xc0 (the first 0x40 bytes are
//                                     a struct page — flags @0, mapping @0x18,
//                                     index @0x20 mirror page semantics).
//
// xarray entry encoding (include/linux/xarray.h):
//   bit 0 set → "value" entry (xa_to_value); we ignore for the page cache.
//   bits 0..1 == 0b10 → internal pointer (xa_to_node)
//   else → leaf pointer to user-defined entry (folio*)
//
// vmemmap → PFN:
//   vmemmap_base (a runtime variable in kernel) is the VA where the kernel
//   maps the sparse mem_map array. Each PFN is stored as one `struct page`
//   (64 bytes on x86_64). So:
//     PFN = (folio_va - vmemmap_base) / sizeof(struct page)
//     PA  = PFN << PAGE_SHIFT      (PAGE_SHIFT == 12 on x86_64)
//
#include "os/linux/pagecache.h"
#include "os/linux/kva_reader.h"
#include "os/linux/dentry_path.h"
#include "os/linux/kernel_resolver.h"
#include "os/linux/mountinfo.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "formats/physical_layer.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace lmpfs::linux {

namespace {

constexpr u64 kPageSize     = 4096;
constexpr u64 kPageShift    = 12;
constexpr u64 kStructPageSz = 0x40;   // sizeof(struct page) on x86_64
constexpr std::size_t kMaxRecoveryRanges = 256;

bool is_host_forbidden_path_char(unsigned char c) {
    return c == ':' || c == '\\' || c == '*' || c == '?' || c == '"' ||
           c == '<' || c == '>' || c == '|';
}

// Length (1-4) of a well-formed UTF-8 sequence starting at p with `avail`
// bytes remaining, or 0 if the bytes are not well-formed UTF-8. Follows the
// Unicode 3.9 well-formed byte-sequence table: rejects overlong encodings,
// UTF-16 surrogates (U+D800–U+DFFF), and codepoints above U+10FFFF, as well as
// lone continuation bytes and truncated sequences. This is what tells a real
// non-ASCII filename apart from binary garbage in a corrupt/hostile dentry.
int utf8_sequence_len(const unsigned char* p, std::size_t avail) {
    const unsigned char c = p[0];
    if (c < 0x80) return 1;
    auto cont = [](unsigned char b, unsigned char lo, unsigned char hi) {
        return b >= lo && b <= hi;
    };
    if (c >= 0xC2 && c <= 0xDF)
        return (avail >= 2 && cont(p[1], 0x80, 0xBF)) ? 2 : 0;
    if (c == 0xE0)
        return (avail >= 3 && cont(p[1], 0xA0, 0xBF) && cont(p[2], 0x80, 0xBF)) ? 3 : 0;
    if (c >= 0xE1 && c <= 0xEC)
        return (avail >= 3 && cont(p[1], 0x80, 0xBF) && cont(p[2], 0x80, 0xBF)) ? 3 : 0;
    if (c == 0xED)   // exclude surrogates: second byte capped at 0x9F
        return (avail >= 3 && cont(p[1], 0x80, 0x9F) && cont(p[2], 0x80, 0xBF)) ? 3 : 0;
    if (c >= 0xEE && c <= 0xEF)
        return (avail >= 3 && cont(p[1], 0x80, 0xBF) && cont(p[2], 0x80, 0xBF)) ? 3 : 0;
    if (c == 0xF0)
        return (avail >= 4 && cont(p[1], 0x90, 0xBF) && cont(p[2], 0x80, 0xBF) &&
                cont(p[3], 0x80, 0xBF)) ? 4 : 0;
    if (c >= 0xF1 && c <= 0xF3)
        return (avail >= 4 && cont(p[1], 0x80, 0xBF) && cont(p[2], 0x80, 0xBF) &&
                cont(p[3], 0x80, 0xBF)) ? 4 : 0;
    if (c == 0xF4)   // cap at U+10FFFF: second byte 0x80–0x8F
        return (avail >= 4 && cont(p[1], 0x80, 0x8F) && cont(p[2], 0x80, 0xBF) &&
                cont(p[3], 0x80, 0xBF)) ? 4 : 0;
    return 0;        // 0x80–0xBF lone, 0xC0/0xC1 overlong, 0xF5–0xFF out of range
}

PathTrust validate_path_component(std::string_view comp) {
    if (comp.empty()) return {false, "empty path component"};
    if (comp == "." || comp == "..") return {false, "path traversal component"};
    const auto* p = reinterpret_cast<const unsigned char*>(comp.data());
    const std::size_t n = comp.size();
    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = p[i];
        if (c < 0x80) {
            // ASCII byte: apply the display-/host-safety rules.
            if (c == 0) return {false, "embedded NUL in path component"};
            if (c == '/') return {false, "slash in path component"};
            if (c < 0x20 || c == 0x7f) return {false, "control byte in path component"};
            if (is_host_forbidden_path_char(c))
                return {false, "host-forbidden character in path component"};
            ++i;
        } else {
            // Non-ASCII: accept only well-formed UTF-8; reject binary garbage.
            const int len = utf8_sequence_len(p + i, n - i);
            if (len == 0) return {false, "invalid UTF-8 in path component"};
            // Reject C1 control codepoints U+0080–U+009F (0xC2 0x80–0x9F).
            if (len == 2 && c == 0xC2 && p[i + 1] <= 0x9F)
                return {false, "control codepoint in path component"};
            i += static_cast<std::size_t>(len);
        }
    }
    if (comp.back() == ' ' || comp.back() == '.')
        return {false, "component has trailing space or dot"};
    return {true, {}};
}

std::string escape_path_for_report(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    constexpr char hex[] = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c >= 0x20 && c < 0x7f) {
            out.push_back(static_cast<char>(c));
        } else {
            out += "\\x";
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xf]);
        }
    }
    return out;
}

bool pagecache_path_is_pseudo_fs(std::string_view fs) {
    static constexpr std::string_view kPseudo[] = {
        "sysfs", "proc", "procfs", "cgroup", "cgroup2",
        "securityfs", "debugfs", "tracefs", "configfs",
        "bpf", "pstore", "efivarfs", "devtmpfs", "devpts",
        "tmpfs", "mqueue", "hugetlbfs", "autofs", "rpc_pipefs",
        "fusectl", "fuse", "selinuxfs", "nsfs", "binfmt_misc"
    };
    for (auto p : kPseudo) {
        if (fs == p) return true;
    }
    return false;
}

// xarray entry tagging — bits 0..1 form an enum:
//   00 → leaf (real pointer to a folio)
//   01 → "value" entry — not used for page cache, skip
//   10 → internal pointer (xa_node *)
//   11 → "zero" / retry — skip
inline bool xa_is_internal(VAddr e) { return (e & 3ULL) == 2; }
inline bool xa_is_value(VAddr e)    { return (e & 1ULL) == 1; }
inline VAddr xa_to_node(VAddr e)    { return e & ~3ULL; }

struct Offsets {
    // super_block
    u64 sb_s_list   = 0;
    u64 sb_s_inodes = 0;
    u64 sb_s_type   = 0;
    u64 sb_s_id     = 0;
    u64 sb_s_root   = 0;
    // inode
    u64 in_i_mode      = 0;
    u64 in_i_sb        = 0;
    u64 in_i_mapping   = 0;
    u64 in_i_ino       = 0;
    u64 in_i_size      = 0;
    u64 in_i_state     = 0;
    u64 in_i_sb_list   = 0;
    u64 in_i_dentry    = 0;
    u64 in_i_data      = 0;
    // address_space
    u64 as_i_pages  = 0;
    u64 as_nrpages  = 0;
    // xarray
    u64 xa_xa_head  = 0;
    // xa_node
    u64 xn_shift    = 0;
    u64 xn_slots    = 0;
    u64 xn_offset   = 0;
    // folio
    u64 folio_index = 0;
    // file_system_type
    u64 fst_name    = 0;
    // hlist_head / hlist_node
    u64 hlist_first = 0;
    u64 in_i_hash   = 0;   // inode.i_hash offset (hlist_node)
    bool ok = false;
};

Offsets resolve_offsets(const IsfSymbols& isf) {
    Offsets o{};
    try {
        o.sb_s_list      = isf.field_offset("super_block",   "s_list");
        o.sb_s_inodes    = isf.field_offset("super_block",   "s_inodes");
        o.sb_s_type      = isf.field_offset("super_block",   "s_type");
        o.sb_s_id        = isf.field_offset("super_block",   "s_id");
        o.sb_s_root      = isf.field_offset("super_block",   "s_root");

        o.in_i_mode      = isf.field_offset("inode",         "i_mode");
        o.in_i_sb        = isf.field_offset("inode",         "i_sb");
        o.in_i_mapping   = isf.field_offset("inode",         "i_mapping");
        o.in_i_ino       = isf.field_offset("inode",         "i_ino");
        o.in_i_size      = isf.field_offset("inode",         "i_size");
        o.in_i_state     = isf.field_offset("inode",         "i_state");
        o.in_i_sb_list   = isf.field_offset("inode",         "i_sb_list");
        o.in_i_dentry    = isf.field_offset("inode",         "i_dentry");
        o.in_i_data      = isf.field_offset("inode",         "i_data");

        o.as_i_pages     = isf.field_offset("address_space", "i_pages");
        o.as_nrpages     = isf.field_offset("address_space", "nrpages");

        o.xa_xa_head     = isf.field_offset("xarray",        "xa_head");

        o.xn_shift       = isf.field_offset("xa_node",       "shift");
        o.xn_slots       = isf.field_offset("xa_node",       "slots");
        o.xn_offset      = isf.field_offset("xa_node",       "offset");

        o.fst_name       = isf.field_offset("file_system_type", "name");

        o.ok = true;
    } catch (const std::exception& e) {
        log::warn("pagecache: ISF lacks required field — {}", e.what());
        return o;
    }
    // Optional: folio.index — present on kernels ≥ 5.18.
    try { o.folio_index = isf.field_offset("folio", "index"); }
    catch (...) { o.folio_index = 0; }
    // hlist_head.first is always at offset 0.
    o.hlist_first = 0;
    // inode.i_hash is the global-hashtable linkage. Optional — if absent,
    // we fall back to s_inodes-only enumeration.
    try { o.in_i_hash = isf.field_offset("inode", "i_hash"); }
    catch (...) { o.in_i_hash = 0; }
    return o;
}

// Read a kernel u64 variable (e.g. vmemmap_base) addressed by its symbol.
u64 read_kernel_u64_var(const Engine& eng, const char* sym_name) {
    auto* s = eng.isf().find_symbol(sym_name);
    if (!s) return 0;
    u64 v = 0;
    return kva_read_pod(eng, s->address, v) ? v : 0;
}

const char* mode_to_type(u16 m) {
    switch (m & 0170000) {
    case 0040000: return "DIR";
    case 0100000: return "REG";
    case 0120000: return "LNK";
    case 0020000: return "CHR";
    case 0060000: return "BLK";
    case 0010000: return "FIFO";
    case 0140000: return "SOCK";
    default:      return "?";
    }
}

std::string mode_to_perm_string(u16 m) {
    char b[10] = "---------";
    if (m & 0400) b[0]='r';
    if (m & 0200) b[1]='w';
    if (m & 0100) b[2]='x';
    if (m & 0040) b[3]='r';
    if (m & 0020) b[4]='w';
    if (m & 0010) b[5]='x';
    if (m & 0004) b[6]='r';
    if (m & 0002) b[7]='w';
    if (m & 0001) b[8]='x';
    return std::string(b, 9);
}

// Read a NUL-terminated kernel string of up to maxlen bytes (used for s_id
// inline char arrays and file_system_type.name pointer chases).
std::string read_kstr(const Engine& eng, VAddr va, std::size_t maxlen,
                       bool deref_pointer) {
    if (va == 0) return {};
    if (deref_pointer) {
        VAddr p = 0;
        if (!kva_read_pod(eng, va, p) || p == 0) return {};
        return kva_read_cstr(eng, p, maxlen);
    }
    return kva_read_cstr(eng, va, maxlen);
}

// Resolve a path for this inode by walking `i_dentry.first` (a dentry that
// aliases the inode). When there's no alias (anonymous inodes), return "".
// If `vfsmount_va` is supplied, the path is composed all the way up through
// every mount-point hop to the global root ("/"); otherwise it stops at
// this inode's fs root.
std::string inode_to_path(const Engine& eng, VAddr inode_va,
                           const Offsets& o, const DentryOffsets& dop,
                           VAddr vfsmount_va = 0)
{
    // i_dentry is a hlist_head; hlist_head.first is the first hlist_node.
    VAddr first_node = 0;
    if (!kva_read_pod(eng, inode_va + o.in_i_dentry + o.hlist_first,
                     first_node) || first_node == 0)
        return {};
    // The hlist_node is dentry.d_u.d_alias (an hlist_node embedded inside
    // dentry). To get the dentry pointer, container_of(first_node, dentry,
    // d_u.d_alias) — i.e. subtract dop.dentry_d_alias.
    VAddr dentry_va = first_node - dop.dentry_d_alias;
    if (dop.d_inode == 0) return {};
    VAddr dent_inode = 0;
    if (!kva_read_pod(eng, dentry_va + dop.d_inode, dent_inode) ||
        dent_inode != inode_va)
        return {};
    return dentry_to_path(eng, dentry_va, vfsmount_va, dop);
}

// xarray traversal — depth-first; collect every leaf (folio pointer +
// implied index reconstructed from path-in-tree).
struct CachedPage {
    u64    index;       // page-aligned offset into the file (in PAGES)
    VAddr  folio_va;
};

void walk_xarray(const Engine& eng, const Offsets& o,
                 VAddr entry, u64 base_index,
                 std::vector<CachedPage>& out, int depth, std::size_t& budget)
{
    if (entry == 0 || depth > 16) return;
    // Total-node budget: a depth cap alone doesn't stop a CRAFTED xarray whose
    // node slots form a cycle / DAG — with 64-way fanout that re-visits a few
    // nodes ~64^depth times (effective hang). The budget bounds total visits.
    if (budget == 0) return;
    --budget;
    if (xa_is_value(entry))      return;  // not a pointer entry

    if (!xa_is_internal(entry)) {
        // Leaf — folio*.
        // For leaves at the root of a small tree, base_index is the slot
        // index from the parent. Caller does base_index assembly.
        out.push_back({ base_index, entry });
        return;
    }

    VAddr node_va = xa_to_node(entry);
    u8 shift = 0;
    if (!kva_read_pod(eng, node_va + o.xn_shift, shift)) return;

    constexpr u64 kSlots = 64;
    std::vector<VAddr> slots(kSlots, 0);
    if (!kva_read(eng, node_va + o.xn_slots, slots.data(),
                  kSlots * sizeof(VAddr))) return;

    for (u64 i = 0; i < kSlots; ++i) {
        if (slots[i] == 0) continue;
        u64 child_base = base_index | (i << shift);
        walk_xarray(eng, o, slots[i], child_base, out, depth + 1, budget);
    }
}

std::vector<CachedPage>
collect_cached_pages(const Engine& eng, const Offsets& o, VAddr inode_va)
{
    std::vector<CachedPage> pages;
    // Use the *inline* address_space at &inode.i_data (avoids an extra ptr
    // chase; for regular files i_mapping == &i_data anyway).
    VAddr as_va = inode_va + o.in_i_data;

    VAddr xa_head = 0;
    if (!kva_read_pod(eng, as_va + o.as_i_pages + o.xa_xa_head, xa_head))
        return pages;
    if (xa_head == 0) return pages;

    if (!xa_is_internal(xa_head)) {
        // Single-page file: root holds the folio directly. Index 0.
        if (!xa_is_value(xa_head)) pages.push_back({ 0, xa_head });
        return pages;
    }
    std::size_t budget = 1'000'000;   // far above any real file; bounds malice
    walk_xarray(eng, o, xa_head, 0, pages, 0, budget);
    return pages;
}

void add_recovery_range(std::vector<RecoveredRange>& ranges,
                        bool& truncated,
                        u64& total,
                        u64 offset,
                        u64 length)
{
    if (length == 0) return;
    ++total;
    if (!ranges.empty()) {
        auto& last = ranges.back();
        if (last.offset + last.length == offset) {
            last.length += length;
            return;
        }
    }
    if (ranges.size() < kMaxRecoveryRanges) {
        ranges.push_back({offset, length});
    } else {
        truncated = true;
    }
}

std::string compact_ranges(const std::vector<RecoveredRange>& ranges, bool truncated) {
    if (ranges.empty()) return "-";
    std::string out;
    for (std::size_t i = 0; i < ranges.size(); ++i) {
        if (i) out += ",";
        out += fmt::format("{:#x}+{:#x}", ranges[i].offset, ranges[i].length);
    }
    if (truncated) out += ",...";
    return out;
}

// Walk the GLOBAL inode hashtable. This is the only reliable way to find
// every cached inode on modern (≥ ~5.x) kernels — `super_block.s_inodes` is
// frequently sparse because most inodes spend their cached life on the
// per-sb LRU and aren't kept on s_inodes.
//
// inode_hashtable is a `struct hlist_head *` array of `1 << i_hash_shift`
// entries (8 bytes each — single `first` pointer per bucket). Each cached
// inode is linked into one bucket via `inode.i_hash` (hlist_node @ 0xd0).
std::vector<VAddr> walk_inode_hashtable(const Engine& eng, const Offsets& o)
{
    std::vector<VAddr> inodes;
    const auto& isf = eng.isf();
    if (o.in_i_hash == 0) {
        log::warn("inode_hashtable: ISF has no inode.i_hash field");
        return inodes;
    }

    auto* tbl_sym   = isf.find_symbol("inode_hashtable");
    auto* shift_sym = isf.find_symbol("i_hash_shift");
    if (!tbl_sym || !shift_sym) {
        log::warn("inode_hashtable: missing inode_hashtable / i_hash_shift "
                  "symbols");
        return inodes;
    }

    VAddr table_va = 0;
    if (!kva_read_pod(eng, tbl_sym->address, table_va) || table_va == 0) {
        log::warn("inode_hashtable: cannot read table pointer");
        return inodes;
    }
    u32 hash_shift = 0;
    if (!kva_read_pod(eng, shift_sym->address, hash_shift) ||
        hash_shift == 0 || hash_shift > 30)
    {
        log::warn("inode_hashtable: bad hash_shift = {}", hash_shift);
        return inodes;
    }
    const u64 buckets = 1ULL << hash_shift;
    log::debug("inode_hashtable @ {:#x} ({} buckets)", table_va, buckets);

    // Read the array in big chunks to amortise PGD walks.
    constexpr u64 kChunk = 0x10000;       // 64 KiB at a time (8192 ptrs)
    std::vector<VAddr> chunk(kChunk / sizeof(VAddr), 0);
    constexpr std::size_t kInodeCap = 500'000;
    std::size_t empty_buckets = 0;

    for (u64 start = 0; start < buckets; start += chunk.size()) {
        u64 want = std::min<u64>(chunk.size(), buckets - start);
        std::size_t bytes = want * sizeof(VAddr);
        std::memset(chunk.data(), 0, bytes);
        kva_read(eng, table_va + start * sizeof(VAddr), chunk.data(), bytes);

        for (u64 i = 0; i < want; ++i) {
            VAddr node = chunk[i];
            if (node == 0) { ++empty_buckets; continue; }
            // Walk the hlist chain in this bucket.
            int chain_guard = 0;
            while (node != 0 && chain_guard++ < 1'000'000 &&
                   inodes.size() < kInodeCap)
            {
                VAddr inode_va = node - o.in_i_hash;
                inodes.push_back(inode_va);

                // Next link is at hlist_node offset 0.
                VAddr next = 0;
                if (!kva_read_pod(eng, node, next) || next == node) break;
                node = next;
            }
            if (inodes.size() >= kInodeCap) break;
        }
        if (inodes.size() >= kInodeCap) break;
    }
    log::debug("inode_hashtable: walked {} inodes ({} empty buckets)",
              inodes.size(), empty_buckets);
    return inodes;
}

// Last-ditch enumeration path: walk every running process's open fd table and
// collect inode VAs. This is the ONLY view that works on a BTF-only ISF —
// inode_hashtable and super_blocks are both ISF *symbols* (kernel-VA anchors)
// that a types-only BTF section can't supply, but task→files→fdt→fd[]→f_inode
// is a pure offset chain through `task_struct`, `files_struct`, `fdtable`,
// `file`, and `inode` — all four type definitions are present in BTF.
//
// Coverage: every file currently open by a running process. That's a smaller
// set than the full page-cache (we miss inodes whose last opener has closed
// the fd but whose pages haven't been reclaimed yet), but it's strictly the
// most forensically-relevant subset — every binary that's executing, every
// log file an attacker is writing to, every config file a daemon is reading.
// For typical desktop dumps this gives 2 000–5 000 inodes, more than enough
// to populate /fs with a usable file tree.
std::vector<VAddr> walk_fdtables_for_inodes(const Engine& eng,
                                            std::unordered_set<VAddr>* fs_roots)
{
    std::vector<VAddr> inodes;
    const auto& isf = eng.isf();

    u64 ts_files_off = 0, fs_fdt_off = 0, fdt_max_off = 0, fdt_fd_off = 0,
        file_inode_off = 0;
    // Optional — only needed to harvest fs-root dentries for the tree walk.
    u64 file_path_off = 0, path_mnt_off = 0, vfs_mnt_root_off = 0;
    bool can_roots = false;
    try {
        ts_files_off   = isf.field_offset("task_struct",  "files");
        fs_fdt_off     = isf.field_offset("files_struct", "fdt");
        fdt_max_off    = isf.field_offset("fdtable",      "max_fds");
        fdt_fd_off     = isf.field_offset("fdtable",      "fd");
        file_inode_off = isf.field_offset("file",         "f_inode");
    } catch (const std::exception& e) {
        log::warn("pagecache.fdtable: BTF lacks required field — {}", e.what());
        return inodes;
    }
    if (fs_roots) {
        try {
            file_path_off    = isf.field_offset("file",     "f_path");
            path_mnt_off     = isf.field_offset("path",     "mnt");
            vfs_mnt_root_off = isf.field_offset("vfsmount", "mnt_root");
            can_roots = true;
        } catch (...) { can_roots = false; }
    }

    std::unordered_set<VAddr> seen;
    std::unordered_set<VAddr> seen_vfsmount;   // dedup vfsmount→root lookups
    seen.reserve(8192);
    inodes.reserve(8192);
    std::size_t tasks_scanned = 0, tasks_with_files = 0, fds_seen = 0;

    for (const auto& p : eng.processes()) {
        if (p.task_va == 0) continue;
        ++tasks_scanned;

        VAddr files_va = 0;
        if (!kva_read_pod(eng, p.task_va + ts_files_off, files_va) ||
            files_va == 0) continue;
        VAddr fdt_va = 0;
        if (!kva_read_pod(eng, files_va + fs_fdt_off, fdt_va) ||
            fdt_va == 0) continue;

        u32   max_fds = 0;
        VAddr fd_arr  = 0;
        if (!kva_read_pod(eng, fdt_va + fdt_max_off, max_fds)) continue;
        if (!kva_read_pod(eng, fdt_va + fdt_fd_off,  fd_arr )) continue;
        // Sanity-bound max_fds — kernel hard cap is 2^20 but most processes
        // are < 1024. Reject obviously-garbage values from torn reads.
        if (max_fds == 0 || max_fds > 65536 || fd_arr == 0) continue;
        ++tasks_with_files;

        // Bulk-read the whole fd pointer array in one PGD walk.
        std::vector<VAddr> fd_ptrs(max_fds, 0);
        kva_read(eng, fd_arr, fd_ptrs.data(),
                 static_cast<std::size_t>(max_fds) * sizeof(VAddr));

        for (u32 i = 0; i < max_fds; ++i) {
            VAddr file_va = fd_ptrs[i];
            if (file_va == 0) continue;
            ++fds_seen;

            VAddr inode_va = 0;
            if (kva_read_pod(eng, file_va + file_inode_off, inode_va) &&
                inode_va != 0 && seen.insert(inode_va).second)
                inodes.push_back(inode_va);

            // Harvest the filesystem root dentry for this file:
            //   file.f_path.mnt (vfsmount*) → vfsmount.mnt_root (dentry*).
            // Both the vfsmount (embedded in a kmalloc'd struct mount) and
            // the root dentry are direct-map objects, so this works in
            // BTF-only mode where init_task.nsproxy (kernel-image) does not.
            if (can_roots) {
                VAddr vfsmnt = 0;
                if (kva_read_pod(eng, file_va + file_path_off + path_mnt_off,
                                 vfsmnt) &&
                    vfsmnt != 0 && seen_vfsmount.insert(vfsmnt).second)
                {
                    VAddr root_dentry = 0;
                    if (kva_read_pod(eng, vfsmnt + vfs_mnt_root_off,
                                     root_dentry) && root_dentry != 0)
                        fs_roots->insert(root_dentry);
                }
            }
        }
    }

    log::debug("pagecache.fdtable: {} tasks scanned, {} with files, "
              "{} fds visited → {} unique inodes{}",
              tasks_scanned, tasks_with_files, fds_seen, inodes.size(),
              fs_roots ? fmt::format(", {} fs-root dentries", fs_roots->size())
                       : std::string{});
    return inodes;
}

// Recursively walk the dentry cache tree DOWNWARD from a set of seed root
// dentries, collecting every dentry's d_inode.
//
// This is the high-coverage symbol-free path. Unlike the fdtable walk (open
// files only), this recovers the ENTIRE cached directory hierarchy reachable
// from each seed: every directory and file the kernel's dcache currently
// holds under those roots, which on a running system is essentially the whole
// active tree.
//
// Seeds (`roots`) are filesystem root dentries. They come from the caller —
// either enumerate_mounts() (when DTB/symbols make init_task.nsproxy
// reachable) or, in BTF-only mode, harvested from open files'
// vfsmount.mnt_root (all direct-map objects, so no kernel-image deref).
//
// Two child-linkage layouts, auto-detected from the ISF:
//   * ≥ 6.8 (commit da549bdd15c2): d_children (hlist_head) in the parent,
//     d_sib (hlist_node) in each child.
//   * ≤ 6.7: d_subdirs (list_head) in the parent, d_child (list_head) in
//     each child.
std::vector<VAddr> walk_dentry_tree_for_inodes(
        const Engine& eng, const std::unordered_set<VAddr>& roots) {
    std::vector<VAddr> inodes;
    const auto& isf = eng.isf();

    if (roots.empty()) {
        log::warn("pagecache.dcache: no seed root dentries — skipping tree walk");
        return inodes;
    }

    u64 d_inode_off = 0;
    // New (hlist) layout.
    u64 d_children_off = 0, d_sib_off = 0;
    // Old (list_head) layout.
    u64 d_subdirs_off = 0, d_child_off = 0;
    bool hlist_layout = false, list_layout = false;

    try {
        d_inode_off = isf.field_offset("dentry", "d_inode");
    } catch (const std::exception& e) {
        log::warn("pagecache.dcache: BTF lacks dentry.d_inode — {}", e.what());
        return inodes;
    }
    try {
        d_children_off = isf.field_offset("dentry", "d_children");
        d_sib_off      = isf.field_offset("dentry", "d_sib");
        hlist_layout   = true;
    } catch (...) {
        try {
            d_subdirs_off = isf.field_offset("dentry", "d_subdirs");
            d_child_off   = isf.field_offset("dentry", "d_child");
            list_layout   = true;
        } catch (const std::exception& e) {
            log::warn("pagecache.dcache: dentry has neither d_children/d_sib "
                      "nor d_subdirs/d_child — {}", e.what());
            return inodes;
        }
    }

    std::unordered_set<VAddr> seen_dentry;   // cycle / DAG guard
    std::unordered_set<VAddr> seen_inode;    // dedup inodes (hardlinks)
    seen_dentry.reserve(1 << 16);
    seen_inode.reserve(1 << 16);
    inodes.reserve(1 << 16);

    // Hard caps so a corrupt link can't spin forever. kMaxSiblings bounds one
    // directory's child chain (real dirs can have tens of thousands of entries
    // — e.g. a Maildir — so this is generous); kMaxDentries bounds total work.
    constexpr std::size_t kMaxDentries = 2'000'000;
    constexpr int         kMaxSiblings = 1'000'000;

    std::vector<VAddr> stack;   // DFS over dentries
    for (VAddr r : roots)
        if (r != 0) stack.push_back(r);

    std::size_t visited = 0, with_inode = 0;
    while (!stack.empty() && visited < kMaxDentries) {
        VAddr dent = stack.back();
        stack.pop_back();
        if (dent == 0) continue;
        if (!seen_dentry.insert(dent).second) continue;
        ++visited;

        // Collect this dentry's inode (directories have one too — we want the
        // dirs in /fs, not just leaf files).
        VAddr inode_va = 0;
        if (kva_read_pod(eng, dent + d_inode_off, inode_va) && inode_va != 0) {
            if (seen_inode.insert(inode_va).second) {
                inodes.push_back(inode_va);
                ++with_inode;
            }
        }

        // Enumerate children.
        if (hlist_layout) {
            // d_children is an hlist_head; .first @ 0. Each node is a child's
            // d_sib; container_of(node, dentry, d_sib) = node - d_sib_off.
            VAddr node = 0;
            kva_read_pod(eng, dent + d_children_off, node);   // hlist_head.first
            int guard = 0;
            while (node != 0 && guard++ < kMaxSiblings) {
                VAddr child = node - d_sib_off;
                stack.push_back(child);
                VAddr next = 0;
                if (!kva_read_pod(eng, node, next) || next == node) break;
                node = next;                                  // hlist_node.next @ 0
            }
        } else { // list_layout
            // d_subdirs is a list_head; .next @ 0. Walk until we return to the
            // head address. Each link is a child's d_child list_head.
            const VAddr head = dent + d_subdirs_off;
            VAddr link = 0;
            kva_read_pod(eng, head, link);                    // list_head.next
            int guard = 0;
            while (link != 0 && link != head && guard++ < kMaxSiblings) {
                VAddr child = link - d_child_off;
                stack.push_back(child);
                VAddr next = 0;
                if (!kva_read_pod(eng, link, next) || next == link) break;
                link = next;
            }
        }
    }

    log::debug("pagecache.dcache: {} root(s) seeded, {} dentries visited "
              "({} layout) → {} unique inodes",
              roots.size(), visited,
              hlist_layout ? "hlist d_children" : "list d_subdirs",
              inodes.size());
    (void)with_inode; (void)list_layout;
    return inodes;
}

} // anonymous

std::vector<CachedInode> enumerate_cached_inodes(const Engine& eng) {
    std::vector<CachedInode> out;

    const auto& isf = eng.isf();
    Offsets o = resolve_offsets(isf);
    if (!o.ok) return out;
    DentryOffsets dop = resolve_dentry_offsets(isf);

    // Map sb_va → vfsmount we can use for global-path composition. Without
    // this, paths in /files/by-path/ are fs-local and the /fs/ tree can't
    // be built. (Mount enumeration tolerates failure — without it, every
    // path resolves only inside its fs, same as the v0.2 behaviour.)
    auto mounts        = enumerate_mounts(eng);
    auto sb_to_mount   = build_sb_to_mount_map(mounts);

    // -------- Primary enumeration: global inode_hashtable --------
    //
    // `super_block.s_inodes` is broken in modern kernels — they keep most
    // inodes on the per-sb LRU, not on the s_inodes list. We get ~30k via
    // s_inodes on the test dump but only 1 is from ext4 (the actual root
    // filesystem). The global hash table is the only complete view.
    auto from_hash = walk_inode_hashtable(eng, o);

    // -------- Materialise each inode --------
    auto materialise = [&](VAddr inode_va, std::unordered_map<VAddr, std::string>& sb_fs_cache) -> bool {
        CachedInode ci{};
        ci.inode_va = inode_va;
        if (!kva_read_pod(eng, inode_va + o.in_i_sb, ci.sb_va) ||
            ci.sb_va == 0) return false;
        // sb_fs caching across inodes from the same sb
        auto cit = sb_fs_cache.find(ci.sb_va);
        if (cit == sb_fs_cache.end()) {
            std::string sb_fs;
            VAddr fst = 0;
            if (kva_read_pod(eng, ci.sb_va + o.sb_s_type, fst) && fst != 0)
                sb_fs = read_kstr(eng, fst + o.fst_name, 32, /*deref=*/true);
            if (sb_fs.empty()) {
                std::string id(32, 0);
                kva_read(eng, ci.sb_va + o.sb_s_id, id.data(), id.size());
                std::size_t k = 0;
                while (k < id.size() && id[k]) ++k;
                sb_fs.assign(id.data(), k);
            }
            sb_fs_cache[ci.sb_va] = sb_fs;
            cit = sb_fs_cache.find(ci.sb_va);
        }
        ci.sb_fs = cit->second;

        kva_read_pod(eng, inode_va + o.in_i_ino,    ci.i_ino);
        kva_read_pod(eng, inode_va + o.in_i_size,   ci.i_size);
        kva_read_pod(eng, inode_va + o.in_i_mode,   ci.i_mode);
        kva_read_pod(eng, inode_va + o.in_i_state,  ci.i_state);
        // Sanity: reject obvious garbage
        if (ci.i_mode == 0 && ci.i_ino == 0 && ci.i_size == 0) return false;

        u64 nrp = 0;
        kva_read_pod(eng, inode_va + o.in_i_data + o.as_nrpages, nrp);
        ci.nr_cached = nrp;

        VAddr vfsmount_for_inode = 0;
        if (auto it = sb_to_mount.find(ci.sb_va);
            it != sb_to_mount.end())
            vfsmount_for_inode = it->second.vfsmount_va;
        ci.path = inode_to_path(eng, inode_va, o, dop, vfsmount_for_inode);
        out.push_back(std::move(ci));
        return true;
    };

    std::unordered_map<VAddr, std::string> sb_fs_cache;
    out.reserve(from_hash.size());
    for (VAddr ino : from_hash) materialise(ino, sb_fs_cache);

    if (!from_hash.empty()) {
        log::debug("pagecache: {} inodes via inode_hashtable (definitive view)",
                  out.size());
        return out;
    }

    // -------- Fallback: walk super_blocks → s_inodes --------
    log::warn("pagecache: falling back to super_blocks.s_inodes walk "
              "(coverage will be sparse on modern kernels)");

    auto* sb_sym = isf.find_symbol("super_blocks");
    if (!sb_sym) {
        log::warn("pagecache: ISF lacks `super_blocks` symbol; switching to "
                  "symbol-free enumeration (dcache tree + fd tables)");

        // Symbol-free enumeration for BTF-only ISFs (no DWARF symbols +
        // kallsyms not recoverable from the dump). Strategy:
        //
        //   1. Walk every task's fd table. This does double duty: it yields
        //      the open-file inodes AND harvests each file's filesystem-root
        //      dentry (file.f_path.mnt → vfsmount.mnt_root). Both are
        //      kmalloc'd direct-map objects, so they're readable even when
        //      init_task.nsproxy (kernel-image static data) is not.
        //   2. (Bonus) if enumerate_mounts works — i.e. DTB/symbols make the
        //      mount namespace reachable — fold in those mount roots too.
        //   3. DFS down the dentry tree from the union of those roots,
        //      collecting every cached directory + file. This is the bulk of
        //      /fs: the whole active tree, not just open files.
        //
        // The fd inodes are then unioned with the tree inodes so deleted-but-
        // open files (whose dentry is detached from the tree) are still seen.
        std::unordered_set<VAddr> fs_roots;

        auto from_fds = walk_fdtables_for_inodes(eng, &fs_roots);

        // Fold in mount roots when reachable (no-op in pure BTF-only mode).
        for (const auto& m : enumerate_mounts(eng))
            if (m.mnt_root != 0) fs_roots.insert(m.mnt_root);

        auto from_tree = walk_dentry_tree_for_inodes(eng, fs_roots);

        std::unordered_set<VAddr> uniq;
        std::vector<VAddr>        merged;
        uniq.reserve(from_tree.size() + from_fds.size());
        merged.reserve(from_tree.size() + from_fds.size());
        for (VAddr ino : from_tree)
            if (uniq.insert(ino).second) merged.push_back(ino);
        const std::size_t n_tree = merged.size();
        for (VAddr ino : from_fds)
            if (uniq.insert(ino).second) merged.push_back(ino);
        const std::size_t n_fd_extra = merged.size() - n_tree;

        if (merged.empty()) {
            log::warn("pagecache: symbol-free enumeration produced 0 inodes "
                      "(fd-table chain unreadable — kernel-VA reads are likely "
                      "failing for an unrelated reason)");
            return out;
        }
        out.reserve(merged.size());
        for (VAddr ino : merged) materialise(ino, sb_fs_cache);
        log::debug("pagecache: {} inodes via symbol-free enumeration "
                  "({} from dcache tree + {} unique from fd tables)",
                  out.size(), n_tree, n_fd_extra);
        return out;
    }

    // super_blocks is itself a list_head (not a pointer). Its .next is the
    // first super_block's s_list field.
    VAddr head_va = sb_sym->address;
    VAddr cur = 0;
    if (!kva_read_pod(eng, head_va, cur)) {
        log::warn("pagecache: cannot read super_blocks @ {:#x}", head_va);
        return out;
    }

    std::size_t sb_count = 0, inode_count = 0;
    constexpr std::size_t kSbCap     = 256;
    constexpr std::size_t kInodeCap  = 200'000;

    while (cur != 0 && cur != head_va && sb_count < kSbCap) {
        VAddr sb_va = cur - o.sb_s_list;

        // Read fs name + s_id label.
        std::string sb_id; sb_id.resize(32, 0);
        kva_read(eng, sb_va + o.sb_s_id, sb_id.data(), sb_id.size());
        // strnlen is non-portable in <string>. Trim manually.
        {
            std::size_t k = 0;
            while (k < sb_id.size() && sb_id[k]) ++k;
            sb_id.resize(k);
        }

        std::string sb_fs;
        {
            VAddr fst = 0;
            if (kva_read_pod(eng, sb_va + o.sb_s_type, fst) && fst != 0)
                sb_fs = read_kstr(eng, fst + o.fst_name, 32, /*deref=*/true);
        }
        if (sb_fs.empty()) sb_fs = sb_id;

        // Walk this sb's s_inodes list.
        VAddr ihead = sb_va + o.sb_s_inodes;
        VAddr inode_link = 0;
        kva_read_pod(eng, ihead, inode_link);

        std::size_t this_sb_inodes = 0;
        while (inode_link != 0 && inode_link != ihead &&
               inode_count < kInodeCap)
        {
            VAddr inode_va = inode_link - o.in_i_sb_list;

            CachedInode ci{};
            ci.inode_va = inode_va;
            ci.sb_va    = sb_va;
            ci.sb_fs    = sb_fs;
            kva_read_pod(eng, inode_va + o.in_i_ino,    ci.i_ino);
            kva_read_pod(eng, inode_va + o.in_i_size,   ci.i_size);
            kva_read_pod(eng, inode_va + o.in_i_mode,   ci.i_mode);
            kva_read_pod(eng, inode_va + o.in_i_state,  ci.i_state);
            u64 nrp = 0;
            kva_read_pod(eng, inode_va + o.in_i_data + o.as_nrpages, nrp);
            ci.nr_cached = nrp;

            // Resolve full GLOBAL path (mount-point-composed) when we have
            // a mount for this sb. Falls back to fs-local if not.
            VAddr vfsmount_for_inode = 0;
            if (auto it = sb_to_mount.find(sb_va);
                it != sb_to_mount.end())
                vfsmount_for_inode = it->second.vfsmount_va;
            ci.path = inode_to_path(eng, inode_va, o, dop, vfsmount_for_inode);

            out.push_back(std::move(ci));
            ++inode_count;
            ++this_sb_inodes;

            VAddr nxt = 0;
            if (!kva_read_pod(eng, inode_link, nxt)) break;
            if (nxt == inode_link) break;
            inode_link = nxt;
        }
        log::debug("pagecache: sb {:#x} '{}' ({}) → {} inodes",
                   sb_va, sb_id, sb_fs, this_sb_inodes);

        ++sb_count;
        VAddr nxt = 0;
        if (!kva_read_pod(eng, cur, nxt)) break;
        if (nxt == cur) break;
        cur = nxt;
    }

    log::debug("pagecache: {} super_blocks, {} cached inodes",
              sb_count, out.size());

    // On dumps where the DTB didn't validate, reads of kernel-image globals
    // (super_blocks itself) can come back empty/garbage even though the
    // kmalloc'd objects are perfectly readable via the direct map. When that
    // leaves us with nothing, fall back to the symbol-free path (fd tables +
    // dcache tree) — it relies only on direct-map reads, so it works whenever
    // the process list does. (Previously this path was reached only when the
    // `super_blocks` symbol was absent, so a present-but-unreadable symbol gave
    // an empty /fs.)
    if (out.empty()) {
        log::warn("pagecache: super_blocks walk yielded 0 inodes; falling back "
                  "to symbol-free enumeration (fd tables + dcache tree)");
        std::unordered_set<VAddr> fs_roots;
        auto from_fds  = walk_fdtables_for_inodes(eng, &fs_roots);
        for (const auto& m : enumerate_mounts(eng))
            if (m.mnt_root != 0) fs_roots.insert(m.mnt_root);
        auto from_tree = walk_dentry_tree_for_inodes(eng, fs_roots);
        std::unordered_set<VAddr> uniq;
        uniq.reserve(from_tree.size() + from_fds.size());
        for (VAddr ino : from_tree) if (uniq.insert(ino).second) materialise(ino, sb_fs_cache);
        const std::size_t n_tree = out.size();
        for (VAddr ino : from_fds)  if (uniq.insert(ino).second) materialise(ino, sb_fs_cache);
        log::debug("pagecache: {} inodes via symbol-free fallback "
                  "({} from dcache tree + {} unique from fd tables)",
                  out.size(), n_tree, out.size() - n_tree);
    }
    return out;
}

ByteBuf format_pagecache_index(const Engine& eng) {
    auto inodes = enumerate_cached_inodes(eng);
    if (inodes.empty()) {
        const char msg[] =
            "; no cached inodes recovered. Either super_blocks symbol is\n"
            "; missing from the ISF, or the kernel page cache is empty\n"
            "; (very unlikely on any running system).\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }

    // Sort by (fs, path) so the listing reads naturally.
    std::sort(inodes.begin(), inodes.end(),
              [](const CachedInode& a, const CachedInode& b) {
                  if (a.sb_fs != b.sb_fs) return a.sb_fs < b.sb_fs;
                  return a.path < b.path;
              });

    std::string out;
    out.reserve(256 * 1024);
    out += fmt::format(
        "# Linux page cache — {} inodes across all mounted filesystems\n"
        "# fs           type  perms      ino  cached size           path\n"
        "#-------------+-----+----------+----+------+--------------+----\n",
        inodes.size());
    for (const auto& ci : inodes) {
        out += fmt::format("{:<13} {:<5} {} {:>10} {:>6} {:>14}  {}\n",
                           ci.sb_fs.empty() ? "?" : ci.sb_fs,
                           mode_to_type(ci.i_mode),
                           mode_to_perm_string(ci.i_mode),
                           ci.i_ino,
                           ci.nr_cached,
                           ci.i_size,
                           ci.path.empty() ? "(anon)" : ci.path);
    }
    return ByteBuf(out.begin(), out.end());
}

PathTrust validate_recovered_fs_path(const std::string& path) {
    if (path.empty()) return {false, "empty path"};
    if (path == "(null)") return {false, "null dentry path"};
    if (path[0] != '/') return {false, "not an absolute path"};
    if (path.size() > 4096) return {false, "path too long"};

    std::size_t i = 0;
    bool saw_component = false;
    while (i < path.size()) {
        while (i < path.size() && path[i] == '/') ++i;
        if (i >= path.size()) break;
        std::size_t j = i;
        while (j < path.size() && path[j] != '/') ++j;
        auto r = validate_path_component(std::string_view(path.data() + i, j - i));
        if (!r.ok) return r;
        saw_component = true;
        i = j;
    }
    if (!saw_component) return {false, "root path has no leaf component"};
    return {true, {}};
}

ByteBuf format_pagecache_path_quality(const Engine& eng) {
    auto inodes = enumerate_cached_inodes(eng);
    std::sort(inodes.begin(), inodes.end(),
              [](const CachedInode& a, const CachedInode& b) {
                  if (a.sb_fs != b.sb_fs) return a.sb_fs < b.sb_fs;
                  return a.path < b.path;
              });

    std::string out;
    out.reserve(128 * 1024);
    out += "# /sys/pagecache/path_quality.txt - recovered path trust diagnostics\n";
    out += "# /fs exposes only trusted, display-safe absolute paths. Inodes rejected here remain visible in index.txt.\n";
    out += "# reason fs ino inode_va path\n";
    out += "#------+--+---+--------+----\n";

    std::size_t rejected = 0;
    for (const auto& ci : inodes) {
        if (pagecache_path_is_pseudo_fs(ci.sb_fs)) continue;
        if (ci.path.empty() || ci.path == "/" || ci.path == "(null)") continue;
        auto trust = validate_recovered_fs_path(ci.path);
        if (trust.ok) continue;
        ++rejected;
        out += fmt::format("{:<38} {:<12} {:>10} {:#018x} {}\n",
                           trust.reason,
                           ci.sb_fs.empty() ? "?" : ci.sb_fs,
                           ci.i_ino,
                           ci.inode_va,
                           escape_path_for_report(ci.path));
    }
    if (rejected == 0)
        out += "checked: no malformed recovered paths were found\n";
    return ByteBuf(out.begin(), out.end());
}

// ----------------- file content recovery -------------------

// Canonical file size — must agree with what recover_file's output buffer
// length will be, otherwise WinFsp/HxD see a "stream read error" when they
// try to read past the buffer end (Windows treats partial reads inside the
// reported file size as I/O failures).
//
// Rule:
//   * If inode.i_size > 0  → use that (the on-disk file size). Missing
//     pages are zero-filled (sparse-file semantics). This matches what a
//     reader would see if it `cat`'d the file on the live machine.
//   * If inode.i_size == 0 (pseudo-fs like procfs/sysfs that don't set it)
//     → use the highest cached page index instead.
u64 recover_file_size(const Engine& eng, const CachedInode& ci) {
    // Cap reported/allocated size: a forged inode.i_size must not drive a
    // multi-terabyte zero-fill allocation (malicious-dump DoS lever). 4 GiB is
    // far above any real file we'd recover from a memory dump.
    constexpr u64 kMaxRecoverBytes = 4ULL * 1024 * 1024 * 1024;
    if (ci.i_size > 0) return std::min<u64>(ci.i_size, kMaxRecoverBytes);

    // No i_size — fall back to walking the xarray for the highest index.
    const auto& isf = eng.isf();
    Offsets o = resolve_offsets(isf);
    if (!o.ok) return 0;
    auto pages = collect_cached_pages(eng, o, ci.inode_va);
    if (pages.empty()) return 0;
    u64 max_idx = 0;
    for (auto& p : pages) max_idx = std::max(max_idx, p.index);
    return std::min<u64>((max_idx + 1) * kPageSize, kMaxRecoverBytes);
}

RecoveredFile recover_file_internal(const Engine& eng, const CachedInode& ci,
                                    bool materialize_bytes,
                                    bool check_physical) {
    RecoveredFile rf;
    const auto& isf = eng.isf();
    Offsets o = resolve_offsets(isf);
    if (!o.ok) return rf;

    // Final size MUST match recover_file_size() exactly, otherwise WinFsp/HxD
    // see a stream read error when reading past the produced buffer but still
    // within the file's reported size.
    u64 final_size = recover_file_size(eng, ci);
    rf.stats.logical_size = final_size;
    rf.stats.expected_pages = final_size == 0 ? 0 : ((final_size + kPageSize - 1) / kPageSize);
    rf.stats.physical_reads_checked = check_physical;
    if (final_size == 0) return rf;

    // Allocate the full file's worth of zeros up front. Pages that aren't
    // currently in the page cache stay as zeros (sparse-file semantics — the
    // same thing the kernel would hand to `cat` on the live system).
    if (materialize_bytes)
        rf.bytes.assign(final_size, 0);

    // 1. Collect cached folios.
    auto pages = collect_cached_pages(eng, o, ci.inode_va);
    rf.stats.xarray_pages_seen = pages.size();
    std::unordered_set<u64> seen_indices;
    seen_indices.reserve(pages.size());
    for (const auto& p : pages) {
        if (p.index < rf.stats.expected_pages)
            seen_indices.insert(p.index);
    }
    rf.stats.pages_within_size = seen_indices.size();

    // 2. Get vmemmap_base — needed to turn a folio (struct page) VA into a PFN.
    //
    // The symbol read goes through kernel-VA translation, which is WRONG when
    // the DTB is unvalidated (degraded mode): it returns a nonzero-but-bogus
    // value that makes every PFN out-of-range, silently dropping all pages to
    // zero. So we cross-check it against a value derived straight from the
    // cached folios — a computation that touches only direct-map reads and is
    // therefore correct regardless of the DTB — and prefer the derived value
    // whenever it disagrees (not only when the symbol is missing).
    //
    // The vmemmap region base is 1 GiB-aligned on x86_64 (CONFIG_RANDOMIZE_MEMORY
    // randomizes at PUD granularity), and a struct page for PFN p lives at
    // vmemmap_base + p*sizeof(page). For RAM < 64 GiB every PFN satisfies
    // p*64 < 1 GiB, so every cached folio VA falls in the first 1 GiB of the
    // region — and the smallest folio VA rounded down to 1 GiB recovers the base
    // EXACTLY. (Verified: 0xfffff82b41e5b640 & ~0x3fffffff == 0xfffff82b40000000.)
    u64 symbol_base = read_kernel_u64_var(eng, "vmemmap_base");
    u64 derived_base = 0;
    rf.stats.vmemmap_symbol_base = symbol_base;
    if (!pages.empty()) {
        u64 min_folio = ~0ull;
        for (const auto& p : pages)
            if (p.folio_va && p.folio_va < min_folio) min_folio = p.folio_va;
        // Derive only where it is provably exact (RAM < 64 GiB) or where there
        // is no symbol to fall back on. For RAM >= 64 GiB with a symbol present
        // we keep the symbol value, since a lone folio could legitimately sit in
        // a later 1 GiB band and the rounding would be off.
        const bool ram_under_64g = eng.phys().max_address() < (64ull << 30);
        if (min_folio != ~0ull && (symbol_base == 0 || ram_under_64g)) {
            constexpr u64 k1GiB = 0x40000000ull;
            derived_base = min_folio & ~(k1GiB - 1);
        }
    }
    rf.stats.vmemmap_derived_base = derived_base;

    struct CopyAttempt {
        u64 base = 0;
        const char* source = "none";
        std::unordered_set<u64> copied_indices;
        std::unordered_set<u64> dropped_indices;
        u64 bytes_copied = 0;
        u64 bytes_nonzero = 0;
    };

    auto count_nonzero = [](const u8* data, u64 len) -> u64 {
        u64 n = 0;
        for (u64 i = 0; i < len; ++i)
            if (data[i] != 0) ++n;
        return n;
    };

    auto attempt_copy = [&](u64 base, const char* source, bool write_bytes) {
        CopyAttempt attempt;
        attempt.base = base;
        attempt.source = source;
        attempt.copied_indices.reserve(pages.size());
        attempt.dropped_indices.reserve(pages.size());
        if (base == 0) {
            for (u64 idx : seen_indices)
                attempt.dropped_indices.insert(idx);
            return attempt;
        }

        for (const auto& p : pages) {
            if (p.index >= rf.stats.expected_pages) continue;
            if (p.folio_va < base) {
                attempt.dropped_indices.insert(p.index);
                continue;
            }
            u64 pfn = (p.folio_va - base) / kStructPageSz;
            PAddr pa = static_cast<PAddr>(pfn) << kPageShift;
            if (pa >= eng.phys().max_address()) {
                attempt.dropped_indices.insert(p.index);
                continue;
            }

            u64 off_in_file = p.index * kPageSize;
            if (off_in_file >= final_size) continue;
            u64 chunk = std::min<u64>(kPageSize, final_size - off_in_file);
            std::array<u8, kPageSize> scratch{};
            if (eng.phys().read(pa, scratch.data(), chunk) == chunk) {
                attempt.copied_indices.insert(p.index);
                attempt.bytes_copied += chunk;
                attempt.bytes_nonzero += count_nonzero(scratch.data(), chunk);
                if (write_bytes && materialize_bytes)
                    std::memcpy(rf.bytes.data() + off_in_file, scratch.data(), chunk);
            } else {
                attempt.dropped_indices.insert(p.index);
            }
        }
        return attempt;
    };

    auto better_attempt = [](const CopyAttempt& a, const CopyAttempt& b) {
        if (a.copied_indices.size() != b.copied_indices.size())
            return a.copied_indices.size() > b.copied_indices.size();
        if (a.bytes_copied != b.bytes_copied)
            return a.bytes_copied > b.bytes_copied;
        if (a.bytes_nonzero != b.bytes_nonzero)
            return a.bytes_nonzero > b.bytes_nonzero;
        if (a.dropped_indices.size() != b.dropped_indices.size())
            return a.dropped_indices.size() < b.dropped_indices.size();
        return a.base != 0 && b.base == 0;
    };

    std::vector<std::pair<u64, const char*>> bases;
    auto add_base = [&](u64 base, const char* source) {
        if (base == 0) return;
        for (const auto& b : bases)
            if (b.first == base) return;
        bases.emplace_back(base, source);
    };
    add_base(symbol_base, "symbol");
    add_base(derived_base, "folio-derived");

    CopyAttempt chosen;
    bool have_attempt = false;
    if (check_physical) {
        for (const auto& b : bases) {
            auto attempt = attempt_copy(b.first, b.second, false);
            if (!have_attempt || better_attempt(attempt, chosen)) {
                chosen = std::move(attempt);
                have_attempt = true;
            }
        }
    }
    u64 vmemmap_base = have_attempt ? chosen.base : 0;
    rf.stats.vmemmap_base = vmemmap_base;
    if (check_physical && symbol_base != 0 && vmemmap_base != 0 &&
        vmemmap_base != symbol_base) {
        log::debug("recover_file: vmemmap_base symbol={:#x} lost to {} "
                   "{:#x} for '{}' (copied={} dropped={} nonzero={})",
                   symbol_base, chosen.source, vmemmap_base, ci.path,
                   chosen.copied_indices.size(), chosen.dropped_indices.size(),
                   chosen.bytes_nonzero);
    }
    std::unordered_set<u64>& copied_indices = chosen.copied_indices;
    std::unordered_set<u64>& dropped_indices = chosen.dropped_indices;
    if (check_physical && vmemmap_base == 0) {
        log::debug("recover_file: no vmemmap_base and no folios — '{}' is zeros",
                   ci.path);
        for (u64 idx = 0; idx < rf.stats.expected_pages; ++idx) {
            u64 off = idx * kPageSize;
            u64 chunk = std::min<u64>(kPageSize, final_size - off);
            if (seen_indices.find(idx) == seen_indices.end()) {
                add_recovery_range(rf.stats.missing_ranges,
                                   rf.stats.missing_ranges_truncated,
                                   rf.stats.missing_ranges_total,
                                   off, chunk);
            } else {
                dropped_indices.insert(idx);
                add_recovery_range(rf.stats.dropped_ranges,
                                   rf.stats.dropped_ranges_truncated,
                                   rf.stats.dropped_ranges_total,
                                   off, chunk);
            }
        }
        rf.stats.pages_dropped = dropped_indices.size();
        return rf;
    }

    // 3. Copy each cached page into the buffer at its correct offset.
    if (check_physical) for (const auto& p : pages) {
        if (p.index >= rf.stats.expected_pages) continue;
        if (p.folio_va < vmemmap_base) {
            dropped_indices.insert(p.index);
            continue;
        }
        u64 pfn = (p.folio_va - vmemmap_base) / kStructPageSz;
        PAddr pa = static_cast<PAddr>(pfn) << kPageShift;
        if (pa >= eng.phys().max_address()) {
            dropped_indices.insert(p.index);
            continue;
        }

        u64 off_in_file = p.index * kPageSize;
        if (off_in_file >= final_size) continue;
        u64 chunk = std::min<u64>(kPageSize, final_size - off_in_file);
        std::array<u8, kPageSize> scratch{};
        u8* dst = materialize_bytes ? rf.bytes.data() + off_in_file
                                    : scratch.data();
        if (eng.phys().read(pa, dst, chunk) == chunk) {
            copied_indices.insert(p.index);
            rf.stats.bytes_copied += chunk;
            rf.stats.bytes_nonzero += count_nonzero(dst, chunk);
        } else {
            dropped_indices.insert(p.index);
        }
    }

    for (u64 idx = 0; idx < rf.stats.expected_pages; ++idx) {
        u64 off = idx * kPageSize;
        u64 chunk = std::min<u64>(kPageSize, final_size - off);
        if (seen_indices.find(idx) == seen_indices.end()) {
            add_recovery_range(rf.stats.missing_ranges,
                               rf.stats.missing_ranges_truncated,
                               rf.stats.missing_ranges_total,
                               off, chunk);
        } else if (check_physical && copied_indices.find(idx) == copied_indices.end()) {
            dropped_indices.insert(idx);
            add_recovery_range(rf.stats.dropped_ranges,
                               rf.stats.dropped_ranges_truncated,
                               rf.stats.dropped_ranges_total,
                               off, chunk);
        }
    }

    rf.stats.pages_copied = copied_indices.size();
    rf.stats.pages_dropped = dropped_indices.size();
    log::debug("recover_file: ino={} pages copied={} dropped={} size={}",
               ci.i_ino, rf.stats.pages_copied, rf.stats.pages_dropped,
               final_size);
    return rf;
}

ByteBuf recover_file(const Engine& eng, const CachedInode& ci) {
    return recover_file_with_stats(eng, ci).bytes;
}

RecoveredFile recover_file_with_stats(const Engine& eng, const CachedInode& ci) {
    return recover_file_internal(eng, ci, true, true);
}

RecoveredFileStats recover_file_stats(const Engine& eng, const CachedInode& ci,
                                      bool check_physical) {
    return recover_file_internal(eng, ci, false, check_physical).stats;
}

namespace {

bool plausible_symlink_target(const std::string& s) {
    if (s.empty() || s.size() > 4096) return false;
    for (unsigned char c : s) {
        if (c == 0 || c == '\n' || c == '\r') return false;
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

std::string bytes_to_symlink_target(const ByteBuf& bytes, u64 logical_size) {
    if (bytes.empty() || logical_size == 0) return {};
    const u64 bounded = std::min<u64>(logical_size, 4096);
    const std::size_t n = static_cast<std::size_t>(
        std::min<u64>(bounded, bytes.size()));
    std::string s(reinterpret_cast<const char*>(bytes.data()), n);
    const auto nul = s.find('\0');
    if (nul != std::string::npos) s.resize(nul);
    while (!s.empty() && (s.back() == '\0' || s.back() == '\n' || s.back() == '\r'))
        s.pop_back();
    return s;
}

} // anonymous

SymlinkTarget recover_symlink_target(const Engine& eng, const CachedInode& ci) {
    SymlinkTarget r;
    if ((ci.i_mode & 0170000) != 0120000) {
        r.reason = "inode is not a symlink";
        return r;
    }

    try {
        const u64 i_link_off = eng.isf().field_offset("inode", "i_link");
        VAddr target_va = 0;
        if (kva_read_pod(eng, ci.inode_va + i_link_off, target_va) && target_va != 0) {
            std::string s = kva_read_cstr(eng, target_va, 4096);
            if (plausible_symlink_target(s)) {
                r.ok = true;
                r.target = std::move(s);
                r.source = "inode.i_link";
                return r;
            }
            r.reason = "inode.i_link was present but did not contain a readable target";
        } else {
            r.reason = "inode.i_link pointer was absent or unreadable";
        }
    } catch (...) {
        r.reason = "ISF has no inode.i_link field";
    }

    auto rf = recover_file_with_stats(eng, ci);
    std::string s = bytes_to_symlink_target(rf.bytes, rf.stats.logical_size);
    if (plausible_symlink_target(s)) {
        r.ok = true;
        r.target = std::move(s);
        r.source = "page-cache content";
        return r;
    }

    if (r.reason.empty())
        r.reason = "no readable inode.i_link target and no cached symlink content";
    else
        r.reason += "; no cached symlink content";
    return r;
}

std::string describe_recovered_file_state(const RecoveredFileStats& st) {
    if (st.logical_size == 0)
        return "unavailable: zero-length recovered file";
    if (st.xarray_pages_seen == 0)
        return "unavailable: inode metadata recovered, but no cached content pages";
    if (st.physical_reads_checked && st.pages_copied == 0)
        return "unavailable: cached folios were found, but all physical bytes were unreadable";
    if (st.missing_ranges_total != 0 && st.dropped_ranges_total != 0)
        return "partial: missing cached pages and unreadable physical pages";
    if (st.missing_ranges_total != 0)
        return "partial: missing cached pages; sparse zero-filled gaps are synthetic";
    if (!st.physical_reads_checked)
        return "partial: cached-page coverage present; physical page readability not checked";
    if (st.dropped_ranges_total != 0 || st.pages_dropped != 0)
        return "partial: cached pages existed but physical bytes were unreadable";
    if (st.complete())
        return "checked: cached file content complete";
    return "partial: recovered-file coverage could not be proven complete";
}

ByteBuf format_pagecache_recovery(const Engine& eng) {
    auto inodes = enumerate_cached_inodes(eng);
    std::sort(inodes.begin(), inodes.end(),
              [](const CachedInode& a, const CachedInode& b) {
                  if (a.sb_fs != b.sb_fs) return a.sb_fs < b.sb_fs;
                  return a.path < b.path;
              });

    std::string out;
    out.reserve(256 * 1024);
    out += "# /sys/pagecache/recovery.txt - recovered-file coverage\n";
    out += "# Exact catalog: validates cached folios against physical memory without materialising file buffers.\n";
    out += "# Zero-filled gaps are synthetic unless copied_pages covers the whole logical file.\n";
    out += "# state fs ino size expected cached seen copied nonzero_bytes dropped missing vmemmap path\n";
    out += "#-----+--+---+----+--------+------+----+------+-------+-------------+-------+-------+-------+----\n";
    if (inodes.empty()) {
        out += "unavailable: no cached inodes recovered\n";
        return ByteBuf(out.begin(), out.end());
    }

    for (const auto& ci : inodes) {
        if (ci.nr_cached == 0 && ci.i_size == 0) continue;
        RecoveredFileStats st{};
        if (ci.i_size == 0) {
            st.logical_size = 0;
            st.expected_pages = 0;
        } else if (ci.nr_cached == 0) {
            st.logical_size = ci.i_size;
            st.expected_pages = (ci.i_size + kPageSize - 1) / kPageSize;
        } else {
            st = recover_file_stats(eng, ci, true);
        }
        const std::string state = ci.i_size == 0
            ? "unavailable: zero-length inode size; exact xarray walk required for pseudo-file size"
            : describe_recovered_file_state(st);
        out += fmt::format("{:<92} {:<8} {:>10} {:>12} {:>8} {:>6} {:>6} {:>7} {:>13} {:>7} {:>7} {:#x} {}\n",
                           state,
                           ci.sb_fs.empty() ? "?" : ci.sb_fs,
                           ci.i_ino,
                           ci.i_size,
                           st.expected_pages,
                           ci.nr_cached,
                           st.pages_within_size,
                           st.pages_copied,
                           st.bytes_nonzero,
                           st.pages_dropped,
                           st.missing_ranges_total,
                           st.vmemmap_base,
                           ci.path.empty() ? "(anon)" : ci.path);
    }
    return ByteBuf(out.begin(), out.end());
}

InodeMacTimes read_inode_mac_times(const Engine& eng, VAddr inode_va) {
    InodeMacTimes t{};
    if (inode_va == 0) return t;
    const auto& isf = eng.isf();
    // Resolve the SECONDS field for each time. Either layout works:
    //   * 6.11+ split: `i_atime_sec` etc. are __s64 seconds at that offset.
    //   * older timespec64: `i_atime` etc. are `struct timespec64` whose tv_sec
    //     is the first 8 bytes — so reading an i64 at the field offset is the
    //     seconds either way.
    const char* an = "(none)"; const char* mn = "(none)"; const char* cn = "(none)";
    auto off = [&](std::initializer_list<const char*> names, const char*& chosen) -> u64 {
        for (const char* n : names) {
            try { u64 o = isf.field_offset("inode", n); chosen = n; return o; } catch (...) {}
        }
        return ~0ull;
    };
    const u64 ao = off({"i_atime_sec", "i_atime", "__i_atime"}, an);
    const u64 mo = off({"i_mtime_sec", "i_mtime", "__i_mtime"}, mn);
    const u64 co = off({"__i_ctime_sec", "i_ctime_sec", "__i_ctime", "i_ctime"}, cn);
    static bool logged = false;
    if (!logged) {   // benign race — at worst a couple of duplicate debug lines
        logged = true;
        log::debug("inode MAC time fields: atime={} mtime={} ctime={}", an, mn, cn);
    }
    auto rd = [&](u64 o, i64& dst) {
        if (o == ~0ull) return;
        i64 v = 0;
        if (kva_read_pod(eng, inode_va + o, v)) dst = v;
    };
    rd(ao, t.atime);
    rd(mo, t.mtime);
    rd(co, t.ctime);
    t.ok = (t.atime != 0 || t.mtime != 0 || t.ctime != 0);
    return t;
}

} // namespace lmpfs::linux
