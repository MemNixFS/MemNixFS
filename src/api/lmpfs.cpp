// lmpfs.cpp — public C API for MemNixFS. See lmpfs.h.
//
// Implementation strategy:
//   * `lmpfs_handle_t` is a heap-allocated struct holding the
//     std::unique_ptr<Engine> + a per-handle mutex. We don't expose the
//     Engine pointer directly because we want to be able to evolve its
//     internals without breaking ABI.
//   * All entry points wrap a `try { … } catch (const std::exception& e)`
//     boundary that stores the message in a thread-local string. We
//     NEVER let an exception cross the C-API boundary — that would be
//     undefined behaviour for FFI callers.
//   * Pointer-returning functions return NULL on failure. Numeric
//     functions return -1 (or 0 for bool-shaped APIs).
//
// References:
//   MemProcFS: vmm/vmmdll.h, vmm/vmmdll.c — same shape, prefixed VMMDLL_.
//              We'll add a thin VMMDLL_-prefixed shim on top of this API
//              in a follow-up so existing MemProcFS code targets us.
//
#define LMPFS_API_BUILDING 1
#include "api/lmpfs.h"
#include "api/lmpfs_plugin.h"

#include "app/engine.h"
#include "vfs/vfs.h"
#include "os/linux/kva_reader.h"
#include "formats/physical_layer.h"
#include "core/log.h"
#include "core/app_paths.h"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <dlfcn.h>
#endif

using namespace lmpfs;

// ---- thread-local error reporting -----------------------------------------
namespace {

thread_local std::string g_last_error;

void clear_last_error() { g_last_error.clear(); }
void set_last_error(const char* msg) {
    if (msg) g_last_error = msg;
    else     g_last_error.clear();
}
void set_last_error_fmt_what(const std::exception& e) { g_last_error = e.what(); }

} // anonymous

// ---- handle wrapper -------------------------------------------------------
//
// `lmpfs_handle_t` is just an Engine* cast through an opaque struct name.
// We used to wrap it in lmpfs_handle_impl { unique_ptr<Engine>, mutex },
// but that prevented Engine::create() from passing handles to plugins
// during VFS construction (the wrapper only existed in lmpfs_open). The
// mutex was unused anyway — Engine itself is thread-safe.
//
// Now the same handle is reachable from both paths:
//   * CLI:  Engine::create() runs the plugin scanner with `(this)`
//   * DLL:  lmpfs_open()    returns release()'d unique_ptr cast to handle

inline Engine* engine_from(lmpfs_handle_t h) {
    return reinterpret_cast<Engine*>(h);
}
inline lmpfs_handle_t handle_from(Engine* e) {
    return reinterpret_cast<lmpfs_handle_t>(e);
}

static Engine* check(lmpfs_handle_t h) {
    if (!h) { set_last_error("null handle"); return nullptr; }
    return engine_from(h);
}

// Forward declaration of the plugin loader — defined further down with
// the rest of the Plugin SDK code.
namespace { void scan_and_load_plugins(Engine*); }

// ---- library-wide ---------------------------------------------------------

extern "C" LMPFS_API const char* lmpfs_version(void) {
    // Mirror PROGRESS / ROADMAP: bumped per release.
#ifdef LMPFS_VERSION
    return LMPFS_VERSION;
#else
    return "0.37.1";
#endif
}

extern "C" LMPFS_API const char* lmpfs_last_error(void) {
    return g_last_error.c_str();
}

// ---- lifecycle ------------------------------------------------------------

extern "C" LMPFS_API lmpfs_handle_t lmpfs_open(const char* dump_path,
                                                const char* symbols_path)
{
    clear_last_error();
    try {
        if (!dump_path || !*dump_path) {
            set_last_error("lmpfs_open: dump_path is required");
            return nullptr;
        }
        Engine::Options o;
        o.dump_path = dump_path;
        if (symbols_path && *symbols_path) o.symbols_path = symbols_path;
        auto eng = Engine::create(o);
        if (!eng) {
            set_last_error("Engine::create returned null");
            return nullptr;
        }
        // Run the plugin scanner now that the engine is fully built.
        // (Defined further down; declared via forward decl up top.)
        scan_and_load_plugins(eng.get());
        return handle_from(eng.release());
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e);
        return nullptr;
    } catch (...) {
        set_last_error("lmpfs_open: unknown exception");
        return nullptr;
    }
}

extern "C" LMPFS_API void lmpfs_close(lmpfs_handle_t h) {
    if (!h) return;
    try { delete engine_from(h); }
    catch (...) { /* destructor must not propagate */ }
}

// ---- processes ------------------------------------------------------------

static void fill_process(lmpfs_process_t* out, const linux::Process& p) {
    out->pid     = p.pid;
    out->tgid    = p.tgid;
    out->ppid    = p.ppid;
    out->uid     = p.uid;
    out->mm_va   = p.mm;
    out->task_va = p.task_va;
    out->task_pa = p.task_pa;
    // comm is 16 bytes. Pad/truncate to fit while ensuring NUL termination.
    std::memset(out->comm, 0, sizeof(out->comm));
    std::size_t n = std::min<std::size_t>(p.comm.size(), sizeof(out->comm) - 1);
    std::memcpy(out->comm, p.comm.data(), n);
}

extern "C" LMPFS_API int lmpfs_process_count(lmpfs_handle_t h) {
    clear_last_error();
    auto* H = check(h); if (!H) return -1;
    try {
        return static_cast<int>(H->processes().size());
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e); return -1;
    }
}

extern "C" LMPFS_API int lmpfs_process_get(lmpfs_handle_t h, int index,
                                            lmpfs_process_t* out) {
    clear_last_error();
    auto* H = check(h); if (!H) return 0;
    if (!out) { set_last_error("lmpfs_process_get: out is null"); return 0; }
    try {
        const auto& v = H->processes();
        if (index < 0 || static_cast<std::size_t>(index) >= v.size()) {
            set_last_error("lmpfs_process_get: index out of range");
            return 0;
        }
        fill_process(out, v[index]);
        return 1;
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e); return 0;
    }
}

extern "C" LMPFS_API int lmpfs_process_find_by_name(lmpfs_handle_t h,
                                                     const char* name,
                                                     lmpfs_process_t* out) {
    clear_last_error();
    auto* H = check(h); if (!H) return 0;
    if (!name || !out) { set_last_error("null arg"); return 0; }
    try {
        for (const auto& p : H->processes()) {
            if (p.comm == name) { fill_process(out, p); return 1; }
        }
        return 0;
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e); return 0;
    }
}

extern "C" LMPFS_API int lmpfs_process_find_by_pid(lmpfs_handle_t h, uint32_t pid,
                                                    lmpfs_process_t* out) {
    clear_last_error();
    auto* H = check(h); if (!H) return 0;
    if (!out) { set_last_error("null out"); return 0; }
    try {
        for (const auto& p : H->processes()) {
            if (p.pid == pid) { fill_process(out, p); return 1; }
        }
        return 0;
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e); return 0;
    }
}

// ---- VFS ------------------------------------------------------------------

// Normalise a UTF-8 path (caller-supplied) to the form vfs::resolve expects:
// leading '/', forward-slash separators, no trailing slash (except for root).
static std::string normalize_path(const char* in) {
    if (!in || !*in) return "/";
    std::string s;
    s.reserve(std::strlen(in) + 1);
    if (in[0] != '/') s.push_back('/');
    for (const char* p = in; *p; ++p) {
        char c = *p;
        if (c == '\\') c = '/';
        // collapse repeated slashes
        if (c == '/' && !s.empty() && s.back() == '/') continue;
        s.push_back(c);
    }
    if (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

extern "C" LMPFS_API int lmpfs_vfs_list(lmpfs_handle_t h, const char* path,
                                         lmpfs_dir_entry_t** entries, int* count) {
    clear_last_error();
    if (entries) *entries = nullptr;
    if (count)   *count   = 0;
    auto* H = check(h); if (!H) return 0;
    if (!entries || !count) { set_last_error("null out args"); return 0; }
    try {
        auto node = vfs::resolve(H->vfs_root(), normalize_path(path));
        if (!node) { set_last_error("path not found"); return 0; }
        if (!node->is_dir()) { set_last_error("path is not a directory"); return 0; }
        auto kids = node->list();
        if (kids.empty()) { return 1; }     // empty dir is OK
        auto* arr = static_cast<lmpfs_dir_entry_t*>(
            std::calloc(kids.size(), sizeof(lmpfs_dir_entry_t)));
        if (!arr) { set_last_error("OOM"); return 0; }
        for (std::size_t i = 0; i < kids.size(); ++i) {
            const auto& e = kids[i];
            std::size_t n = std::min<std::size_t>(e.name.size(),
                                                   sizeof(arr[i].name) - 1);
            std::memcpy(arr[i].name, e.name.data(), n);
            arr[i].name[n]  = '\0';
            arr[i].is_dir   = e.node && e.node->is_dir() ? 1 : 0;
            // size() can be expensive on stream files (rare for directory
            // entries, but cheap-by-design — every StreamReader gives O(1)
            // size). Files we'd want to skip on listing already do that
            // internally (SizedLazyFileNode).
            arr[i].size     = arr[i].is_dir ? 0
                              : (e.node ? e.node->size() : 0);
        }
        *entries = arr;
        *count   = static_cast<int>(kids.size());
        return 1;
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e); return 0;
    }
}

extern "C" LMPFS_API void lmpfs_vfs_list_free(lmpfs_dir_entry_t* entries) {
    std::free(entries);
}

extern "C" LMPFS_API int64_t lmpfs_vfs_size(lmpfs_handle_t h, const char* path) {
    clear_last_error();
    auto* H = check(h); if (!H) return -1;
    try {
        auto node = vfs::resolve(H->vfs_root(), normalize_path(path));
        if (!node) { set_last_error("path not found"); return -1; }
        if (!node->is_file()) { set_last_error("path is not a file"); return -1; }
        return static_cast<int64_t>(node->size());
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e); return -1;
    }
}

extern "C" LMPFS_API int64_t lmpfs_vfs_read(lmpfs_handle_t h, const char* path,
                                             uint64_t offset, void* buf, size_t len) {
    clear_last_error();
    auto* H = check(h); if (!H) return -1;
    if (!buf || len == 0) return 0;
    try {
        auto node = vfs::resolve(H->vfs_root(), normalize_path(path));
        if (!node) { set_last_error("path not found"); return -1; }
        if (!node->is_file()) { set_last_error("path is not a file"); return -1; }
        std::size_t got = node->read(offset, buf, len);
        return static_cast<int64_t>(got);
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e); return -1;
    }
}

// ---- raw memory -----------------------------------------------------------

extern "C" LMPFS_API int64_t lmpfs_mem_read_phys(lmpfs_handle_t h, uint64_t pa,
                                                  void* buf, size_t len) {
    clear_last_error();
    auto* H = check(h); if (!H) return -1;
    if (!buf || len == 0) return 0;
    try {
        std::size_t got = H->phys().read(
            static_cast<PAddr>(pa), buf, len);
        return static_cast<int64_t>(got);
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e); return -1;
    }
}

extern "C" LMPFS_API int64_t lmpfs_mem_read_kva(lmpfs_handle_t h, uint64_t va,
                                                 void* buf, size_t len) {
    clear_last_error();
    auto* H = check(h); if (!H) return -1;
    if (!buf || len == 0) return 0;
    try {
        // kva_read is all-or-nothing per call but we can iterate page-by-page
        // to honour the sparse contract (unmapped → zero-filled).
        u8* p = static_cast<u8*>(buf);
        std::memset(p, 0, len);
        constexpr u64 kPage = 4096;
        std::size_t done = 0;
        while (done < len) {
            VAddr cur = va + done;
            u64 page_off = cur & (kPage - 1);
            std::size_t chunk = static_cast<std::size_t>(
                std::min<u64>(kPage - page_off, len - done));
            (void)linux::kva_read(*H, cur, p + done, chunk);
            done += chunk;
        }
        return static_cast<int64_t>(len);
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e); return -1;
    }
}

// ---- kernel context ------------------------------------------------------

extern "C" LMPFS_API int lmpfs_kernel_banner(lmpfs_handle_t h, char* out,
                                              size_t out_size) {
    clear_last_error();
    auto* H = check(h); if (!H) return -1;
    if (!out || out_size == 0) { set_last_error("null/empty out"); return -1; }
    try {
        const auto& b = H->kernel().banner;
        std::size_t n = std::min(b.size(), out_size - 1);
        std::memcpy(out, b.data(), n);
        out[n] = '\0';
        return static_cast<int>(n);
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e); return -1;
    }
}

extern "C" LMPFS_API uint64_t lmpfs_kernel_direct_map_base(lmpfs_handle_t h) {
    auto* H = check(h); if (!H) return 0;
    try { return H->kernel().direct_map_base; }
    catch (...) { return 0; }
}

extern "C" LMPFS_API int64_t lmpfs_kernel_kaslr_phys_shift(lmpfs_handle_t h) {
    auto* H = check(h); if (!H) return 0;
    try { return static_cast<int64_t>(H->kernel().kaslr_phys_shift); }
    catch (...) { return 0; }
}

// =========================================================================
//   Plugin SDK (v0.25 — Tier 6 completion)
// =========================================================================

namespace {

// Per-thread "currently-loading plugin" context. Set by the plugin loader
// just before calling the plugin's lmpfs_plugin_init(), cleared right
// after. lmpfs_plugin_add_file reads this to know which /plugins/<name>/
// subdir to attach to.
struct PluginLoadContext {
    Engine*            engine;          // raw — handle for callbacks = (lmpfs_handle_t)engine
    std::string        plugin_name;     // basename without extension
    vfs::DirNode*      plugin_dir;      // /plugins/<plugin_name>/
};
thread_local PluginLoadContext* g_plugin_ctx = nullptr;

// Ensure /plugins/ exists at the root; return the DirNode.
vfs::DirNode* ensure_plugins_root(Engine& eng) {
    auto root_np = eng.vfs_root();    // const ref to shared_ptr — copy ok
    auto* root   = dynamic_cast<vfs::DirNode*>(root_np.get());
    if (!root) return nullptr;
    if (auto existing = root->find("plugins")) {
        return dynamic_cast<vfs::DirNode*>(existing.get());
    }
    auto pdir = std::make_shared<vfs::DirNode>("plugins");
    root->add(pdir);
    return pdir.get();
}

// Walk `parent` creating intermediate `DirNode`s for each path component
// except the last. Returns the deepest DirNode + the leaf filename.
std::pair<vfs::DirNode*, std::string>
descend_for_file(vfs::DirNode* parent, const std::string& rel_path) {
    std::string acc;
    std::string last;
    std::vector<std::string> comps;
    for (char c : rel_path) {
        if (c == '/' || c == '\\') {
            if (!acc.empty()) comps.push_back(std::move(acc));
            acc.clear();
        } else acc.push_back(c);
    }
    if (acc.empty()) return { nullptr, "" };   // trailing slash
    last = std::move(acc);
    vfs::DirNode* cur = parent;
    for (const auto& dirname : comps) {
        auto existing = cur->find(dirname);
        vfs::DirNode* next = nullptr;
        if (existing && existing->is_dir()) {
            next = dynamic_cast<vfs::DirNode*>(existing.get());
        } else {
            auto fresh = std::make_shared<vfs::DirNode>(dirname);
            cur->add(fresh);
            next = fresh.get();
        }
        if (!next) return { nullptr, "" };
        cur = next;
    }
    return { cur, last };
}

} // anonymous

extern "C" LMPFS_API int lmpfs_plugin_add_file(lmpfs_handle_t /*engine*/,
                                                const char* path,
                                                lmpfs_plugin_file_producer producer) {
    clear_last_error();
    if (!g_plugin_ctx)   { set_last_error("lmpfs_plugin_add_file: not in a plugin-init scope"); return -1; }
    if (!path || !*path) { set_last_error("lmpfs_plugin_add_file: empty path"); return -1; }
    if (!producer)       { set_last_error("lmpfs_plugin_add_file: null producer"); return -1; }
    try {
        // Skip leading slash if user wrote "/foo/bar".
        const char* p = path;
        while (*p == '/' || *p == '\\') ++p;
        auto [parent, leaf] = descend_for_file(g_plugin_ctx->plugin_dir, p);
        if (!parent || leaf.empty()) {
            set_last_error("lmpfs_plugin_add_file: bad path"); return -1;
        }
        // Wrap the producer in a LazyFileNode whose ByteBuf-producing closure
        // calls the C function pointer. Capture the engine pointer (= the
        // opaque handle from the plugin's POV) — VFS lifetime ⊆ engine
        // lifetime so the pointer stays valid through every read.
        auto* eng = g_plugin_ctx->engine;
        parent->add(std::make_shared<vfs::LazyFileNode>(std::move(leaf),
            [eng, producer]() -> ByteBuf {
                lmpfs_plugin_buffer_t out{};
                int rc = producer(handle_from(eng), &out);
                if (rc != 0 || !out.data) return ByteBuf{};
                ByteBuf result(static_cast<u8*>(out.data),
                                static_cast<u8*>(out.data) + out.length);
                if (out.free_fn) out.free_fn(out.data);
                else             std::free(out.data);
                return result;
            }));
        return 0;
    } catch (const std::exception& e) {
        set_last_error_fmt_what(e); return -1;
    }
}

// ----------------------------------------------------------------------
// Plugin directory scanner.
// ----------------------------------------------------------------------
namespace {

// Cross-platform DLL handling.
#ifdef _WIN32
using lib_handle_t = HMODULE;
inline lib_handle_t load_lib(const std::filesystem::path& p) {
    return LoadLibraryW(p.wstring().c_str());
}
inline void* resolve_sym(lib_handle_t h, const char* name) {
    return reinterpret_cast<void*>(GetProcAddress(h, name));
}
inline void close_lib(lib_handle_t h) { FreeLibrary(h); }
constexpr const char* kPluginExt = ".dll";
#else
using lib_handle_t = void*;
inline lib_handle_t load_lib(const std::filesystem::path& p) {
    return dlopen(p.c_str(), RTLD_NOW | RTLD_LOCAL);
}
inline void* resolve_sym(lib_handle_t h, const char* name) {
    return dlsym(h, name);
}
inline void close_lib(lib_handle_t h) { dlclose(h); }
constexpr const char* kPluginExt = ".so";
#endif

// Compute the canonical plugin name: file stem without extension.
// `foo.plugin.dll` → `foo.plugin`; `core.dll` → `core`.
std::string plugin_name_from_path(const std::filesystem::path& p) {
    return p.stem().string();
}

// Try to load + initialise plugins from one directory.
int load_plugins_from(Engine* eng, vfs::DirNode* plugins_root,
                      const std::filesystem::path& dir) {
    std::error_code ec;
    log::info("plugin: scanning dir {}", dir.string());
    if (!std::filesystem::is_directory(dir, ec)) {
        log::info("plugin: {} is not a directory (skip)", dir.string());
        return 0;
    }
    int loaded = 0;
    for (auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        for (auto& c : ext) c = (char)std::tolower((unsigned char)c);
        log::info("plugin: candidate {} ext={}", entry.path().string(), ext);
        if (ext != kPluginExt) continue;

        auto lib = load_lib(entry.path());
        if (!lib) {
#ifdef _WIN32
            DWORD err = GetLastError();
            log::warn("plugin: failed to load {} (Windows error {})",
                       entry.path().string(), err);
#else
            log::warn("plugin: failed to load {}", entry.path().string());
#endif
            continue;
        }
        auto raw_init = resolve_sym(lib, "lmpfs_plugin_init");
        if (!raw_init) {
            log::warn("plugin: {} has no lmpfs_plugin_init export — skipping",
                       entry.path().string());
            close_lib(lib);
            continue;
        }
        auto init = reinterpret_cast<lmpfs_plugin_init_fn>(raw_init);

        std::string name = plugin_name_from_path(entry.path());
        // Create the plugin's /plugins/<name>/ subdir up front so the
        // plugin can find it (and we have somewhere to add children).
        auto sub = std::make_shared<vfs::DirNode>(name);
        plugins_root->add(sub);

        PluginLoadContext ctx{};
        ctx.engine      = eng;
        ctx.plugin_name = name;
        ctx.plugin_dir  = sub.get();
        g_plugin_ctx = &ctx;
        int rc = init(handle_from(eng));
        g_plugin_ctx = nullptr;
        if (rc != 0) {
            log::warn("plugin: {} init returned {} — keeping anyway",
                       name, rc);
        } else {
            log::info("plugin: loaded {} from {}", name,
                       entry.path().string());
            ++loaded;
        }
        // Deliberately KEEP the lib loaded — its code backs the producer
        // callbacks for the remainder of the engine's lifetime. Unloading
        // would crash on next read. The OS reclaims at process exit.
    }
    return loaded;
}

void scan_and_load_plugins(Engine* eng) {
    auto* plugins_root = ensure_plugins_root(*eng);
    if (!plugins_root) return;

    int total = 0;
    // 1) LMPFS_PLUGINS_DIR env var (semicolon-separated on Windows;
    //    colon-separated on POSIX). On Windows, ':' is part of drive
    //    letters (`C:\...`) and MUST NOT split the path.
    if (const char* env = std::getenv("LMPFS_PLUGINS_DIR")) {
#ifdef _WIN32
        const char kSep = ';';
#else
        const char kSep = ':';
#endif
        std::string acc;
        auto flush = [&](std::string& s) {
            if (s.empty()) return;
            total += load_plugins_from(eng, plugins_root, s);
            s.clear();
        };
        for (char c : std::string(env)) {
            if (c == kSep) flush(acc);
            else           acc.push_back(c);
        }
        flush(acc);
    }
    // 2) Default per-user dirs (same resolver as symbols + YARA rules).
    for (const auto& d : paths::user_dirs("plugins"))
        total += load_plugins_from(eng, plugins_root, d);
    if (total > 0) {
        log::info("plugin: loaded {} plugin(s) under /plugins/", total);
    }
    // Add a README explaining the conventions, even if no plugins loaded.
    static const char* readme =
        "/plugins/ — third-party MemNixFS plugins\n"
        "\n"
        "Each plugin DLL discovered at engine init registers files under\n"
        "/plugins/<plugin-name>/. The plugin DLL must export:\n"
        "\n"
        "    int lmpfs_plugin_init(lmpfs_handle_t engine);\n"
        "\n"
        "Discovery order:\n"
        "  1. $LMPFS_PLUGINS_DIR   (';'-separated on Windows, ':' on Linux)\n"
        "  2. Per-user plugins dir (same resolver as symbols + YARA rules):\n"
        "       Windows: %LOCALAPPDATA%\\MemNixFS\\plugins\\*.dll\n"
        "       Linux:   ~/.local/share/memnixfs/plugins/*.so\n"
        "                (or ~/.cache/lmpfs/plugins/)\n"
        "\n"
        "See src/api/lmpfs_plugin.h for the public ABI + a sample plugin.\n";
    auto readme_bytes = ByteBuf(readme, readme + std::strlen(readme));
    plugins_root->add(std::make_shared<vfs::LazyFileNode>("README.txt",
        [readme_bytes]() { return readme_bytes; }));
}

} // anonymous

// External entry point — exported from memnixfs.dll so that the CLI
// (memnixfs.exe) can call it after Engine::create. The CLI's WinFsp
// mount + tree/cat then reach the same VFS that Engine::create
// constructs, with /plugins/<plugin>/ wired up.
extern "C" LMPFS_API void lmpfs_internal_scan_plugins(lmpfs::Engine* eng) {
    if (!eng) {
        log::info("plugin: scan called with null engine — nothing to do");
        return;
    }
    log::info("plugin: scan_plugins entered (LMPFS_PLUGINS_DIR={})",
              std::getenv("LMPFS_PLUGINS_DIR") ? std::getenv("LMPFS_PLUGINS_DIR") : "(unset)");
    try { scan_and_load_plugins(eng); }
    catch (const std::exception& e) {
        log::warn("plugin: scan failed — {}", e.what());
    } catch (...) {
        log::warn("plugin: scan failed (unknown)");
    }
}
