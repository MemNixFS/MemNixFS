// app_paths_test.cpp — verifies the per-user dir resolver for BOTH platforms on
// any host (via the detail:: seam), so the Linux paths are actually tested even
// when the suite runs on Windows.
#include "core/app_paths.h"

#include <cstdio>
#include <map>
#include <string>

namespace fs = std::filesystem;
using lmpfs::paths::detail::user_dirs_impl;
using lmpfs::paths::detail::user_write_dir_impl;
using lmpfs::paths::detail::user_dir_hint_impl;
using lmpfs::paths::detail::EnvFn;

static int g_failures = 0;
#define CHECK(cond, msg)                                      \
    do {                                                      \
        if (cond) std::printf("  ok: %s\n", (msg));           \
        else { std::printf("FAIL: %s\n", (msg)); ++g_failures; } \
    } while (0)

// Fake environment from a fixed map (nullptr for missing/empty keys).
static EnvFn make_env(std::map<std::string, std::string> m) {
    return [m = std::move(m)](const char* k) -> const char* {
        auto it = m.find(k);
        return (it != m.end() && !it->second.empty()) ? it->second.c_str() : nullptr;
    };
}

static bool has(const std::vector<fs::path>& v, const fs::path& p) {
    for (const auto& e : v) if (e == p) return true;
    return false;
}

int main() {
    // Linux, HOME only: data dir first, then the legacy cache dir.
    {
        auto env = make_env({{"HOME", "/home/u"}});
        auto d = user_dirs_impl(/*windows=*/false, env, "yara");
        CHECK(d.size() == 2, "linux/yara: two search dirs (data + cache)");
        CHECK(!d.empty() && d[0] == fs::path("/home/u/.local/share/memnixfs/yara"),
              "linux/yara: XDG data dir first");
        CHECK(has(d, fs::path("/home/u/.cache/lmpfs/yara")),
              "linux/yara: legacy ~/.cache/lmpfs/yara IS searched (issue #3 reporter's path)");
    }
    // Linux, XDG overrides win and suppress the ~/ fallbacks.
    {
        auto env = make_env({{"HOME", "/home/u"},
                             {"XDG_DATA_HOME", "/xdg/data"},
                             {"XDG_CACHE_HOME", "/xdg/cache"}});
        auto d = user_dirs_impl(false, env, "symbols");
        CHECK(has(d, fs::path("/xdg/data/memnixfs/symbols")), "linux/symbols: XDG_DATA_HOME honored");
        CHECK(has(d, fs::path("/xdg/cache/lmpfs/symbols")),   "linux/symbols: XDG_CACHE_HOME honored");
        CHECK(!has(d, fs::path("/home/u/.local/share/memnixfs/symbols")),
              "linux/symbols: XDG_DATA_HOME suppresses ~/.local/share fallback");
    }
    // Windows, LOCALAPPDATA.
    {
        auto env = make_env({{"LOCALAPPDATA", "C:\\Users\\u\\AppData\\Local"}});
        auto d = user_dirs_impl(/*windows=*/true, env, "plugins");
        CHECK(!d.empty() &&
              d[0] == fs::path("C:\\Users\\u\\AppData\\Local") / "MemNixFS" / "plugins",
              "windows/plugins: %LOCALAPPDATA%\\MemNixFS\\plugins");
    }
    // No home dir at all → empty, no crash.
    {
        auto env = make_env({});
        CHECK(user_dirs_impl(false, env, "yara").empty(), "linux/no-HOME: empty search list");
        CHECK(user_write_dir_impl(false, false, env, "yara").empty(), "linux/no-HOME: empty write dir");
    }
    // Write dirs: symbols → cache root; yara → data root.
    {
        auto env = make_env({{"HOME", "/home/u"}});
        CHECK(user_write_dir_impl(false, /*cache=*/true, env, "symbols")
                  == fs::path("/home/u/.cache/lmpfs/symbols"),
              "linux write: symbols (cache) -> ~/.cache/lmpfs/symbols");
        CHECK(user_write_dir_impl(false, /*cache=*/false, env, "yara")
                  == fs::path("/home/u/.local/share/memnixfs/yara"),
              "linux write: yara (data) -> ~/.local/share/memnixfs/yara");
    }
    {
        auto env = make_env({{"LOCALAPPDATA", "C:\\LA"}});
        CHECK(user_write_dir_impl(true, true, env, "symbols")
                  == fs::path("C:\\LA") / "MemNixFS" / "symbols",
              "windows write: symbols -> %LOCALAPPDATA%\\MemNixFS\\symbols");
    }
    // Hints name the right convention per platform.
    {
        CHECK(user_dir_hint_impl(false, "yara").find(".cache/lmpfs/yara") != std::string::npos,
              "linux hint mentions the cache dir");
        CHECK(user_dir_hint_impl(true, "yara").find("LOCALAPPDATA") != std::string::npos,
              "windows hint mentions LOCALAPPDATA");
    }

    if (g_failures) { std::printf("\n== %d failure(s) ==\n", g_failures); return 1; }
    std::printf("\nall app_paths tests passed\n");
    return 0;
}
