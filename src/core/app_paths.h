#pragma once
// app_paths.h — the single place that defines MemNixFS's per-user directories,
// so every subsystem (symbols cache, YARA rules, plugins) resolves them the
// SAME way on Windows and Linux instead of each rolling its own getenv() logic.
//
// Layout (subsystem folder <sub> = "symbols" | "yara" | "plugins"):
//   Windows:  %LOCALAPPDATA%\MemNixFS\<sub>\   (+ %APPDATA%\MemNixFS\<sub>\)
//   Linux:    $XDG_DATA_HOME/memnixfs/<sub>/   or  ~/.local/share/memnixfs/<sub>/
//             $XDG_CACHE_HOME/lmpfs/<sub>/     or  ~/.cache/lmpfs/<sub>/   (legacy)
//
// Both Linux roots are searched so files already living under the long-standing
// ~/.cache/lmpfs are still found, while the XDG-correct data dir works going
// forward.
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace lmpfs::paths {

// Per-user directories to SEARCH for a subsystem's drop-in files, highest
// precedence first. Existence is NOT guaranteed — callers skip missing dirs.
// Callers add their own env-var / CLI overrides ahead of these.
std::vector<std::filesystem::path> user_dirs(std::string_view sub);

// Directory to CREATE/WRITE into for a subsystem (e.g. where fetched symbols
// are saved). `cache == true` selects the cache root (regenerable data),
// `false` the data root (user-authored data). On Windows both map to
// %LOCALAPPDATA%\MemNixFS\<sub>. Returns empty if no home dir is known.
std::filesystem::path user_write_dir(std::string_view sub, bool cache);

// Short, platform-correct human hint for help / README text.
std::string user_dir_hint(std::string_view sub);

// Platform-parameterised cores — exposed so the path logic can be unit-tested
// on ANY host (both branches), independent of where the test runs. `env`
// returns the value for a variable or nullptr if unset/empty. The public
// functions above just call these with the real platform + std::getenv.
namespace detail {
using EnvFn = std::function<const char*(const char*)>;
std::vector<std::filesystem::path>
    user_dirs_impl(bool windows, const EnvFn& env, std::string_view sub);
std::filesystem::path
    user_write_dir_impl(bool windows, bool cache, const EnvFn& env, std::string_view sub);
std::string user_dir_hint_impl(bool windows, std::string_view sub);
} // namespace detail

} // namespace lmpfs::paths
