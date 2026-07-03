// app_paths.cpp — see header for the layout contract.
#include "core/app_paths.h"
#include <cstdlib>

namespace lmpfs::paths {
namespace fs = std::filesystem;

namespace detail {

std::vector<fs::path> user_dirs_impl(bool windows, const EnvFn& env, std::string_view sub) {
    std::vector<fs::path> out;
    const std::string s(sub);
    if (windows) {
        if (const char* la = env("LOCALAPPDATA")) out.emplace_back(fs::path(la) / "MemNixFS" / s);
        if (const char* ad = env("APPDATA"))      out.emplace_back(fs::path(ad) / "MemNixFS" / s);
    } else {
        // XDG-correct data dir (persistent, user-authored).
        if (const char* xdg = env("XDG_DATA_HOME"))
            out.emplace_back(fs::path(xdg) / "memnixfs" / s);
        else if (const char* home = env("HOME"))
            out.emplace_back(fs::path(home) / ".local" / "share" / "memnixfs" / s);
        // Legacy cache root — where symbols have always lived and where users
        // intuitively drop files next to them. Kept so nothing already working
        // stops working.
        if (const char* xdgc = env("XDG_CACHE_HOME"))
            out.emplace_back(fs::path(xdgc) / "lmpfs" / s);
        else if (const char* home = env("HOME"))
            out.emplace_back(fs::path(home) / ".cache" / "lmpfs" / s);
    }
    return out;
}

fs::path user_write_dir_impl(bool windows, bool cache, const EnvFn& env, std::string_view sub) {
    const std::string s(sub);
    if (windows) {
        if (const char* la = env("LOCALAPPDATA")) return fs::path(la) / "MemNixFS" / s;
        if (const char* ad = env("APPDATA"))      return fs::path(ad) / "MemNixFS" / s;
        return {};
    }
    if (cache) {
        if (const char* xdgc = env("XDG_CACHE_HOME")) return fs::path(xdgc) / "lmpfs" / s;
        if (const char* home = env("HOME"))           return fs::path(home) / ".cache" / "lmpfs" / s;
    } else {
        if (const char* xdg = env("XDG_DATA_HOME")) return fs::path(xdg) / "memnixfs" / s;
        if (const char* home = env("HOME"))         return fs::path(home) / ".local" / "share" / "memnixfs" / s;
    }
    return {};
}

std::string user_dir_hint_impl(bool windows, std::string_view sub) {
    const std::string s(sub);
    if (windows) return "%LOCALAPPDATA%\\MemNixFS\\" + s + "\\";
    return "~/.local/share/memnixfs/" + s + "/ (or ~/.cache/lmpfs/" + s + "/)";
}

} // namespace detail

namespace {
// getenv that treats an empty value as unset (empty %VAR% / $VAR is useless).
const char* real_env(const char* key) {
    const char* v = std::getenv(key);
    return (v && *v) ? v : nullptr;
}
#ifdef _WIN32
constexpr bool kWindows = true;
#else
constexpr bool kWindows = false;
#endif
} // namespace

std::vector<fs::path> user_dirs(std::string_view sub) {
    return detail::user_dirs_impl(kWindows, real_env, sub);
}
fs::path user_write_dir(std::string_view sub, bool cache) {
    return detail::user_write_dir_impl(kWindows, cache, real_env, sub);
}
std::string user_dir_hint(std::string_view sub) {
    return detail::user_dir_hint_impl(kWindows, sub);
}

} // namespace lmpfs::paths
