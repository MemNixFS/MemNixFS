// timeline.cpp - see header.
#include "os/linux/timeline.h"
#include "os/linux/dmesg.h"
#include "os/linux/crash_journal.h"
#include "os/linux/bash_history.h"
#include "os/linux/ebpf.h"
#include "os/linux/findevil.h"
#include "os/linux/netstat.h"
#include "os/linux/pagecache.h"
#include "os/linux/kva_reader.h"
#include "os/linux/csv_export.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "symbols/kallsyms.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <ctime>
#include <unordered_map>

namespace lmpfs::linux {

namespace {

// Plausibility window for wall-clock timestamps recovered from kernel memory.
// Anything outside [2010, ~2040) is treated as a garbage/uninitialised field
// (overwritten inode slab, sign-extended junk) and dropped rather than emitted.
constexpr i64 kMinEpoch = 1262304000;   // 2010-01-01 UTC
constexpr i64 kMaxEpoch = 2240000000;   // ~2040-12 UTC

// Unix seconds → "YYYY-MM-DD HH:MM:SS UTC" (matches the shell-history format so
// wall-clock rows from every source sort and read consistently).
std::string iso_utc(i64 secs) {
    std::time_t t = static_cast<std::time_t>(secs);
    std::tm* tm = std::gmtime(&t);
    if (!tm) return {};
    char b[32];
    std::strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S UTC", tm);
    return std::string(b);
}

VAddr resolve_kernel_sym(const Engine& eng, const char* name) {
    if (auto* s = eng.isf().find_symbol(name)) return s->address;  // KASLR-resilient
    const auto& ks = eng.kallsyms();
    if (ks.ok) for (const auto& s : ks.symbols) if (s.name == name) return s.address;
    return 0;
}

// Wall-clock seconds at boot (UTC), or 0 if not derivable. With it we can
// convert every boot-relative event (process starts, dmesg, eBPF) to absolute
// time so they interleave with wall-clock events (shell, file MAC) on ONE true
// chronological axis — the whole point of a timeline. Source: the kernel
// timekeeper — boot_epoch = CLOCK_REALTIME(now) - CLOCK_MONOTONIC(now) =
// xtime_sec - ktime_sec. Needs the `tk_core` symbol (so it works on
// symbol-rich/kallsyms dumps; on a pure BTF dump with no symbol addresses we
// fall back to a boot-relative axis). Sanity-gated to a plausible epoch window
// so a layout mismatch degrades gracefully instead of producing garbage times.
i64 compute_boot_epoch(const Engine& eng) {
    VAddr tk = resolve_kernel_sym(eng, "tk_core");
    if (!tk) { log::debug("timeline: tk_core symbol not found — boot-relative axis"); return 0; }
    const auto& isf = eng.isf();

    // `xtime_sec` (CLOCK_REALTIME) and `ktime_sec` (CLOCK_MONOTONIC ≈ uptime)
    // live in `struct timekeeper`, which IS a named type → reliable offsets.
    u64 xt_off = 0, kt_off = 0;
    try {
        xt_off = isf.field_offset("timekeeper", "xtime_sec");
        kt_off = isf.field_offset("timekeeper", "ktime_sec");
    } catch (...) {
        log::debug("timeline: timekeeper.xtime_sec/ktime_sec not in ISF — boot-relative axis");
        return 0;
    }

    // `tk_core` is an ANONYMOUS struct `{ seqcount_raw_spinlock_t seq; struct
    // timekeeper timekeeper; }`, so there's no "tk_core" type to ask for the
    // `timekeeper` offset. Derive it: it sits right after `seq`, 8-byte aligned.
    // seqcount_raw_spinlock_t is 4 B (no lockdep) → timekeeper at +8; lockdep
    // builds are larger → try a few candidates and accept the one whose values
    // are self-consistent (realtime > monotonic > 0, epoch in a plausible
    // window). A wrong offset reads unrelated bytes and fails that gate, so this
    // degrades to the boot-relative axis instead of inventing timestamps.
    std::vector<u64> cands;
    try { cands.push_back((isf.type_size("seqcount_raw_spinlock_t") + 7) & ~7ull); } catch (...) {}
    for (u64 c : {8ull, 16ull, 24ull, 0ull}) cands.push_back(c);
    for (u64 tk_off : cands) {
        u64 xtime = 0, ktime = 0;
        if (!kva_read_pod(eng, tk + tk_off + xt_off, xtime)) continue;
        if (!kva_read_pod(eng, tk + tk_off + kt_off, ktime)) continue;
        i64 epoch = static_cast<i64>(xtime) - static_cast<i64>(ktime);
        const bool sane = xtime > ktime && ktime > 0 &&
                          ktime < 2'000'000'000ULL &&   // uptime < ~63 years
                          epoch >= kMinEpoch && epoch <= kMaxEpoch;
        if (sane) {
            log::info("timeline: boot epoch = {} ({}); uptime={}s; "
                      "boot-relative events anchored to absolute time "
                      "(timekeeper @ tk_core+{})",
                      epoch, iso_utc(epoch), ktime, tk_off);
            return epoch;
        }
    }
    log::debug("timeline: no self-consistent timekeeper offset — boot-relative axis");
    return 0;
}

// Sort key + display for a DATED wall-clock event (absolute Unix seconds, with
// optional sub-second nsec for ordering kernel events within a second). All
// dated events — whatever the source — share the "1|" prefix so they sort into
// one chronological stream. `boot_note` is appended to the display for events
// derived from a boot-relative clock (e.g. " (boot+43.9s)").
std::pair<std::string, std::string> dated_keys(i64 epoch_secs, u64 nsec,
                                               const std::string& boot_note = {}) {
    std::string iso = iso_utc(epoch_secs);
    std::string sort = fmt::format("1|{}.{:09}", iso, nsec);
    std::string disp = boot_note.empty() ? iso : iso + " " + boot_note;
    return {sort, disp};
}

// Parse a dmesg line "[<sec>.<usec>] <text>" into numeric boot-relative time +
// the message text. `ok` is false when there's no leading timestamp.
struct DmesgLine { bool ok = false; u64 sec = 0; u64 usec = 0; std::string text; };
DmesgLine split_dmesg_line(const std::string& line) {
    DmesgLine d;
    if (line.size() < 4 || line[0] != '[') return d;
    auto close = line.find(']');
    if (close == std::string::npos) return d;
    auto dot = line.find('.', 1);
    if (dot == std::string::npos || dot >= close) return d;
    std::string sec = line.substr(1, dot - 1);
    std::string usec = line.substr(dot + 1, close - dot - 1);
    while (!sec.empty() && sec.front() == ' ') sec.erase(sec.begin());
    try { d.sec = std::stoull(sec); d.usec = std::stoull(usec); }
    catch (...) { return d; }
    std::string tail = (close + 1 < line.size()) ? line.substr(close + 1) : std::string{};
    while (!tail.empty() && tail.front() == ' ') tail.erase(tail.begin());
    d.text = std::move(tail);
    d.ok = true;
    return d;
}

// Boot-relative fallback key/display, used only when the boot epoch is unknown
// (then boot events form a leading "0|" block before the wall-clock "1|" axis).
std::pair<std::string, std::string> boot_rel_keys(u64 sec, u64 nsec) {
    return { fmt::format("0|{:012}.{:09}", sec, nsec),
             fmt::format("boot+{}.{:09}s", sec, nsec) };
}

// Re-key an event that another module built with the legacy scheme
// ("0000-boot+<sec>.<usec>" for boot-relative, anything else = undated) onto
// the unified axis used here. Boot-relative rows get anchored to absolute time
// when the boot epoch is known; undated rows go to the trailing "2|" bucket.
void rekey_legacy_event(TimelineEvent& e, i64 boot_epoch) {
    if (e.sort_key.rfind("0000-boot+", 0) == 0) {
        std::string rest = e.sort_key.substr(10);  // strip "0000-boot+"
        auto dot = rest.find('.');
        u64 sec = 0, usec = 0;
        try {
            sec = std::stoull(rest.substr(0, dot));
            if (dot != std::string::npos) usec = std::stoull(rest.substr(dot + 1));
        } catch (...) {}
        if (boot_epoch) {
            auto [k, d] = dated_keys(boot_epoch + (i64)sec, usec * 1000,
                                     fmt::format("(boot+{}.{:06}s)", sec, usec));
            e.sort_key = std::move(k); e.display_time = std::move(d);
        } else {
            auto [k, d] = boot_rel_keys(sec, usec * 1000);
            e.sort_key = std::move(k); e.display_time = std::move(d);
        }
    } else {
        // Undated (no boot-relative stamp recovered) → trailing snapshot bucket,
        // preserving whatever display_time the source provided.
        e.sort_key = "2|crash-" + e.sort_key;
    }
}

std::string socket_proto(const SocketInfo& s) {
    switch (s.proto) {
    case SocketInfo::P_TCP: return "tcp";
    case SocketInfo::P_UDP: return "udp";
    case SocketInfo::P_RAW: return "raw";
    case SocketInfo::P_UNIX: return "unix";
    }
    return "unknown";
}

std::string socket_state(const SocketInfo& s) {
    switch (s.state) {
    case SocketInfo::S_ESTABLISHED: return "ESTABLISHED";
    case SocketInfo::S_SYN_SENT: return "SYN_SENT";
    case SocketInfo::S_SYN_RECV: return "SYN_RECV";
    case SocketInfo::S_FIN_WAIT1: return "FIN_WAIT1";
    case SocketInfo::S_FIN_WAIT2: return "FIN_WAIT2";
    case SocketInfo::S_TIME_WAIT: return "TIME_WAIT";
    case SocketInfo::S_CLOSE: return "CLOSE";
    case SocketInfo::S_CLOSE_WAIT: return "CLOSE_WAIT";
    case SocketInfo::S_LAST_ACK: return "LAST_ACK";
    case SocketInfo::S_LISTEN: return "LISTEN";
    case SocketInfo::S_CLOSING: return "CLOSING";
    case SocketInfo::S_NEW_SYN_RECV: return "NEW_SYN_RECV";
    default: return "UNKNOWN";
    }
}

std::string ipv4(const std::array<u8, 16>& a) {
    return fmt::format("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
}

std::string endpoint(const SocketInfo& s, bool remote) {
    const auto& a = remote ? s.remote_addr : s.local_addr;
    u16 port = remote ? s.remote_port : s.local_port;
    if (s.family == SocketInfo::AF_INET4)
        return fmt::format("{}:{}", ipv4(a), port);
    if (s.family == SocketInfo::AF_INET6)
        return fmt::format("[{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}]:{}",
                           a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                           a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
                           port);
    return port ? fmt::format("?:{}", port) : "?";
}

std::string nz(const std::string& s, const char* fallback = "-") {
    return s.empty() ? std::string(fallback) : s;
}

bool domain_match(const TimelineEvent& e, const std::string& domain) {
    if (domain == "all") return true;
    if (domain == "process") return e.type == "PROC";
    if (domain == "network") return e.type == "NET";
    if (domain == "shell") return e.type == "SHELL";
    if (domain == "kernel") return e.type == "KERN";
    if (domain == "findevil") return e.type == "EVIL";
    return false;
}

std::vector<TimelineEvent> filter_domain(std::vector<TimelineEvent> ev,
                                         const std::string& domain) {
    ev.erase(std::remove_if(ev.begin(), ev.end(),
        [&](const TimelineEvent& e) { return !domain_match(e, domain); }),
        ev.end());
    return ev;
}

std::string render_timeline_txt(const std::vector<TimelineEvent>& ev,
                                const std::string& path,
                                const std::string& note) {
    std::string out;
    out.reserve(64 * 1024);
    out += fmt::format("# {} - normalized forensic timeline\n", path);
    out += "# Dated rows are sorted into ONE absolute-UTC stream. Boot-relative\n";
    out += "# events (process starts, dmesg, eBPF) are anchored via the kernel\n";
    out += "# timekeeper and tagged '(boot+N.Ms)'; if the boot epoch can't be\n";
    out += "# derived they instead lead as a 'boot+N.Ms' block before the UTC rows.\n";
    out += "# 'snapshot-time-unavailable' rows (current sockets / FindEvil) have no\n";
    out += "# recoverable timestamp and trail at the very end — current state, not\n";
    out += "# history.\n";
    if (!note.empty()) out += "# " + note + "\n";
    out += fmt::format("# {} events total.\n#\n", ev.size());
    out += "# time                                        type   action    pid     uid   source      actor                  object            conf     summary\n";
    out += "# ------------------------------------------+------+---------+-------+-----+-----------+----------------------+-----------------+--------+--------\n";
    for (const auto& e : ev) {
        out += fmt::format("  {:<42}  {:<5}  {:<8}  {:>6}  {:>4}  {:<10}  {:<22}  {:<16}  {:<7}  {}\n",
                           e.display_time, nz(e.type), nz(e.action), e.pid, e.uid,
                           e.source, e.actor, nz(e.object), nz(e.confidence), e.summary);
    }
    return out;
}

std::string render_timeline_csv(const std::vector<TimelineEvent>& ev) {
    std::string out;
    out.reserve(64 * 1024);
    out += "time,type,action,pid,uid,source,actor,object,confidence,summary\r\n";
    for (const auto& e : ev) {
        out += fmt::format("{},{},{},{},{},{},{},{},{},{}\r\n",
                           csv_quote(e.display_time),
                           csv_quote(e.type),
                           csv_quote(e.action),
                           e.pid,
                           e.uid,
                           csv_quote(e.source),
                           csv_quote(e.actor),
                           csv_quote(e.object),
                           csv_quote(e.confidence),
                           csv_quote(e.summary));
    }
    return out;
}

} // namespace

std::vector<TimelineEvent> build_timeline(const Engine& eng) {
    std::vector<TimelineEvent> ev;

    // Anchor for converting boot-relative clocks to absolute UTC (0 = unknown →
    // boot-relative events keep a leading "0|" axis; see compute_boot_epoch).
    const i64 boot_epoch = compute_boot_epoch(eng);

    {
        u64 sb_off = 0;
        const char* field = nullptr;
        for (const char* cand : {"start_boottime", "start_time", "real_start_time"}) {
            try { sb_off = eng.isf().field_offset("task_struct", cand); field = cand; break; }
            catch (...) {}
        }
        if (sb_off) {
            const u64 dmap = eng.kernel().direct_map_base;
            std::unordered_map<u32, std::string> comm_by_pid;
            for (const auto& p : eng.processes()) comm_by_pid[p.pid] = p.comm;
            for (const auto& p : eng.processes()) {
                PAddr tpa = p.task_pa;
                if (tpa == 0 && p.task_va && dmap && p.task_va > dmap)
                    tpa = static_cast<PAddr>(p.task_va - dmap);
                if (tpa == 0) continue;
                u64 ns = 0;
                if (eng.phys().read(tpa + sb_off, &ns, 8) != 8) continue;
                if (ns == 0) continue;
                u64 sec = ns / 1'000'000'000ULL, nsec = ns % 1'000'000'000ULL;
                TimelineEvent e{};
                if (boot_epoch) {
                    auto [k, d] = dated_keys(boot_epoch + (i64)sec, nsec,
                                             fmt::format("(boot+{}.{:03}s)", sec, nsec / 1000000));
                    e.sort_key = std::move(k); e.display_time = std::move(d);
                } else {
                    auto [k, d] = boot_rel_keys(sec, nsec);
                    e.sort_key = std::move(k); e.display_time = std::move(d);
                }
                e.source       = "proc";
                e.type         = "PROC";
                e.action       = "START";
                e.pid          = p.pid;
                e.uid          = p.uid;
                e.object       = p.comm;
                e.confidence   = "high";
                auto it_parent = comm_by_pid.find(p.ppid);
                e.actor        = fmt::format("pid={} ppid={}{} uid={}",
                    p.pid, p.ppid,
                    it_parent == comm_by_pid.end() ? "" : "/" + it_parent->second,
                    p.uid);
                e.summary      = fmt::format("process started: {}", p.comm);
                ev.push_back(std::move(e));
            }
            log::debug("timeline: process starts via task_struct.{}", field);
        } else {
            log::debug("timeline: no task_struct start-time field in ISF");
        }
    }

    try {
        ByteBuf dm = format_dmesg(eng);
        std::string text(dm.begin(), dm.end());
        std::size_t pos = 0;
        while (pos < text.size()) {
            std::size_t eol = text.find('\n', pos);
            std::string line = text.substr(pos,
                eol == std::string::npos ? std::string::npos : eol - pos);
            pos = (eol == std::string::npos) ? text.size() : eol + 1;
            DmesgLine d = split_dmesg_line(line);
            if (!d.ok) continue;
            TimelineEvent e{};
            if (boot_epoch) {
                auto [k, disp] = dated_keys(boot_epoch + (i64)d.sec, d.usec * 1000,
                                            fmt::format("(boot+{}.{:06}s)", d.sec, d.usec));
                e.sort_key = std::move(k); e.display_time = std::move(disp);
            } else {
                auto [k, disp] = boot_rel_keys(d.sec, d.usec * 1000);
                e.sort_key = std::move(k); e.display_time = std::move(disp);
            }
            e.source       = "dmesg";
            e.type         = "KERN";
            e.action       = "EVENT";
            e.object       = "dmesg";
            e.confidence   = "high";
            e.actor        = "kernel";
            e.summary      = d.text;
            ev.push_back(std::move(e));
        }
    } catch (...) {}

    try {
        auto crash = collect_crash_log_timeline_events(eng);
        for (auto& e : crash) {
            if (e.type.empty()) e.type = "KERN";
            if (e.action.empty()) e.action = "EVENT";
            if (e.object.empty()) e.object = e.source.empty() ? "log" : e.source;
            if (e.confidence.empty()) e.confidence = "high";
            rekey_legacy_event(e, boot_epoch);   // onto the unified axis
        }
        ev.insert(ev.end(), crash.begin(), crash.end());
    } catch (...) {}

    for (const auto& p : eng.processes()) {
        std::vector<ShellCmd> cmds;
        try { cmds = scan_shell_history(eng, p); } catch (...) { continue; }
        for (const auto& c : cmds) {
            if (c.timestamp.empty()) continue;
            TimelineEvent e{};
            // Shell timestamps are already "YYYY-MM-DD HH:MM:SS UTC"; key them on
            // the same unified "1|<iso>.<nsec>" axis (nsec=0) as every other
            // dated source so commands interleave with process starts / files.
            e.sort_key     = "1|" + c.timestamp + ".000000000";
            e.display_time = c.timestamp;
            e.source       = "shell";
            e.type         = "SHELL";
            e.action       = "CMD";
            e.pid          = p.pid;
            e.uid          = p.uid;
            e.object       = c.source;
            e.confidence   = "high";
            e.actor        = fmt::format("pid={} uid={} {}", p.pid, p.uid, c.source);
            e.summary      = c.command;
            ev.push_back(std::move(e));
        }
    }

    // ---- filesystem MAC times from cached inodes ----
    // The backbone of a real forensic timeline: every cached regular file with
    // a resolved path contributes its mtime (data modified) and ctime (inode
    // metadata changed) as wall-clock UTC events. This is the single biggest
    // source of "what happened, when" detail — without it the timeline only had
    // process starts + a handful of kernel/shell rows. atime is omitted: it is
    // both noisy and unreliable (relatime/noatime mounts). Capped to the most
    // RECENT kFsCap events so timeline.txt stays usable on a big page cache.
    try {
        constexpr std::size_t kFsCap = 8000;
        std::vector<TimelineEvent> fs_ev;
        for (const auto& ci : enumerate_cached_inodes(eng)) {
            if ((ci.i_mode & 0170000) != 0100000) continue;  // S_IFREG only
            if (ci.path.empty()) continue;                   // need a path
            auto t = read_inode_mac_times(eng, ci.inode_va);
            if (!t.ok) continue;
            auto add = [&](i64 secs, const char* action, const char* verb) {
                if (secs < kMinEpoch || secs > kMaxEpoch) return;
                TimelineEvent e{};
                auto [k, d] = dated_keys(secs, 0);
                e.sort_key     = std::move(k);
                e.display_time = std::move(d);
                e.source       = "fs";
                e.type         = "FILE";
                e.action       = action;
                e.object       = ci.path;
                e.confidence   = "high";
                e.actor        = fmt::format("{} ino={}",
                                             ci.sb_fs.empty() ? "fs" : ci.sb_fs, ci.i_ino);
                e.summary      = fmt::format("{} {}", verb, ci.path);
                fs_ev.push_back(std::move(e));
            };
            add(t.mtime, "MTIME", "modified");
            add(t.ctime, "CTIME", "inode-changed");
        }
        if (fs_ev.size() > kFsCap) {
            // Keep the most recent kFsCap (descending by sort_key = time).
            std::partial_sort(fs_ev.begin(), fs_ev.begin() + kFsCap, fs_ev.end(),
                [](const TimelineEvent& a, const TimelineEvent& b) {
                    return a.sort_key > b.sort_key;
                });
            fs_ev.resize(kFsCap);
            log::debug("timeline: file MAC events capped to most-recent {}", kFsCap);
        }
        ev.insert(ev.end(),
                  std::make_move_iterator(fs_ev.begin()),
                  std::make_move_iterator(fs_ev.end()));
    } catch (...) {}

    try {
        auto progs = enumerate_bpf_programs(eng);
        for (const auto& bp : progs) {
            if (bp.load_time_ns == 0) continue;
            u64 sec  = bp.load_time_ns / 1'000'000'000ULL;
            u64 nsec = bp.load_time_ns % 1'000'000'000ULL;
            TimelineEvent e{};
            if (boot_epoch) {
                auto [k, d] = dated_keys(boot_epoch + (i64)sec, nsec,
                                         fmt::format("(boot+{}.{:03}s)", sec, nsec / 1000000));
                e.sort_key = std::move(k); e.display_time = std::move(d);
            } else {
                auto [k, d] = boot_rel_keys(sec, nsec);
                e.sort_key = std::move(k); e.display_time = std::move(d);
            }
            e.source       = "ebpf";
            e.type         = "KERN";
            e.action       = "LOAD";
            e.object       = bp.name.empty() ? "ebpf" : bp.name;
            e.confidence   = "high";
            e.actor        = fmt::format("prog id={} type={}", bp.id, bpf_prog_type_name(bp.type));
            e.summary      = fmt::format("loaded {}{}",
                bp.name.empty() ? "(unnamed)" : bp.name,
                bp.tag_hex.empty() ? "" : " tag=" + bp.tag_hex);
            ev.push_back(std::move(e));
        }
    } catch (...) {}

    try {
        auto sockets = enumerate_all_sockets(eng);
        std::size_t n = 0;
        for (const auto& s : sockets) {
            TimelineEvent e{};
            e.sort_key     = fmt::format("2|net-{:08}", n++);
            e.display_time = "snapshot-time-unavailable";
            e.source       = "netstat";
            e.type         = "NET";
            e.action       = "SNAPSHOT";
            e.uid          = s.uid;
            e.object       = fmt::format("{} ino={}", socket_proto(s), s.ino);
            e.confidence   = "low";
            e.actor        = fmt::format("sock={:#x}", s.sock_va);
            e.summary      = fmt::format("{} {} -> {} state={} uid={}",
                                         socket_proto(s), endpoint(s, false),
                                         endpoint(s, true), socket_state(s), s.uid);
            ev.push_back(std::move(e));
        }
    } catch (...) {}

    try {
        auto findings = collect_findevil_indicators(eng);
        std::size_t n = 0;
        for (const auto& f : findings) {
            if (severity_rank(f.severity) > severity_rank("MEDIUM")) continue;
            TimelineEvent e{};
            e.sort_key     = fmt::format("2|findevil-{:08}", n++);
            e.display_time = "snapshot-time-unavailable";
            e.source       = "findevil";
            e.type         = "EVIL";
            e.action       = "FINDING";
            e.pid          = f.pid;
            e.uid          = f.uid;
            e.object       = f.type;
            e.confidence   = f.confidence;
            e.actor        = f.comm.empty() ? "-" : fmt::format("pid={} {}", f.pid, f.comm);
            e.summary      = fmt::format("{}: {}", f.severity, f.summary);
            ev.push_back(std::move(e));
        }
    } catch (...) {}

    std::sort(ev.begin(), ev.end(),
        [](const TimelineEvent& a, const TimelineEvent& b) {
            return a.sort_key < b.sort_key;
        });
    log::info("timeline: built {} events", ev.size());
    return ev;
}

ByteBuf format_timeline_txt(const Engine& eng) {
    auto out = render_timeline_txt(eng.timeline(), "/forensic/timeline.txt",
        "Legacy merged view; split domains live under /forensic/timeline/.");
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_timeline_summary_txt(const Engine& eng) {
    auto ev = eng.timeline();
    std::unordered_map<std::string, std::size_t> counts;
    std::unordered_map<std::string, std::size_t> type_counts;
    for (const auto& e : ev) {
        ++counts[e.source];
        ++type_counts[e.type];
    }

    auto interesting = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        static const char* needles[] = {
            "panic", "oops", "bug:", "call trace", "segfault", "error",
            "failed", "denied", "sudo", "su ", "ssh", "nc ", "ncat",
            "curl ", "wget ", "insmod", "modprobe", "avml", "lime",
            "meterpreter", "shell", "exec", "hidden", "hook", "rwx"
        };
        for (const char* n : needles)
            if (s.find(n) != std::string::npos) return true;
        return false;
    };

    std::string out;
    out.reserve(32 * 1024);
    out += "# /forensic/timeline_summary.txt - high-signal timeline overview\n";
    out += "# This summarizes recovered events only. Missing sources are not\n";
    out += "# interpreted as absence of activity; check /sys/crash and /sys/journal\n";
    out += "# for source availability and partial/unavailable states.\n\n";
    out += fmt::format("events total: {}\n", ev.size());
    out += "source counts:\n";
    for (const char* src : {"proc", "dmesg", "crash", "journal", "shell", "ebpf", "netstat", "findevil"})
        out += fmt::format("  {:<8} {}\n", src, counts[src]);
    out += "domain counts:\n";
    for (const char* typ : {"PROC", "NET", "SHELL", "KERN", "EVIL"})
        out += fmt::format("  {:<8} {}\n", typ, type_counts[typ]);

    if (!ev.empty()) {
        out += fmt::format("\nfirst event: {} [{}] {} {}\n",
                           ev.front().display_time, ev.front().source,
                           ev.front().actor, ev.front().summary);
        out += fmt::format("last event:  {} [{}] {} {}\n",
                           ev.back().display_time, ev.back().source,
                           ev.back().actor, ev.back().summary);
    }

    out += "\n[high-signal recovered events]\n";
    std::size_t shown = 0;
    for (const auto& e : ev) {
        if (!interesting(e.summary) && !interesting(e.actor) && e.type != "EVIL") continue;
        out += fmt::format("{}  {:<5} {:<8} {:<10} {:<32} {}\n",
                           e.display_time, e.type, e.action, e.source,
                           e.actor, e.summary);
        if (++shown >= 100) break;
    }
    if (shown == 0)
        out += "checked recovered timeline rows: no high-signal keyword rows matched.\n";
    else if (shown == 100)
        out += "... output limited to first 100 high-signal rows; see timeline.txt for all events.\n";

    out += "\n[shell commands with timestamps]\n";
    shown = 0;
    for (const auto& e : ev) {
        if (e.type != "SHELL") continue;
        out += fmt::format("{}  {}  {}\n", e.display_time, e.actor, e.summary);
        if (++shown >= 50) break;
    }
    if (shown == 0)
        out += "unavailable/unchecked: no timestamped shell-history rows were recovered into the timeline.\n";
    else if (shown == 50)
        out += "... output limited to first 50 timestamped shell rows; see /forensic/timeline/shell.txt.\n";

    out += "\n[findevil indicators]\n";
    shown = 0;
    for (const auto& e : ev) {
        if (e.type != "EVIL") continue;
        out += fmt::format("{}  {:<7}  pid={} uid={}  {}  {}\n",
                           e.display_time, e.confidence, e.pid, e.uid,
                           e.object, e.summary);
        if (++shown >= 50) break;
    }
    if (shown == 0)
        out += "checked recovered indicators: no HIGH/MEDIUM FindEvil indicators were promoted into the timeline.\n";
    else if (shown == 50)
        out += "... output limited to first 50 FindEvil rows; see /forensic/timeline/findevil.txt.\n";

    out += "\n[notes]\n";
    out += "- Boot-relative events (process starts, dmesg, eBPF) are anchored to\n";
    out += "  absolute UTC via the kernel timekeeper and merged into one stream;\n";
    out += "  if the boot epoch is unavailable they fall back to a 'boot+N.Ms' axis.\n";
    out += "- Network and FindEvil rows without real timestamps are labeled\n";
    out += "  snapshot-time-unavailable and trail at the end (current state).\n";
    out += "- File rows are inode MAC times (mtime=data, ctime=metadata); atime is\n";
    out += "  omitted as noisy/unreliable; the list is capped to the most recent.\n";
    out += "- Untimestamped shell-history candidates cannot be placed chronologically.\n";
    out += "- Crash/log absence here means no recovered timeline row, not proof no crash/log existed.\n";
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_timeline_csv(const Engine& eng) {
    auto out = render_timeline_csv(eng.timeline());
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_timeline_domain_txt(const Engine& eng, const std::string& domain) {
    std::string note;
    if (domain == "network")
        note = "Network rows are current socket-state snapshots; creation times are unavailable.";
    else if (domain == "findevil")
        note = "FindEvil rows are snapshot indicators promoted from /sys/findevil/indicators.txt.";
    else if (domain == "all")
        note = "All normalized domains merged together.";
    auto out = render_timeline_txt(filter_domain(eng.timeline(), domain),
                                   "/forensic/timeline/" + domain + ".txt",
                                   note);
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_timeline_domain_csv(const Engine& eng, const std::string& domain) {
    auto out = render_timeline_csv(filter_domain(eng.timeline(), domain));
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
