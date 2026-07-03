// forensic_warmer_test.cpp — unit-tests the warm-duration formatter behind the
// "warming complete in ..." line, so both the sub-minute and minutes branches
// are verified on any host without needing a live mount.
#include "vfs/forensic_warmer.h"

#include <cstdio>
#include <string>

using lmpfs::vfs::detail::format_warm_duration;

static int g_failures = 0;
#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (cond) std::printf("  ok: %s\n", (msg));               \
        else { std::printf("FAIL: %s\n", (msg)); ++g_failures; }  \
    } while (0)

int main() {
    // Under a minute: one decimal of seconds (matches the "Loaded in {:.1f}s"
    // convention used for the dump load).
    CHECK(format_warm_duration(0.0)   == "0.0s",    "zero -> 0.0s");
    CHECK(format_warm_duration(9.5)   == "9.5s",    "sub-minute keeps one decimal");
    CHECK(format_warm_duration(45.5)  == "45.5s",   "45.5 -> 45.5s");
    CHECK(format_warm_duration(59.9)  == "59.9s",   "just under a minute stays seconds");
    // A minute and beyond: "Nm SSs" with zero-padded seconds.
    CHECK(format_warm_duration(60.0)  == "1m 00s",  "exactly a minute -> 1m 00s");
    CHECK(format_warm_duration(75.0)  == "1m 15s",  "75s -> 1m 15s");
    CHECK(format_warm_duration(252.0) == "4m 12s",  "252s -> 4m 12s (the forensic=full case)");
    CHECK(format_warm_duration(600.0) == "10m 00s", "600s -> 10m 00s, zero-padded seconds");
    CHECK(format_warm_duration(3661.0)== "61m 01s", "minutes are not clamped to hours");

    if (g_failures) { std::printf("\n== %d failure(s) ==\n", g_failures); return 1; }
    std::printf("\nall forensic_warmer tests passed\n");
    return 0;
}
