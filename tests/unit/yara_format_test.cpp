#include "os/linux/yara_search.h"

#include <cstdio>
#include <string>

using lmpfs::linux::detail::yara_hex_preview;
using lmpfs::linux::detail::yara_text_preview;

static int g_failures = 0;
#define CHECK(cond, msg)                                           \
    do {                                                           \
        if (cond) std::printf("  ok: %s\n", (msg));                \
        else { std::printf("FAIL: %s\n", (msg)); ++g_failures; }   \
    } while (0)

int main() {
    const lmpfs::u8 sample[] = {
        'm','e','t','e','r','p','r','e','t','e','r','/',
        'x','\n','\t','\\','"',0x00,0xff
    };
    const std::string text = yara_text_preview(sample, sizeof(sample));
    CHECK(text == "meterpreter/x\\n\\t\\\\\\\"\\x00\\xff",
          "text preview is readable and safely escapes control/binary bytes");

    const std::string hex = yara_hex_preview(sample, sizeof(sample));
    CHECK(hex.rfind("6d 65 74 65 72 70 72 65 74 65 72", 0) == 0,
          "hex preview preserves exact bytes");

    lmpfs::u8 long_data[80];
    for (auto& b : long_data) b = 'A';
    CHECK(yara_text_preview(long_data, sizeof(long_data)).size() == 64,
          "text preview is capped at 64 readable bytes");
    CHECK(yara_hex_preview(long_data, sizeof(long_data)).size() == 95,
          "hex preview is capped at 32 bytes");

    const lmpfs::u8 heap_tail[] = {'s','o','c','a','t',' ',0,0,0,0,0,0};
    CHECK(yara_text_preview(heap_tail, sizeof(heap_tail)) == "socat ...",
          "sustained binary heap data is collapsed");

    const lmpfs::u8 binary_only[] = {0x90,0x90,0x90,0x90,0x90};
    CHECK(yara_text_preview(binary_only, sizeof(binary_only)) == "<binary data>",
          "binary-only matches receive a readable label");

    if (g_failures) {
        std::printf("\n== %d failure(s) ==\n", g_failures);
        return 1;
    }
    std::printf("\nall YARA formatting tests passed\n");
    return 0;
}
