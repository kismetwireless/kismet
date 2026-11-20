/* Tests for is_valid_utf8, is_printable_utf8, munge_to_printable and munge_to_display:
 * well-formed UTF-8 per RFC 3629, and how strings that aren't come out.
 *
 *   make test/util_utf8/utf8_test && test/util_utf8/utf8_test
 */

#include "config.h"

#include <cstdio>
#include <string>

#include "util.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

static bool valid(const std::string& s) {
    return is_valid_utf8(s.data(), s.size());
}

static void test_valid() {
    CHECK(valid(""));
    CHECK(valid("plain ascii"));
    CHECK(valid(std::string("nul\0inside", 10)));
    CHECK(valid("\x7f"));

    // Each lead byte range with its first continuation at both ends of its range
    CHECK(valid("\xc2\x80"));
    CHECK(valid("\xdf\xbf"));
    CHECK(valid("\xe0\xa0\x80"));
    CHECK(valid("\xe0\xbf\xbf"));
    CHECK(valid("\xe1\x80\x80"));
    CHECK(valid("\xec\xbf\xbf"));
    CHECK(valid("\xed\x80\x80"));
    CHECK(valid("\xed\x9f\xbf"));       // U+D7FF, just below the surrogates
    CHECK(valid("\xee\x80\x80"));       // U+E000, just above them
    CHECK(valid("\xef\xbf\xbf"));
    CHECK(valid("\xf0\x90\x80\x80"));   // U+10000
    CHECK(valid("\xf0\xbf\xbf\xbf"));
    CHECK(valid("\xf1\x80\x80\x80"));
    CHECK(valid("\xf3\xbf\xbf\xbf"));
    CHECK(valid("\xf4\x80\x80\x80"));
    CHECK(valid("\xf4\x8f\xbf\xbf"));   // U+10FFFF
    CHECK(valid("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80"));
}

static void test_invalid() {
    // Overlong forms
    CHECK(!valid("\xc0\x80"));
    CHECK(!valid("\xc1\xbf"));
    CHECK(!valid("\xe0\x80\xaf"));
    CHECK(!valid("\xe0\x9f\xbf"));
    CHECK(!valid("\xf0\x80\x80\xaf"));
    CHECK(!valid("\xf0\x8f\xbf\xbf"));

    // Surrogates
    CHECK(!valid("\xed\xa0\x80"));
    CHECK(!valid("\xed\xbf\xbf"));

    // Above U+10FFFF, and lead bytes that can't start anything
    CHECK(!valid("\xf4\x90\x80\x80"));
    CHECK(!valid("\xf5\x80\x80\x80"));
    CHECK(!valid("\xf6\x80\x80\x80"));
    CHECK(!valid("\xf7\x80\x80\x80"));
    CHECK(!valid("\xf8\x88\x80\x80\x80"));
    CHECK(!valid("\xfe"));
    CHECK(!valid("\xff"));

    // Stray and missing continuation bytes
    CHECK(!valid("\x80"));
    CHECK(!valid("\xbf"));
    CHECK(!valid("a\x80z"));
    CHECK(!valid("\xc3"));
    CHECK(!valid("\xc3z"));
    CHECK(!valid("\xe2\x82"));
    CHECK(!valid("\xe2\x82z"));
    CHECK(!valid("\xf0\x9f\x98"));
    CHECK(!valid("\xf0\x9f\x98z"));
    CHECK(!valid("ok\xf0"));

    // A valid sequence followed by an invalid one
    CHECK(!valid("\xc3\xa9\xc0\x80"));
}

static void test_munge() {
    // Valid UTF-8 passes through, control characters escaped
    CHECK(munge_to_printable(std::string("caf\xc3\xa9")) == "caf\xc3\xa9");
    CHECK(munge_to_printable(std::string("a\x01" "b")) == "a\\u0001b");

    // A string that isn't well-formed has every byte outside printable ASCII escaped, so
    // none of it reaches JSON raw
    CHECK(munge_to_printable(std::string("x\xc0\x80y")) == "x\\xC0\\x80y");
    CHECK(munge_to_printable(std::string("s\xed\xa0\x80")) == "s\\xED\\xA0\\x80");
    CHECK(munge_to_printable(std::string("\xf4\x90\x80\x80")) == "\\xF4\\x90\\x80\\x80");

    for (const auto& s : {std::string("\xe0\x80\xaf"), std::string("\xf5\x80\x80\x80"),
            std::string("\xc3"), std::string("ab\xed\xa0\x80" "cd")}) {
        auto m = munge_to_printable(s);
        CHECK(valid(m));
        for (auto c : m)
            CHECK(static_cast<unsigned char>(c) < 0x80);
    }
}

static void test_display() {
    // Printable UTF-8 is kept, quotes and backslashes too: the output encoder escapes those
    CHECK(munge_to_display("", 4) == "");
    CHECK(munge_to_display("abcd", 4) == "abcd");
    CHECK(munge_to_display("q\"b\\s", 16) == "q\"b\\s");
    CHECK(munge_to_display("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80", 64) == "caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80");

    // Controls and hidden code points are escaped by code point
    CHECK(munge_to_display(std::string("a\0b", 3), 8) == "a\\u0000b");
    CHECK(munge_to_display("a\x01\n\x1b[31m", 16) == "a\\u0001\\u000a\\u001b[31m");
    CHECK(munge_to_display("del\x7f", 8) == "del\\u007f");
    CHECK(munge_to_display("csi\xc2\x9b", 8) == "csi\\u009b");
    CHECK(munge_to_display("ab\xe2\x80\xae" "cd", 16) == "ab\\u202ecd");
    CHECK(munge_to_display("\xef\xbb\xbfx", 8) == "\\ufeffx");
    CHECK(munge_to_display("\xf3\xa0\x81\x81", 8) == "\\U000e0041");

    // Bytes that aren't well-formed are escaped one at a time; valid text around them is kept
    CHECK(munge_to_display("caf\xc3\xa9\xff", 16) == "caf\xc3\xa9\\xFF");
    CHECK(munge_to_display("x\xc0\x80y", 8) == "x\\xC0\\x80y");
    CHECK(munge_to_display("s\xed\xa0\x80", 8) == "s\\xED\\xA0\\x80");
    CHECK(munge_to_display("\xf4\x90\x80\x80", 8) == "\\xF4\\x90\\x80\\x80");
    CHECK(munge_to_display("ok\xe2\x82", 8) == "ok\\xE2\\x82");

    CHECK(munge_to_display("abcde", 4) == "abcd...");
    CHECK(munge_to_display("abcde", 0) == "...");

    // A cut inside a character backs up to its lead byte, so the rest stays valid UTF-8
    const std::string euro("\xe2\x82\xac");
    CHECK(munge_to_display("a" + euro + "b", 1) == "a...");
    CHECK(munge_to_display("a" + euro + "b", 2) == "a...");
    CHECK(munge_to_display("a" + euro + "b", 3) == "a...");
    CHECK(munge_to_display("a" + euro + "b", 4) == "a" + euro + "...");
    CHECK(munge_to_display("\xf0\x9f\x98\x80z", 3) == "...");
    CHECK(munge_to_display("\xf0\x9f\x98\x80z", 4) == "\xf0\x9f\x98\x80...");

    // Continuation bytes with no lead are invalid; the cut backs up at most three
    CHECK(munge_to_display(std::string("ab") + std::string(8, '\x80'), 6) == "ab\\x80...");

    // Long hostile text comes out bounded and printable, and cleaning it again changes nothing
    std::string hostile;
    for (unsigned int i = 0; i < 4000; i++)
        hostile += static_cast<char>(i & 0xFF);
    const auto m = munge_to_display(hostile, 1024);
    CHECK(m.length() <= 1024 * 10 + 3);
    CHECK(m.substr(m.length() - 3) == "...");
    CHECK(is_printable_utf8(m));
    CHECK(munge_to_display(m, m.length()) == m);
}

static void test_printable() {
    CHECK(is_printable_utf8(""));
    CHECK(is_printable_utf8("wlan0:name=\"a b\",channels=\"1,6,11\""));
    CHECK(is_printable_utf8("wl\"q\\x"));
    CHECK(is_printable_utf8("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80"));
    CHECK(is_printable_utf8("\xc2\xa0"));               // U+00A0, first after C1

    CHECK(!is_printable_utf8(std::string("nul\0", 4)));
    CHECK(!is_printable_utf8("a\x01"));
    CHECK(!is_printable_utf8("tab\there"));
    CHECK(!is_printable_utf8("esc\x1b[31m"));
    CHECK(!is_printable_utf8("del\x7f"));
    CHECK(!is_printable_utf8("\xc2\x80"));              // U+0080
    CHECK(!is_printable_utf8("csi\xc2\x9b"));           // U+009B
    CHECK(!is_printable_utf8("\xc2\x9f"));              // U+009F
    CHECK(!is_printable_utf8("\xc0\x80"));
    CHECK(!is_printable_utf8("\xf4\x90\x80\x80"));
    CHECK(!is_printable_utf8("ok\xc2"));

    // Hidden code points: soft hyphen, zero-width space, right-to-left override, isolates,
    // the BOM and a tag character
    CHECK(!is_printable_utf8("a\xc2\xad"));
    CHECK(!is_printable_utf8("a\xe2\x80\x8b"));
    CHECK(!is_printable_utf8("wlan\xe2\x80\xae" "0"));
    CHECK(!is_printable_utf8("\xe2\x81\xa6x\xe2\x81\xa9"));
    CHECK(!is_printable_utf8("\xef\xbb\xbfwlan0"));
    CHECK(!is_printable_utf8("\xf3\xa0\x81\x81"));
}

int main() {
    test_valid();
    test_invalid();
    test_munge();
    test_display();
    test_printable();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("all utf-8 tests passed\n");
    return 0;
}
