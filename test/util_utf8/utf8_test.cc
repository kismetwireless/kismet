/* Tests for is_valid_utf8 and munge_to_printable: well-formed UTF-8 per RFC 3629, and how
 * strings that aren't come out.
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

int main() {
    test_valid();
    test_invalid();
    test_munge();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("all utf-8 tests passed\n");
    return 0;
}
