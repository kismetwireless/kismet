/* Tests for rtl433_json.h, json_number.h and freq_bounds.h: rtl_433 records are hostile
 * JSON, so a missing model is not a meter (and doesn't abort on a const lookup), a
 * frequency is taken only when finite and in range, numeric ids only where master's cast
 * was defined, and range-checked numbers (Z-Wave ids, session times) never wrap.
 *
 *   make test/rtl433_json/rtl433_test && test/rtl433_json/rtl433_test
 *
 * With -DKIS_UNIT_FUZZ (unit.sh fuzz flavor) it is a libFuzzer target instead.
 */

#include "config.h"

#include <cmath>
#include <cstdio>
#include <limits>
#include <string>

#include "freq_bounds.h"
#include "json_number.h"
#include "rtl433_json.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

static nlohmann::json j(const std::string& s) {
    return nlohmann::json::parse(s);
}

static void test_meter_model() {
    const auto none = j(R"({"id":1})");
    CHECK(!rtl433_json::is_meter_model(none));
    CHECK(!rtl433_json::is_meter_model(j("{}")));
    CHECK(!rtl433_json::is_meter_model(j("[1,2]")));
    CHECK(!rtl433_json::is_meter_model(j("5")));
    CHECK(!rtl433_json::is_meter_model(j("null")));
    CHECK(!rtl433_json::is_meter_model(j(R"({"model":5})")));
    CHECK(!rtl433_json::is_meter_model(j(R"({"model":"Acurite-Tower"})")));

    for (const char *m : {"IDM", "NETIDM", "ERT-SCM", "SCMplus", "SCM+"})
        CHECK(rtl433_json::is_meter_model(nlohmann::json{{"model", m}}));
}

static void test_freq_bounds() {
    CHECK(!freq_bounds::khz_valid(0));
    CHECK(!freq_bounds::khz_valid(-1));
    CHECK(!freq_bounds::khz_valid(std::nan("")));
    CHECK(!freq_bounds::khz_valid(std::numeric_limits<double>::infinity()));
    CHECK(!freq_bounds::khz_valid(-std::numeric_limits<double>::infinity()));
    CHECK(!freq_bounds::khz_valid(1e306));
    CHECK(!freq_bounds::khz_valid(freq_bounds::max_khz + 1));
    CHECK(freq_bounds::khz_valid(freq_bounds::max_khz));
    // Below 1 kHz the tracker's int count would truncate it to 0, "no frequency"
    CHECK(!freq_bounds::khz_valid(0.001));
    CHECK(!freq_bounds::khz_valid(0.5));
    CHECK(!freq_bounds::khz_valid(0.999));
    CHECK(!freq_bounds::khz_valid(std::numeric_limits<double>::denorm_min()));
    CHECK(freq_bounds::khz_valid(freq_bounds::min_khz));
    CHECK(freq_bounds::khz_valid(1.5));
    CHECK(freq_bounds::khz_valid(433920));
    CHECK(freq_bounds::khz_valid(64800000));
    // The tracker keeps per-frequency counts keyed by int kHz
    CHECK(freq_bounds::max_khz <= std::numeric_limits<int>::max());
}

static void test_freq() {
    CHECK(rtl433_json::freq_khz(j(R"({"freq":433.92})")) == 433920);
    CHECK(rtl433_json::freq_khz(j(R"({"freq1":315.0,"freq2":314.9})")) == 315000);
    CHECK(rtl433_json::freq_khz(j(R"({"freq2":915})")) == 915000);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":"433.92","freq1":868})")) == 868000);
    // An out of range number moves on to the next key, as a wrong type does
    CHECK(rtl433_json::freq_khz(j(R"({"freq":0.0005,"freq1":433.92})")) == 433920);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":-1,"freq1":1e306,"freq2":915})")) == 915000);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":0,"freq1":0,"freq2":0})")) == 0);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":1000000})")) == freq_bounds::max_khz);

    // Hostile: out of range, negative, zero, overflowing to inf in the kHz math
    CHECK(rtl433_json::freq_khz(j(R"({"freq":1e306})")) == 0);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":1.7e308})")) == 0);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":-433.92})")) == 0);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":0})")) == 0);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":0.0005})")) == 0);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":0.001})")) == 1);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":1000000.001})")) == 0);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":18446744073709551615})")) == 0);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":-9223372036854775808})")) == 0);
    CHECK(rtl433_json::freq_khz(nlohmann::json{{"freq", std::nan("")}}) == 0);
    CHECK(rtl433_json::freq_khz(nlohmann::json{{"freq",
                std::numeric_limits<double>::infinity()}}) == 0);

    // Missing, mistyped or not an object
    const auto none = j(R"({"model":"x"})");
    CHECK(rtl433_json::freq_khz(none) == 0);
    CHECK(rtl433_json::freq_khz(j(R"({"freq":null,"freq1":[1],"freq2":{}})")) == 0);
    CHECK(rtl433_json::freq_khz(j("[433.92]")) == 0);
    CHECK(rtl433_json::freq_khz(j("433.92")) == 0);
}

static void test_ids() {
    CHECK(rtl433_json::id_bits(j("129")) == 129);
    CHECK(rtl433_json::id_bits(j("65541")) == 5);
    CHECK(rtl433_json::id_bits(j("-1")) == 0xffff);
    CHECK(rtl433_json::id_bits(j("18446744073709551615")) == 0xffff);
    CHECK(rtl433_json::id_bits(j("-9223372036854775808")) == 0);
    CHECK(!rtl433_json::id_bits(j(R"("129")")));
    CHECK(!rtl433_json::id_bits(j("null")));

    // Floats that fit an unsigned int keep master's truncated bits; the rest are rejected
    CHECK(rtl433_json::id_bits(j("12.5")) == 12);
    CHECK(rtl433_json::id_bits(j("129.0")) == 129);
    CHECK(rtl433_json::id_bits(j("65541.9")) == 5);
    CHECK(rtl433_json::id_bits(j("-0.5")) == 0);
    CHECK(rtl433_json::id_bits(j("4294967295.5")) == 0xffff);
    CHECK(!rtl433_json::id_bits(j("4294967296.0")));
    CHECK(!rtl433_json::id_bits(j("-1.0")));
    CHECK(!rtl433_json::id_bits(j("1e306")));
    CHECK(!rtl433_json::id_bits(j("-1e306")));
    CHECK(!rtl433_json::id_bits(nlohmann::json(std::nan(""))));
    CHECK(!rtl433_json::id_bits(nlohmann::json(std::numeric_limits<double>::infinity())));

    CHECK(rtl433_json::integer_text(j("129")) == "129");
    CHECK(rtl433_json::integer_text(j("-5")) == "-5");
    CHECK(rtl433_json::integer_text(j("4294967296")) == "4294967296");
    CHECK(rtl433_json::integer_text(j("18446744073709551615")) == "18446744073709551615");
    CHECK(rtl433_json::integer_text(j("-9223372036854775808")) == "-9223372036854775808");
    CHECK(rtl433_json::integer_text(j("1.5")) == "1");
    CHECK(rtl433_json::integer_text(j("3000000000.0")) == "3000000000");
    CHECK(rtl433_json::integer_text(j("1e306")).empty());
    CHECK(rtl433_json::integer_text(j("-2.0")).empty());
    CHECK(rtl433_json::integer_text(nlohmann::json(std::nan(""))).empty());
    CHECK(rtl433_json::integer_text(j(R"("a")")).empty());
    CHECK(rtl433_json::integer_text(j("true")).empty());
}

static void test_json_number() {
    using json_number::integral;
    using json_number::unsigned_integer;

    // Z-Wave node ids (uint8) and data sizes (int)
    CHECK(integral(j("0"), 0, 255) == 0);
    CHECK(integral(j("255"), 0, 255) == 255);
    CHECK(integral(j("232.7"), 0, 255) == 232);
    CHECK(!integral(j("256"), 0, 255));
    CHECK(!integral(j("-1"), 0, 255));
    CHECK(!integral(j("-1.0"), 0, 255));
    CHECK(!integral(j("255.0001e300"), 0, 255));
    CHECK(!integral(j("18446744073709551615"), 0, 255));
    CHECK(!integral(j("-9223372036854775808"), 0, 255));
    CHECK(!integral(nlohmann::json(std::nan("")), 0, 255));
    CHECK(!integral(nlohmann::json(-std::numeric_limits<double>::infinity()), 0, 255));
    CHECK(!integral(j(R"("5")"), 0, 255));
    CHECK(!integral(j("null"), 0, 255));
    CHECK(!integral(j("true"), 0, 255));

    constexpr int64_t int_max = std::numeric_limits<int>::max();
    CHECK(integral(j("2147483647"), 0, int_max) == int_max);
    CHECK(!integral(j("2147483648"), 0, int_max));
    CHECK(!integral(j("2147483648.0"), 0, int_max));
    CHECK(!integral(j("1e19"), 0, int_max));
    CHECK(integral(j("-5"), -10, 10) == -5);
    CHECK(integral(j("-5.9"), -10, 10) == -5);
    CHECK(!integral(j("-11"), -10, 10));

    // Session db times: integers only, never wrapped from a negative
    constexpr uint64_t uint_max = std::numeric_limits<unsigned int>::max();
    CHECK(unsigned_integer(j("0"), uint_max) == 0u);
    CHECK(unsigned_integer(j("1700000000"), uint_max) == 1700000000u);
    CHECK(unsigned_integer(j("4294967295"), uint_max) == uint_max);
    CHECK(unsigned_integer(nlohmann::json(int64_t{5}), uint_max) == 5u);
    CHECK(!unsigned_integer(j("4294967296"), uint_max));
    CHECK(!unsigned_integer(j("-1"), uint_max));
    CHECK(!unsigned_integer(nlohmann::json(int64_t{-1}), uint_max));
    CHECK(!unsigned_integer(j("1700000000.0"), uint_max));
    CHECK(!unsigned_integer(j("1e300"), uint_max));
    CHECK(!unsigned_integer(j(R"("1700000000")"), uint_max));
    CHECK(!unsigned_integer(j("null"), uint_max));
}

#ifdef KIS_UNIT_FUZZ
// tools/unit.sh fuzz flavor: any JSON text through every helper, which must not abort or
// hand back an out of range frequency; ids must give the 16 bits master's
// (uint16_t) get<unsigned int>() gave wherever that cast was defined (device keys)
static void fuzz_number(const nlohmann::json& v) {
    if (auto b = rtl433_json::id_bits(v)) {
        uint16_t master = 0;

        if (v.is_number_unsigned()) {
            master = (uint16_t) (unsigned int) v.get<uint64_t>();
        } else if (v.is_number_integer()) {
            master = (uint16_t) (unsigned int) v.get<int64_t>();
        } else {
            const double d = v.get<double>();
            if (!(d > -1 && d < 4294967296.0))
                __builtin_trap();
            master = (uint16_t) (unsigned int) d;
        }

        if (master != *b)
            __builtin_trap();
    } else if (v.is_number_integer() ||
            (v.is_number_float() && v.get<double>() > -1 && v.get<double>() < 4294967296.0)) {
        __builtin_trap();
    }

    if (rtl433_json::integer_text(v).empty() != !rtl433_json::id_bits(v).has_value())
        __builtin_trap();

    if (auto n = json_number::integral(v, 0, 255)) {
        if (*n < 0 || *n > 255 || !v.is_number())
            __builtin_trap();
        if (v.is_number_float() && *n != (int64_t) std::trunc(v.get<double>()))
            __builtin_trap();
    }

    if (auto n = json_number::integral(v, -10, std::numeric_limits<int>::max())) {
        if (*n < -10 || *n > std::numeric_limits<int>::max())
            __builtin_trap();
    }

    if (auto n = json_number::unsigned_integer(v, std::numeric_limits<unsigned int>::max())) {
        if (!v.is_number_integer() || *n > std::numeric_limits<unsigned int>::max())
            __builtin_trap();
    }
}

static void fuzz_walk(const nlohmann::json& j, int depth) {
    if (depth > 8)
        return;

    (void) rtl433_json::is_meter_model(j);

    const double khz = rtl433_json::freq_khz(j);
    if (khz != 0 && !freq_bounds::khz_valid(khz))
        __builtin_trap();

    for (const char *k : {"id", "device", "channel", "source", "dest", "datasize", "expires"}) {
        if (auto f = rtl433_json::field(j, k))
            fuzz_number(*f);
    }

    fuzz_number(j);

    if (j.is_structured()) {
        for (const auto& e : j)
            fuzz_walk(e, depth + 1);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    nlohmann::json json;

    try {
        json = nlohmann::json::parse(std::string((const char *) data, size));
    } catch (const std::exception&) {
        return 0;
    }

    const auto& cj = json;
    fuzz_walk(cj, 0);

    return 0;
}
#else
int main() {
    test_freq_bounds();
    test_freq();
    test_ids();
    test_json_number();
    // Last: on master's lookup this one aborts
    test_meter_model();

    if (failures != 0) {
        fprintf(stderr, "rtl433_test: %d failures\n", failures);
        return 1;
    }

    printf("rtl433_test: all passed\n");
    return 0;
}
#endif
