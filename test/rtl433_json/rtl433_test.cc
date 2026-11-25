/* Tests for rtl433_json.h, json_number.h and freq_bounds.h: rtl_433 records are hostile
 * JSON, so a missing model is not a meter (and doesn't abort on a const lookup), a
 * frequency is taken only when finite and in range, numeric ids only where master's cast
 * was defined, range-checked numbers (Z-Wave ids, session times) never wrap, and levels
 * (rssi, snr, noise) are used only when finite and plausible, as an rssi signal that
 * replaces a source's dBm values.
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
#include "rtl433_signal.h"

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

static bool level_is(const nlohmann::json& json, int rssi, int noise) {
    auto l = rtl433_json::levels(json);
    return l && l->rssi == rssi && l->noise == noise;
}

static void test_levels() {
    using rtl433_json::levels;
    using rtl433_json::level_text;
    using rtl433_json::level_min_dbfs;
    using rtl433_json::level_max_dbfs;
    using rtl433_json::snr_min_db;
    using rtl433_json::snr_max_db;
    constexpr double inf = std::numeric_limits<double>::infinity();

    // rtl_433 without -M level has no rssi, snr or noise
    const auto plain = j(R"({"model":"Acurite-Tower","id":1})");
    CHECK(!levels(plain));
    CHECK(!level_text(plain, "rssi", level_min_dbfs, level_max_dbfs));
    CHECK(!level_text(plain, "snr", snr_min_db, snr_max_db));

    // Rounded down, so a level just under 0 dBFS isn't 0 ("no value")
    CHECK(level_is(j(R"({"rssi":-0.13,"snr":15.077,"noise":-15.207})"), -1, -16));
    CHECK(level_is(j(R"({"rssi":-7.18})"), -8, 0));
    CHECK(level_is(j(R"({"rssi":-12})"), -12, 0));
    CHECK(level_is(j(R"({"rssi":-150,"noise":-150})"), -150, -150));
    CHECK(level_is(j(R"({"rssi":10.0})"), 10, 0));
    CHECK(level_is(j(R"({"rssi":3.7,"noise":-40.5})"), 3, -41));

    // Float inputs don't clip, so levels well above full scale are kept
    CHECK(level_is(j(R"({"rssi":25.5,"noise":-15})"), 25, -15));
    CHECK(level_is(j(R"({"rssi":60,"noise":59.9})"), 60, 59));
    CHECK(level_is(j(R"({"rssi":10.01})"), 10, 0));

    // Levels in [0, 1) round down to -1 like -0.13, never to 0 ("no value")
    CHECK(level_is(j(R"({"rssi":0})"), -1, 0));
    CHECK(level_is(j(R"({"rssi":0.0})"), -1, 0));
    CHECK(level_is(j(R"({"rssi":-0.0})"), -1, 0));
    CHECK(level_is(j(R"({"rssi":0.99})"), -1, 0));
    CHECK(level_is(j(R"({"rssi":1.0,"noise":0.5})"), 1, -1));
    CHECK(level_is(j(R"({"rssi":-20,"noise":0})"), -20, -1));
    CHECK(level_is(j(R"({"rssi":-20,"noise":-0.0})"), -20, -1));
    CHECK(level_is(j(R"({"rssi":-20,"noise":-0.5})"), -20, -1));

    // Out of range, non-finite or mistyped rssi gives no signal at all
    for (const char *r : {"-150.01", "60.01", "1e300", "-1e300", "1.7e308", "18446744073709551615",
            "-9223372036854775808", "\"-7.5\"", "null", "true", "[-7]", "{}"})
        CHECK(!levels(j(fmt::format(R"({{"rssi":{},"noise":-20}})", r))));
    CHECK(!levels(nlohmann::json{{"rssi", std::nan("")}}));
    CHECK(!levels(nlohmann::json{{"rssi", inf}}));
    CHECK(!levels(nlohmann::json{{"rssi", -inf}}));

    // A bad noise leaves the rssi
    CHECK(level_is(j(R"({"rssi":-5.5,"noise":1e300})"), -6, 0));
    CHECK(level_is(j(R"({"rssi":-5.5,"noise":"-20"})"), -6, 0));
    CHECK(level_is(nlohmann::json{{"rssi", -5.5}, {"noise", std::nan("")}}, -6, 0));
    CHECK(level_is(nlohmann::json{{"rssi", -5.5}, {"noise", -inf}}, -6, 0));

    // Not an object
    CHECK(!levels(j("[-7]")));
    CHECK(!levels(j("-7")));
    CHECK(!levels(j("null")));

    // Display text keeps the fraction as reported
    CHECK(level_text(j(R"({"rssi":-0.13})"), "rssi", level_min_dbfs, level_max_dbfs) == "-0.13");
    CHECK(level_text(j(R"({"rssi":-12})"), "rssi", level_min_dbfs, level_max_dbfs) == "-12");
    CHECK(level_text(j(R"({"rssi":25.5})"), "rssi", level_min_dbfs, level_max_dbfs) == "25.5");
    CHECK(level_text(j(R"({"snr":15.077})"), "snr", snr_min_db, snr_max_db) == "15.077");
    CHECK(level_text(j(R"({"snr":-3.5})"), "snr", snr_min_db, snr_max_db) == "-3.5");
    CHECK(level_text(j(R"({"snr":210})"), "snr", snr_min_db, snr_max_db) == "210");

    // Strings go on as sent, for the caller to make printable
    CHECK(level_text(j(R"({"noise":"-20"})"), "noise", level_min_dbfs, level_max_dbfs) == "-20");
    CHECK(level_text(j(R"({"snr":"x"})"), "snr", snr_min_db, snr_max_db) == "x");

    // A level thrown away shows as none, not as the last record's
    CHECK(level_text(j(R"({"snr":210.01})"), "snr", snr_min_db, snr_max_db) == "");
    CHECK(level_text(j(R"({"rssi":1e300})"), "rssi", level_min_dbfs, level_max_dbfs) == "");
    CHECK(level_text(j(R"({"rssi":60.5})"), "rssi", level_min_dbfs, level_max_dbfs) == "");
    CHECK(level_text(nlohmann::json{{"noise", std::nan("")}}, "noise", level_min_dbfs, level_max_dbfs) == "");
    CHECK(level_text(nlohmann::json{{"rssi", inf}}, "rssi", level_min_dbfs, level_max_dbfs) == "");
    for (const char *v : {"null", "true", "[-7]", "{}"})
        CHECK(level_text(j(fmt::format(R"({{"rssi":{}}})", v)), "rssi", level_min_dbfs, level_max_dbfs) == "");

    // Not an object: no field
    CHECK(!level_text(j("[-7]"), "rssi", level_min_dbfs, level_max_dbfs));
    CHECK(!level_text(j("-7"), "rssi", level_min_dbfs, level_max_dbfs));

    // Lookups don't add keys
    auto rec = j(R"({"model":"x"})");
    (void) levels(rec);
    (void) level_text(rec, "snr", snr_min_db, snr_max_db);
    CHECK(rec.size() == 1);
}

static kis_layer1_packinfo dbm_block() {
    kis_layer1_packinfo sig;
    sig.data_ok = true;
    sig.signal_type = kis_l1_signal_type_dbm;
    sig.signal_dbm = -50;
    sig.noise_dbm = -90;
    sig.antenna_signal_map[0] = -51;
    sig.freq_khz = 868000;
    sig.channel = "x";
    return sig;
}

static void test_apply_levels() {
    using rtl433_json::apply_levels;

    // A record's levels replace a source's dBm block, and its frequency goes on the signal
    auto sig = dbm_block();
    apply_levels(j(R"({"rssi":-5.5,"noise":-15})"), sig, 433920);
    CHECK(sig.data_ok && sig.signal_type == kis_l1_signal_type_rssi);
    CHECK(sig.signal_rssi == -6 && sig.noise_rssi == -15);
    CHECK(sig.signal_dbm == 0 && sig.noise_dbm == 0 && sig.antenna_signal_map.empty());
    CHECK(sig.freq_khz == 433920);
    CHECK(sig.channel == "x");

    // On an empty signal
    kis_layer1_packinfo fresh;
    apply_levels(j(R"({"rssi":25.5})"), fresh, 915000);
    CHECK(fresh.data_ok && fresh.signal_type == kis_l1_signal_type_rssi);
    CHECK(fresh.signal_rssi == 25 && fresh.noise_rssi == 0 && fresh.signal_dbm == 0);
    CHECK(fresh.freq_khz == 915000);

    // No record frequency, or a bad one, leaves the source's
    sig = dbm_block();
    apply_levels(j(R"({"rssi":-5.5})"), sig, 0);
    CHECK(sig.signal_type == kis_l1_signal_type_rssi && sig.freq_khz == 868000);
    sig = dbm_block();
    apply_levels(j(R"({"rssi":-5.5})"), sig, 1e303);
    CHECK(sig.freq_khz == 868000);
    sig = dbm_block();
    apply_levels(j(R"({"rssi":-5.5})"), sig, std::nan(""));
    CHECK(sig.freq_khz == 868000);

    // Without usable levels the source's block is left as it came
    for (const char *r : {R"({"model":"x"})", R"({"rssi":1e300})", R"({"rssi":"-5"})", "[]"}) {
        sig = dbm_block();
        apply_levels(j(r), sig, 433920);
        CHECK(sig.data_ok && sig.signal_type == kis_l1_signal_type_dbm);
        CHECK(sig.signal_dbm == -50 && sig.noise_dbm == -90 && sig.signal_rssi == 0);
        CHECK(sig.antenna_signal_map.size() == 1 && sig.freq_khz == 868000);
    }

    // and no record levels and no block stays no signal
    kis_layer1_packinfo none;
    apply_levels(j(R"({"rssi":null})"), none, 433920);
    CHECK(!none.data_ok && none.signal_type == kis_l1_signal_type_none && none.freq_khz == 0);
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

// Display text: a number in range comes back as one that parses to the same finite value,
// a string as sent, anything else as empty
static void fuzz_level_text(const nlohmann::json& j, const char *key, double lo, double hi) {
    auto t = rtl433_json::level_text(j, key, lo, hi);
    auto f = rtl433_json::field(j, key);

    if (t.has_value() != (f != nullptr))
        __builtin_trap();

    if (f == nullptr)
        return;

    if (f->is_string()) {
        if (*t != f->get_ref<const std::string&>())
            __builtin_trap();
        return;
    }

    auto v = rtl433_json::number_in(*f, lo, hi);

    if (!v) {
        if (!t->empty())
            __builtin_trap();
        return;
    }

    const auto back = nlohmann::json::parse(*t, nullptr, false);

    if (!back.is_number())
        __builtin_trap();

    const double d = back.get<double>();

    if (!std::isfinite(d) || d < lo || d > hi || d != *v)
        __builtin_trap();
}

static void fuzz_walk(const nlohmann::json& j, int depth) {
    if (depth > 8)
        return;

    (void) rtl433_json::is_meter_model(j);

    const double khz = rtl433_json::freq_khz(j);
    if (khz != 0 && !freq_bounds::khz_valid(khz))
        __builtin_trap();

    if (auto l = rtl433_json::levels(j)) {
        if (l->rssi == 0 || l->rssi < rtl433_json::level_min_dbfs || l->rssi > rtl433_json::level_max_dbfs ||
                l->noise < rtl433_json::level_min_dbfs || l->noise > rtl433_json::level_max_dbfs)
            __builtin_trap();
    }

    fuzz_level_text(j, "rssi", rtl433_json::level_min_dbfs, rtl433_json::level_max_dbfs);
    fuzz_level_text(j, "noise", rtl433_json::level_min_dbfs, rtl433_json::level_max_dbfs);
    fuzz_level_text(j, "snr", rtl433_json::snr_min_db, rtl433_json::snr_max_db);

    kis_layer1_packinfo sig;
    sig.signal_dbm = -50;
    rtl433_json::apply_levels(j, sig, khz);
    if (sig.data_ok != rtl433_json::levels(j).has_value() ||
            (sig.data_ok && (sig.signal_type != kis_l1_signal_type_rssi || sig.signal_dbm != 0 ||
                             sig.freq_khz != khz)))
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
    test_levels();
    test_apply_levels();
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
