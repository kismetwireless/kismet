/* Tests for environmental sensors: the datasource report parser, the sensor store and
 * its limits, the capture framework encoder against the parser, and the sysfs readers
 * (power_supply, hwmon, thermal zones) on fixture trees.
 *
 *   make test/environment/env_test && test/environment/env_test
 *
 * Fixture trees are made under $TMPDIR (or /tmp) and removed at the end.
 */

#include "config.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ftw.h>
#include <limits>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include "battery.h"
#include "capture_env.h"
#include "entrytracker.h"
#include "environment.h"
#include "environment_report.h"
#include "fmt.h"
#include "globalregistry.h"
#include "mpack/mpack.h"

static int failures = 0;
static int checks = 0;

#define CHECK(c) do { \
    checks++; \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

// A test reading; numbers are written as the type asked for
struct tr {
    const char *id = "temp0";
    int kind = KIS_EXTERNAL_V3_ENV_KIND_THERMAL;
    double value = 42.5;
    bool as_float = false;
    const char *label = nullptr;
    size_t label_len = 0;
    bool no_id = false, no_kind = false, no_value = false;
    bool id_as_int = false, value_as_str = false, kind_as_str = false;
    int batt_state = -1;
    int ext_power = -1;
    double voltage = -1;
    long long remaining = -1;
};

static std::string build(const std::vector<tr>& readings, bool with_ts = false, uint64_t ts_s = 0,
        bool sensors_not_array = false) {
    char *data = nullptr;
    size_t size = 0;
    mpack_writer_t w;
    mpack_writer_init_growable(&w, &data, &size);

    mpack_build_map(&w);
    mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_SENSORS);

    if (sensors_not_array) {
        mpack_write_cstr(&w, "nope");
    } else {
        mpack_build_array(&w);
        for (const auto& r : readings) {
            mpack_build_map(&w);
            if (!r.no_id) {
                mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_ID);
                if (r.id_as_int)
                    mpack_write_uint(&w, 7);
                else
                    mpack_write_cstr(&w, r.id);
            }
            if (!r.no_kind) {
                mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_KIND);
                if (r.kind_as_str)
                    mpack_write_cstr(&w, "thermal");
                else
                    mpack_write_uint(&w, r.kind);
            }
            if (!r.no_value) {
                mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_VALUE);
                if (r.value_as_str)
                    mpack_write_cstr(&w, "42");
                else if (r.as_float)
                    mpack_write_float(&w, (float) r.value);
                else
                    mpack_write_double(&w, r.value);
            }
            if (r.label != nullptr) {
                mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_LABEL);
                mpack_write_str(&w, r.label, (uint32_t) (r.label_len ? r.label_len : strlen(r.label)));
            }
            if (r.batt_state >= 0) {
                mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_BATT_STATE);
                mpack_write_uint(&w, r.batt_state);
            }
            if (r.ext_power >= 0) {
                mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_EXT_POWER);
                mpack_write_bool(&w, r.ext_power == 1);
            }
            if (r.voltage >= 0 || std::isnan(r.voltage)) {
                mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_VOLTAGE);
                mpack_write_float(&w, (float) r.voltage);
            }
            if (r.remaining >= 0) {
                mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_REMAINING_S);
                mpack_write_uint(&w, (uint64_t) r.remaining);
            }
            mpack_complete_map(&w);
        }
        mpack_complete_array(&w);
    }

    if (with_ts) {
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_TS_S);
        mpack_write_u64(&w, ts_s);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_TS_US);
        mpack_write_u32(&w, 5);
    }

    mpack_complete_map(&w);

    if (mpack_writer_destroy(&w) != mpack_ok) {
        fprintf(stderr, "test writer failed\n");
        exit(2);
    }

    std::string s(data, size);
    MPACK_FREE(data);
    return s;
}

static bool parse(const std::string& s, env_report& r) {
    std::string err;
    return env_report_parse(s, r, err);
}

static void test_parse_good() {
    env_report r;
    tr t;
    t.label = "CPU package";
    tr b;
    b.id = "battery";
    b.kind = KIS_EXTERNAL_V3_ENV_KIND_BATTERY;
    b.value = 87.0;
    b.as_float = true;
    b.batt_state = KIS_EXTERNAL_V3_ENV_BATT_CHARGING;
    b.ext_power = 1;
    b.voltage = 3.9;
    b.remaining = 3600;
    tr f;
    f.id = "fan.1";
    f.kind = KIS_EXTERNAL_V3_ENV_KIND_FAN;
    f.value = 2400;

    CHECK(parse(build({t, b, f}, true, 1700000000), r));
    CHECK(r.readings.size() == 3);
    CHECK(r.skipped == 0);
    CHECK(r.has_ts && r.ts_s == 1700000000 && r.ts_us == 5);
    CHECK(r.readings[0].id == "temp0");
    CHECK(r.readings[0].kind == env_kind::thermal);
    CHECK(r.readings[0].value == 42.5);
    CHECK(r.readings[0].label == "CPU package");
    CHECK(r.readings[1].kind == env_kind::battery);
    CHECK(r.readings[1].value == 87.0);
    CHECK(r.readings[1].batt_state == KIS_EXTERNAL_V3_ENV_BATT_CHARGING);
    CHECK(r.readings[1].ext_power == 1);
    CHECK(std::fabs(r.readings[1].voltage - 3.9) < 0.001);
    CHECK(r.readings[1].remaining_s == 3600);
    CHECK(r.readings[2].kind == env_kind::fan);
    CHECK(r.readings[2].value == 2400);

    // No readings is a valid, empty report
    CHECK(parse(build({}), r));
    CHECK(r.readings.empty());
}

static void test_parse_malformed() {
    env_report r;
    std::string err;

    CHECK(!env_report_parse("", r, err));
    CHECK(!env_report_parse(std::string("\xc1", 1), r, err));
    CHECK(!env_report_parse(std::string("\x92\x01\x02", 3), r, err));
    // A truncated report
    auto good = build({tr()});
    CHECK(!env_report_parse(good.substr(0, good.size() - 3), r, err));
    // Map without the sensor array
    CHECK(!env_report_parse(std::string("\x81\x05\x01", 3), r, err));
    CHECK(!parse(build({}, false, 0, true), r));

    tr t;
    t.no_id = true;
    CHECK(!parse(build({t}), r));
    t = tr();
    t.no_kind = true;
    CHECK(!parse(build({t}), r));
    t = tr();
    t.no_value = true;
    CHECK(!parse(build({t}), r));
    t = tr();
    t.id_as_int = true;
    CHECK(!parse(build({t}), r));
    t = tr();
    t.value_as_str = true;
    CHECK(!parse(build({t}), r));
    t = tr();
    t.kind_as_str = true;
    CHECK(!parse(build({t}), r));
    // A good reading doesn't save a report with a bad one
    CHECK(!parse(build({tr(), t}), r));

    // Kind past u8
    t = tr();
    t.kind = 300;
    CHECK(!parse(build({t}), r));

    // 17 readings
    std::vector<tr> many;
    std::vector<std::string> ids;
    for (int i = 0; i < 17; i++)
        ids.push_back(fmt::format("t{}", i));
    for (int i = 0; i < 17; i++) {
        tr m;
        m.id = ids[i].c_str();
        many.push_back(m);
    }
    CHECK(!parse(build(many), r));
    many.pop_back();
    CHECK(parse(build(many), r));
    CHECK(r.readings.size() == 16);
}

static void test_parse_skips() {
    env_report r;

    const double bad_values[] = {
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity(),
        -100.5, 400.5, 1e300,
    };

    for (auto v : bad_values) {
        for (bool as_float : {false, true}) {
            tr t;
            t.value = v;
            t.as_float = as_float;
            CHECK(parse(build({t, tr{.id = "ok"}}), r));
            CHECK(r.readings.size() == 1 && r.skipped == 1);
            CHECK(r.readings.size() == 1 && r.readings[0].id == "ok");
        }
    }

    // Ranges per kind
    tr f;
    f.kind = KIS_EXTERNAL_V3_ENV_KIND_FAN;
    f.value = -1;
    CHECK(parse(build({f}), r) && r.readings.empty() && r.skipped == 1);
    f.value = 1000001;
    CHECK(parse(build({f}), r) && r.readings.empty());
    f.value = 1000000;
    CHECK(parse(build({f}), r) && r.readings.size() == 1);

    tr b;
    b.kind = KIS_EXTERNAL_V3_ENV_KIND_BATTERY;
    b.value = 100.4;
    CHECK(parse(build({b}), r) && r.readings.size() == 1 && r.readings[0].value == 100.0);
    b.value = 100.6;
    CHECK(parse(build({b}), r) && r.readings.empty());
    b.value = -0.1;
    CHECK(parse(build({b}), r) && r.readings.empty());

    // Bad battery details are dropped, the reading kept
    b.value = 50;
    b.batt_state = 9;
    b.voltage = 150;
    b.remaining = 31LL * 24 * 3600;
    CHECK(parse(build({b}), r) && r.readings.size() == 1);
    CHECK(r.readings.size() == 1 && r.readings[0].batt_state == KIS_EXTERNAL_V3_ENV_BATT_UNKNOWN);
    CHECK(r.readings.size() == 1 && r.readings[0].voltage == 0 && r.readings[0].remaining_s == 0);
    b.voltage = std::numeric_limits<double>::quiet_NaN();
    CHECK(parse(build({b}), r) && r.readings.size() == 1 && r.readings[0].voltage == 0);
    // remaining past u32 is a type error
    b.voltage = -1;
    b.remaining = 5000000000LL;
    CHECK(!parse(build({b}), r));

    // Battery details on another kind are ignored
    tr tb;
    tb.batt_state = KIS_EXTERNAL_V3_ENV_BATT_FULL;
    tb.ext_power = 1;
    CHECK(parse(build({tb}), r) && r.readings.size() == 1);
    CHECK(r.readings.size() == 1 && r.readings[0].ext_power == -1);

    // Unknown kinds are skipped, for newer helpers
    tr u;
    u.kind = 4;
    CHECK(parse(build({u, tr{.id = "ok"}}), r) && r.readings.size() == 1 && r.skipped == 1);
    u.kind = 0;
    CHECK(parse(build({u}), r) && r.readings.empty());

    // Ids
    const char *bad_ids[] = { "", ".x", "../x", "a/b", "a b", "a\nb", "temp\xc3\xa9", "x;rm",
        "123456789012345678901234567890123" };
    for (auto id : bad_ids) {
        tr t;
        t.id = id;
        CHECK(parse(build({t}), r));
        CHECK(r.readings.empty() && r.skipped == 1);
    }

    const char *good_ids[] = { "a", "A-b_c.d", "x.", "12345678901234567890123456789012" };
    for (auto id : good_ids) {
        tr t;
        t.id = id;
        CHECK(parse(build({t}), r) && r.readings.size() == 1);
    }

    // An id with an embedded null
    tr nul;
    static const char nul_id[] = "ab\0cd";
    nul.id = nul_id;
    {
        char *data = nullptr;
        size_t size = 0;
        mpack_writer_t w;
        mpack_writer_init_growable(&w, &data, &size);
        mpack_build_map(&w);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_SENSORS);
        mpack_build_array(&w);
        mpack_build_map(&w);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_ID);
        mpack_write_str(&w, nul_id, 5);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_KIND);
        mpack_write_uint(&w, 1);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_VALUE);
        mpack_write_double(&w, 20);
        mpack_complete_map(&w);
        mpack_complete_array(&w);
        mpack_complete_map(&w);
        mpack_writer_destroy(&w);
        CHECK(parse(std::string(data, size), r) && r.readings.empty() && r.skipped == 1);
        MPACK_FREE(data);
    }

    // Duplicate ids keep the first
    tr d1, d2;
    d2.value = 10;
    CHECK(parse(build({d1, d2}), r) && r.readings.size() == 1 && r.skipped == 1);
    CHECK(r.readings.size() == 1 && r.readings[0].value == 42.5);

    // Labels: 10 KB cut to 64, control and high bytes replaced
    std::string big(10240, 'L');
    tr l;
    l.label = big.c_str();
    CHECK(parse(build({l}), r) && r.readings.size() == 1);
    CHECK(r.readings.size() == 1 && r.readings[0].label == std::string(64, 'L'));

    static const char hostile[] = "a\"b\\c<d>&\x01\x1f\x7f\xff\xc3\xa9\n\0z";
    l.label = hostile;
    l.label_len = sizeof(hostile) - 1;
    CHECK(parse(build({l}), r) && r.readings.size() == 1);
    CHECK(r.readings.size() == 1 && r.readings[0].label == "a\"b\\c<d>&????????z");

    // Timestamps with bad microseconds are ignored
    {
        char *data = nullptr;
        size_t size = 0;
        mpack_writer_t w;
        mpack_writer_init_growable(&w, &data, &size);
        mpack_build_map(&w);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_SENSORS);
        mpack_build_array(&w);
        mpack_complete_array(&w);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_TS_S);
        mpack_write_u64(&w, 100);
        mpack_write_uint(&w, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_TS_US);
        mpack_write_u32(&w, 2000000);
        mpack_complete_map(&w);
        mpack_writer_destroy(&w);
        CHECK(parse(std::string(data, size), r) && !r.has_ts);
        MPACK_FREE(data);
    }
}

static env_report report_of(std::initializer_list<std::pair<std::string, double>> vals,
        env_kind kind = env_kind::thermal) {
    env_report r;
    for (const auto& v : vals) {
        env_report_reading rr;
        rr.id = v.first;
        rr.kind = kind;
        rr.value = v.second;
        r.readings.push_back(rr);
    }
    return r;
}

static std::shared_ptr<tracked_env_sensor> sensor_of(environment_store& st, const std::string& key) {
    auto s = st.get_status()->get_sensors();
    auto i = s->find(key);
    if (i == s->end())
        return nullptr;
    return std::static_pointer_cast<tracked_env_sensor>(i->second);
}

static void test_store_sources() {
    env_store_config c;
    c.source_max_sensors = 3;
    c.source_total_max = 5;
    c.report_ms = 4000;
    environment_store st(c);

    uuid a("11111111-0000-0000-0000-000000000001");
    uuid b("11111111-0000-0000-0000-000000000002");
    uuid z("11111111-0000-0000-0000-000000000003");
    time_t now = 1700000000;
    uint64_t mono = 100000;

    CHECK(st.record_source(a, "src-a", report_of({{"t1", 30}, {"t2", 31}, {"t3", 32}, {"t4", 33}}), now, mono));
    CHECK(st.source_sensor_count(a) == 3);
    CHECK(st.get_status()->get_dropped_sensors() == 1);
    CHECK(sensor_of(st, environment_store::source_key(a, "t4")) == nullptr);

    auto s1 = sensor_of(st, environment_store::source_key(a, "t1"));
    CHECK(s1 != nullptr);
    if (s1 != nullptr) {
        CHECK(s1->get_origin() == "datasource");
        CHECK(s1->get_source_uuid() == a);
        CHECK(s1->get_source_name() == "src-a");
        CHECK(s1->get_kind() == "thermal");
        CHECK(s1->get_units() == "C");
        CHECK(s1->get_sensor_value() == 30);
        CHECK(s1->get_label() == "t1");
        CHECK(s1->get_sensor_id() == environment_store::source_key(a, "t1"));
        CHECK(s1->get_last_time() == now);
    }

    // Rate limit: reports closer than half the interval are dropped
    CHECK(!st.record_source(a, "src-a", report_of({{"t1", 99}}), now, mono + 1999));
    CHECK(st.get_status()->get_dropped_reports() == 1);
    CHECK(s1 != nullptr && s1->get_sensor_value() == 30);
    CHECK(st.record_source(a, "src-a", report_of({{"t1", 40}}), now + 2, mono + 2000));
    CHECK(s1 != nullptr && s1->get_sensor_value() == 40);

    // Another source has its own limit, and the total caps both
    CHECK(st.record_source(b, "src-b", report_of({{"t1", 1}, {"t2", 2}, {"t3", 3}}), now, mono));
    CHECK(st.source_sensor_count(b) == 2);
    CHECK(st.source_total() == 5);
    CHECK(st.get_status()->get_dropped_sensors() == 2);

    // A known sensor changing kind is refused
    CHECK(st.record_source(b, "src-b", report_of({{"t1", 50}}, env_kind::battery), now, mono + 5000));
    CHECK(st.get_status()->get_dropped_sensors() == 3);
    auto sb = sensor_of(st, environment_store::source_key(b, "t1"));
    CHECK(sb != nullptr && sb->get_kind() == "thermal" && sb->get_sensor_value() == 1);

    // Timestamps from the source within a minute of ours are used
    auto rt = report_of({{"t1", 41}});
    rt.has_ts = true;
    rt.ts_s = now - 30;
    CHECK(st.record_source(a, "src-a", rt, now, mono + 10000));
    CHECK(s1 != nullptr && s1->get_last_time() == now - 30);
    rt.ts_s = now - 3600;
    CHECK(st.record_source(a, "src-a", rt, now, mono + 20000));
    CHECK(s1 != nullptr && s1->get_last_time() == now);
    rt.ts_s = (uint64_t) -1;
    CHECK(st.record_source(a, "renamed", rt, now + 1, mono + 30000));
    CHECK(s1 != nullptr && s1->get_last_time() == now + 1 && s1->get_source_name() == "renamed");

    // History
    CHECK(s1 != nullptr && s1->get_tracker_rrd() != nullptr);

    // Sweep removes sources which are gone, and frees their share of the total
    std::unordered_set<uuid> live{a};
    CHECK(st.sweep(live, now + 2) == 2);
    CHECK(sensor_of(st, environment_store::source_key(b, "t1")) == nullptr);
    CHECK(st.source_total() == 3);
    CHECK(st.source_sensor_count(b) == 0);
    CHECK(st.record_source(z, "src-z", report_of({{"t1", 1}, {"t2", 2}, {"t3", 3}}), now, mono));
    CHECK(st.source_sensor_count(z) == 2);

    // A removed source comes back with a fresh rate limit
    CHECK(st.sweep(std::unordered_set<uuid>{}, now + 2) == 5);
    CHECK(st.get_status()->get_sensors()->size() == 0);
    CHECK(st.source_total() == 0);
    CHECK(st.record_source(a, "src-a", report_of({{"t1", 30}}), now, mono + 30001));

    // Labels
    auto rl = report_of({{"t2", 20}});
    rl.readings[0].label = "Radio";
    CHECK(st.record_source(a, "src-a", rl, now, mono + 40000));
    auto s2 = sensor_of(st, environment_store::source_key(a, "t2"));
    CHECK(s2 != nullptr && s2->get_label() == "Radio");

    // Battery details
    env_report rb;
    env_report_reading br;
    br.id = "battery";
    br.kind = env_kind::battery;
    br.value = 75;
    br.batt_state = KIS_EXTERNAL_V3_ENV_BATT_DISCHARGING;
    br.ext_power = 0;
    br.voltage = 3.7;
    br.remaining_s = 1800;
    rb.readings.push_back(br);
    CHECK(st.record_source(a, "src-a", rb, now, mono + 50000));
    auto sbat = sensor_of(st, environment_store::source_key(a, "battery"));
    CHECK(sbat != nullptr);
    if (sbat != nullptr) {
        CHECK(sbat->get_units() == "%");
        CHECK(sbat->get_battery()->get_state() == "discharging");
        CHECK(sbat->get_battery()->get_external_power() == 0);
        CHECK(sbat->get_battery()->get_remaining() == 1800);
    }
}

static void test_store_stale() {
    env_store_config c;
    c.source_max_sensors = 3;
    c.source_total_max = 4;
    c.report_ms = 5000;
    environment_store st(c);

    // At least an hour, or 20 report intervals when those are longer
    CHECK(st.stale_sec() == 3600);
    env_store_config cl = c;
    cl.report_ms = 600000;
    CHECK(environment_store(cl).stale_sec() == 12000);
    cl.report_ms = 0;
    CHECK(environment_store(cl).stale_sec() == 3600);

    uuid a("11111111-0000-0000-0000-000000000001");
    uuid b("11111111-0000-0000-0000-000000000002");
    time_t now = 1700000000;
    uint64_t mono = 100000;

    // A dead remote still listed as live: its sensors stop updating
    CHECK(st.record_source(a, "a", report_of({{"t1", 1}, {"t2", 2}, {"t3", 3}}), now, mono));
    CHECK(st.record_source(b, "b", report_of({{"t1", 1}, {"t2", 2}}), now, mono));
    CHECK(st.source_total() == 4 && st.get_status()->get_dropped_sensors() == 1);

    // b got one sensor under the total cap, and keeps it fresh
    CHECK(st.source_sensor_count(b) == 1);
    CHECK(st.record_source(b, "b", report_of({{"t1", 5}}), now + 3000, mono + 3000000));

    std::unordered_set<uuid> live{a, b};
    CHECK(st.sweep(live, now + 3600) == 0);
    CHECK(st.sweep(live, now + 3601) == 3);
    CHECK(st.source_sensor_count(a) == 0);
    CHECK(st.source_sensor_count(b) == 1);
    CHECK(st.source_total() == 1);
    CHECK(sensor_of(st, environment_store::source_key(b, "t1")) != nullptr);
    CHECK(sensor_of(st, environment_store::source_key(b, "t2")) == nullptr);

    // The freed share is usable again, by the same source and others
    CHECK(st.record_source(a, "a", report_of({{"t1", 1}, {"t2", 2}, {"t3", 3}}), now + 3700, mono + 3700000));
    CHECK(st.source_sensor_count(a) == 3 && st.source_total() == 4);

    // A clock that went backwards doesn't remove anything
    CHECK(st.sweep(live, now) == 0);

    // Host sensors never age out here
    env_host_reading h;
    h.id = "system-thermal-0";
    h.value = 40;
    CHECK(st.record_host(h, now));
    CHECK(st.sweep(live, now + 100000) == 4);
    CHECK(sensor_of(st, "system-thermal-0") != nullptr);
    CHECK(st.source_total() == 0 && st.source_sensor_count(a) == 0 && st.source_sensor_count(b) == 0);
}

static void test_store_current() {
    env_store_config c;
    c.report_ms = 300000;
    environment_store st(c);

    CHECK(st.get_status()->get_source_report_sec() == 300);
    CHECK(st.get_status()->get_source_stale_sec() == 6000);

    env_host_reading h;
    h.id = "system-thermal-0";
    h.label = "zone";
    h.value = 40;
    CHECK(st.record_host(h, 100));

    uuid a("11111111-0000-0000-0000-000000000001");
    env_report rb;
    env_report_reading br;
    br.id = "battery";
    br.kind = env_kind::battery;
    br.value = 75;
    br.label = "Pack";
    br.batt_state = KIS_EXTERNAL_V3_ENV_BATT_CHARGING;
    br.ext_power = 1;
    br.voltage = 3.7;
    br.remaining_s = 600;
    rb.readings.push_back(br);
    CHECK(st.record_source(a, "src-a", rb, 100, 1000));
    // Not in time for the rate limit
    CHECK(!st.record_source(a, "src-a", rb, 100, 1001));

    auto cur = st.current();
    CHECK(cur.get() != st.get_status().get());
    CHECK(cur->get_history() == true);
    CHECK(cur->get_dropped_reports() == 1);
    CHECK(cur->get_source_report_sec() == 300);
    CHECK(cur->get_source_stale_sec() == 6000);
    CHECK(cur->get_sensors()->size() == 2);

    for (const auto& kv : *cur->get_sensors()) {
        auto cs = std::static_pointer_cast<tracked_env_sensor>(kv.second);
        auto orig = sensor_of(st, kv.first);
        CHECK(orig != nullptr && orig.get() != cs.get());
        CHECK(orig != nullptr && orig->get_tracker_rrd() != nullptr);
        CHECK(cs->get_tracker_rrd() == nullptr);
        CHECK(cs->get_sensor_id() == kv.first);
        if (orig == nullptr)
            continue;
        CHECK(cs->get_label() == orig->get_label() && cs->get_kind() == orig->get_kind());
        CHECK(cs->get_units() == orig->get_units() && cs->get_sensor_value() == orig->get_sensor_value());
        CHECK(cs->get_last_time() == orig->get_last_time() && cs->get_origin() == orig->get_origin());
        CHECK(cs->get_source_uuid() == orig->get_source_uuid() && cs->get_source_name() == orig->get_source_name());
        CHECK(cs->has_battery() == orig->has_battery());
    }

    auto ci = cur->get_sensors()->find(environment_store::source_key(a, "battery"));
    CHECK(ci != cur->get_sensors()->end());
    if (ci != cur->get_sensors()->end()) {
        auto cs = std::static_pointer_cast<tracked_env_sensor>(ci->second);
        CHECK(cs->has_battery());
        if (cs->has_battery()) {
            auto b = cs->get_tracker_battery();
            CHECK(b->get_state() == "charging" && b->get_external_power() == 1);
            CHECK(std::fabs(b->get_voltage() - 3.7) < 0.001 && b->get_remaining() == 600);
        }
        CHECK(cs->get_label() == "Pack" && cs->get_source_name() == "src-a");
    }

    // Later changes don't reach the copy
    h.value = 50;
    CHECK(st.record_host(h, 101));
    auto hc = std::static_pointer_cast<tracked_env_sensor>(cur->get_sensors()->find("system-thermal-0")->second);
    CHECK(hc->get_sensor_value() == 40);

    // The thermal view carries the same header
    auto tv = st.thermal_view();
    CHECK(tv->get_source_report_sec() == 300 && tv->get_source_stale_sec() == 6000);
    CHECK(tv->get_sensors()->size() == 1);
}

static void test_store_off() {
    env_store_config c;
    c.source_max_sensors = 0;
    environment_store st(c);
    uuid a("11111111-0000-0000-0000-000000000001");
    CHECK(!st.record_source(a, "x", report_of({{"t1", 1}}), 1, 1));
    CHECK(st.get_status()->get_sensors()->size() == 0);
    CHECK(st.get_status()->get_dropped_reports() == 1);
    CHECK(st.get_status()->get_source_report_sec() == 0);
    CHECK(st.get_status()->get_source_stale_sec() == 3600);

    // History off: no RRD
    env_store_config c2;
    c2.history = false;
    environment_store st2(c2);
    env_host_reading h;
    h.id = "system-thermal-0";
    h.value = 40;
    CHECK(st2.record_host(h, 100));
    auto s = sensor_of(st2, "system-thermal-0");
    CHECK(s != nullptr && s->get_tracker_rrd() == nullptr);
    CHECK(st2.get_status()->get_history() == false);
}

static void test_store_host() {
    env_store_config c;
    c.host_max_sensors = 2;
    environment_store st(c);

    env_host_reading h;
    h.kind = env_kind::thermal;
    h.label = "zone";
    for (int i = 0; i < 3; i++) {
        h.id = fmt::format("system-thermal-{}", i);
        h.value = 40 + i;
        CHECK(st.record_host(h, 100) == (i < 2));
    }

    // The cap is per kind; fans still go in
    env_host_reading f;
    f.id = "fan1";
    f.kind = env_kind::fan;
    f.value = 1200;
    CHECK(st.record_host(f, 100));

    env_host_reading n = h;
    n.id = "system-thermal-0";
    n.value = std::numeric_limits<double>::quiet_NaN();
    CHECK(!st.record_host(n, 101));

    auto s0 = sensor_of(st, "system-thermal-0");
    CHECK(s0 != nullptr && s0->get_sensor_value() == 40 && s0->get_origin() == "host");
    CHECK(s0 != nullptr && s0->get_source_uuid() == uuid());

    env_host_reading b;
    b.id = "system-battery-BAT0";
    b.kind = env_kind::battery;
    b.value = 90;
    b.batt_state = kis_battery_state::full;
    b.ext_power = 1;
    CHECK(st.record_host(b, 100));
    auto sb = sensor_of(st, "system-battery-BAT0");
    CHECK(sb != nullptr && sb->get_battery()->get_state() == "full");

    // The thermal view shares the thermal records only
    auto v = st.thermal_view();
    CHECK(v->get_sensors()->size() == 2);
    CHECK(v->get_sensors()->find("fan1") == v->get_sensors()->end());
    CHECK(v->get_sensors()->find("system-thermal-1") != v->get_sensors()->end());

    // Readings are copies
    auto rd = st.readings();
    CHECK(rd->size() == 4);
    auto ri = rd->find("system-thermal-0");
    CHECK(ri != rd->end());
    if (ri != rd->end()) {
        auto rv = std::static_pointer_cast<tracked_env_reading>(ri->second);
        CHECK(rv->get_sensor_value() == 40 && rv->get_kind() == "thermal");
        CHECK(rv->get_label() == "zone" && rv->get_source_name() == "");
        CHECK(s0 != nullptr && rv.get() != (tracked_env_reading *) s0.get());
    }
}

static void test_round_trip() {
    char buf[8192];
    cf_env_reading_t r[20];
    memset(r, 0, sizeof(r));

    std::string ids[20];
    for (int i = 0; i < 20; i++) {
        ids[i] = fmt::format("s{}", i);
        r[i].id = ids[i].c_str();
        r[i].kind = KIS_EXTERNAL_V3_ENV_KIND_THERMAL;
        r[i].value = 20 + i;
        r[i].ext_power = -1;
    }

    std::string longlabel(100, 'x');
    r[0].label = longlabel.c_str();
    r[1].kind = KIS_EXTERNAL_V3_ENV_KIND_BATTERY;
    r[1].value = 55.5;
    r[1].batt_state = KIS_EXTERNAL_V3_ENV_BATT_NOT_CHARGING;
    r[1].ext_power = 1;
    r[1].voltage = 12.6;
    r[1].remaining_s = 7200;
    r[2].kind = KIS_EXTERNAL_V3_ENV_KIND_FAN;
    r[2].value = 3000;
    // Invalid ones the encoder leaves out
    r[3].value = std::numeric_limits<double>::quiet_NaN();
    r[4].id = "../etc";
    r[5].kind = 9;
    r[6].id = nullptr;

    struct timeval tv = { 1700000000, 250000 };

    auto len = cf_env_encode(buf, sizeof(buf), r, 20, &tv);
    CHECK(len > 0);
    CHECK((size_t) len <= cf_env_estimate_len(20));

    env_report rep;
    std::string err;
    CHECK(env_report_parse(std::string_view(buf, len > 0 ? len : 0), rep, err));
    // 16 valid ones, of 20 with 4 invalid
    CHECK(rep.readings.size() == 16);
    CHECK(rep.skipped == 0);
    CHECK(rep.has_ts && rep.ts_s == 1700000000 && rep.ts_us == 250000);

    if (rep.readings.size() == 16) {
        CHECK(rep.readings[0].id == "s0" && rep.readings[0].label == std::string(64, 'x'));
        CHECK(rep.readings[1].kind == env_kind::battery && rep.readings[1].value == 55.5);
        CHECK(rep.readings[1].batt_state == KIS_EXTERNAL_V3_ENV_BATT_NOT_CHARGING);
        CHECK(rep.readings[1].ext_power == 1);
        CHECK(std::fabs(rep.readings[1].voltage - 12.6) < 0.001);
        CHECK(rep.readings[1].remaining_s == 7200);
        CHECK(rep.readings[2].kind == env_kind::fan && rep.readings[2].value == 3000);
        CHECK(rep.readings[3].id == "s7");
        CHECK(rep.readings[15].id == "s19");
    }

    // Nothing valid: nothing to send
    cf_env_reading_t bad;
    memset(&bad, 0, sizeof(bad));
    bad.id = "";
    bad.kind = KIS_EXTERNAL_V3_ENV_KIND_THERMAL;
    CHECK(cf_env_encode(buf, sizeof(buf), &bad, 1, nullptr) == 0);
    CHECK(cf_env_encode(buf, sizeof(buf), nullptr, 1, nullptr) == 0);

    // A buffer too small fails rather than overrunning
    CHECK(cf_env_encode(buf, 8, r, 20, &tv) == -1);

    // No timestamp
    len = cf_env_encode(buf, sizeof(buf), r, 1, nullptr);
    CHECK(len > 0 && env_report_parse(std::string_view(buf, len > 0 ? len : 0), rep, err) && !rep.has_ts);
}

// Fixture tree helpers
static std::string fixroot;

static void wfile(const std::string& rel, const std::string& content) {
    auto path = fixroot + "/" + rel;
    for (size_t p = fixroot.length() + 1; (p = path.find('/', p)) != std::string::npos; p++)
        mkdir(path.substr(0, p).c_str(), 0755);
    FILE *f = fopen(path.c_str(), "w");
    if (f == nullptr) {
        fprintf(stderr, "can't write %s\n", path.c_str());
        exit(2);
    }
    fputs(content.c_str(), f);
    fclose(f);
}

static int rm_cb(const char *path, const struct stat *, int, struct FTW *) {
    return remove(path);
}

// The single-battery sysfs code before this change, with the root as an argument,
// for the old-vs-new comparison
static int legacy_battery(const std::string& root, kis_battery_info *out) {
    out->percentage = 0; out->charging = 0; out->remaining_sec = 0; out->ac = 1;
    FILE *f;
    struct stat statbuf;
    std::string bdir, fpath;
    char *line;
    size_t linesz;
    int on_ac = 0, charging = 0;
    long power_now, current_now, charge_now, energy_now, voltage_now, charge_full, energy_full;
    long present_rate = -1, remaining_capacity = -1, remaining_energy = -1, last_capacity = -1,
         last_capacity_unit = -1, voltage = -1, seconds_remaining = -1;
    int percentage = 0;
    struct { const char *filename; long *target; } filepairs[] = {
        { "power_now", &power_now }, { "current_now", &current_now }, { "charge_now", &charge_now },
        { "energy_now", &energy_now }, { "voltage_now", &voltage_now }, { "charge_full", &charge_full },
        { "energy_full", &energy_full }, { "end", NULL } };
    bdir = root + "/BAT0";
    if (stat(bdir.c_str(), &statbuf) < 0) {
        bdir = root + "/BAT1";
        if (stat(bdir.c_str(), &statbuf) < 0)
            return -1;
    }
    fpath = bdir + "/status";
    if ((f = fopen(fpath.c_str(), "r")) == NULL)
        return -1;
    line = NULL; linesz = 0;
    if (getline(&line, &linesz, f) < 0) { }
    fclose(f);
    if (line != NULL && strcasestr(line, "discharging") == line) {
        on_ac = 0;
    } else if (line != NULL && strcasestr(line, "charging") == line) {
        on_ac = 1;
        charging = 1;
    }
    free(line);
    for (int itr = 0; filepairs[itr].target != NULL; itr++) {
        fpath = bdir + "/" + filepairs[itr].filename;
        if ((f = fopen(fpath.c_str(), "r")) != NULL) {
            if (fscanf(f, "%lu", (unsigned long *) filepairs[itr].target) != 1)
                *(filepairs[itr].target) = -1L;
            fclose(f);
        } else {
            *(filepairs[itr].target) = -1L;
        }
    }
    if (charge_now != -1) remaining_capacity = charge_now / 1000L;
    else if (energy_now != -1) remaining_energy = energy_now / 1000L;
    if (current_now != -1) present_rate = current_now / 1000L;
    else if (power_now != -1) present_rate = power_now / 1000L;
    if (charge_full != -1) last_capacity = charge_full / 1000L;
    else if (energy_full != -1) last_capacity_unit = energy_full / 1000L;
    if (voltage_now != -1) voltage = voltage_now / 1000L;
    if (last_capacity_unit != -1 && last_capacity == -1) {
        if (voltage == 0) last_capacity = 0;
        else if (voltage != -1) last_capacity = last_capacity_unit * 1000L / voltage;
        else last_capacity = last_capacity_unit;
    }
    if (remaining_energy != -1 && remaining_capacity == -1) {
        if (voltage == 0) remaining_capacity = 0;
        else if (voltage != -1) {
            remaining_capacity = remaining_energy * 1000 / voltage;
            present_rate = present_rate * 1000 / voltage;
        } else remaining_capacity = remaining_energy;
    }
    percentage = last_capacity <= 0 ? 0 : remaining_capacity * 100 / last_capacity;
    seconds_remaining = present_rate <= 0 ? 0 : 3600 * remaining_capacity / present_rate;
    out->percentage = percentage;
    out->charging = charging;
    out->ac = on_ac;
    out->remaining_sec = seconds_remaining;
    return 1;
}

static std::string charging_str(const kis_battery_info& b) {
    if (b.ac && b.charging)
        return "charging";
    if (b.ac)
        return "charged";
    return "discharging";
}

static void new_battery(const std::string& root, kis_battery_info *out,
        std::vector<kis_battery_reading>* list = nullptr, int *ext = nullptr) {
    std::vector<kis_battery_reading> b;
    int e;
    fetch_linux_power_supplies(root, b, e);
    aggregate_battery_info(b, e, out);
    if (list != nullptr)
        *list = b;
    if (ext != nullptr)
        *ext = e;
}

static void test_power_supply() {
    // Charge-based battery, charging, with an AC adapter
    std::string ps = "ps1";
    wfile(ps + "/BAT0/type", "Battery\n");
    wfile(ps + "/BAT0/status", "Charging\n");
    wfile(ps + "/BAT0/charge_now", "3000000\n");
    wfile(ps + "/BAT0/charge_full", "4000000\n");
    wfile(ps + "/BAT0/current_now", "1500000\n");
    wfile(ps + "/BAT0/voltage_now", "12100000\n");
    wfile(ps + "/AC/type", "Mains\n");
    wfile(ps + "/AC/online", "1\n");

    kis_battery_info o, n;
    legacy_battery(fixroot + "/" + ps, &o);
    std::vector<kis_battery_reading> list;
    int ext;
    new_battery(fixroot + "/" + ps, &n, &list, &ext);
    CHECK(o.percentage == 75 && n.percentage == 75);
    CHECK(o.charging == n.charging && o.ac == n.ac && o.remaining_sec == n.remaining_sec);
    CHECK(n.remaining_sec == 7200);
    CHECK(charging_str(n) == "charging");
    CHECK(list.size() == 1 && ext == 1);
    if (list.size() == 1) {
        CHECK(list[0].name == "BAT0" && list[0].state == kis_battery_state::charging);
        CHECK(std::fabs(list[0].voltage - 12.1) < 0.0001);
    }

    std::vector<env_host_reading> hr;
    env_battery_readings(list, ext, hr);
    CHECK(hr.size() == 1);
    if (hr.size() == 1) {
        CHECK(hr[0].id == "system-battery-BAT0" && hr[0].kind == env_kind::battery);
        CHECK(hr[0].value == 75 && hr[0].ext_power == 1 && hr[0].remaining_s == 7200);
    }

    // Discharging, AC offline: the same old and new
    wfile(ps + "/BAT0/status", "Discharging\n");
    wfile(ps + "/AC/online", "0\n");
    legacy_battery(fixroot + "/" + ps, &o);
    new_battery(fixroot + "/" + ps, &n);
    CHECK(o.percentage == n.percentage && o.charging == n.charging && o.ac == n.ac &&
            o.remaining_sec == n.remaining_sec);
    CHECK(charging_str(o) == "discharging" && charging_str(n) == "discharging");

    // Full and not charging on AC: old said discharging (bug 2), new says charged
    for (const char *st : {"Full\n", "Not charging\n"}) {
        wfile(ps + "/BAT0/status", st);
        wfile(ps + "/AC/online", "1\n");
        legacy_battery(fixroot + "/" + ps, &o);
        new_battery(fixroot + "/" + ps, &n);
        CHECK(charging_str(o) == "discharging");
        CHECK(charging_str(n) == "charged");
        CHECK(o.percentage == n.percentage && o.remaining_sec == n.remaining_sec);

        // Without an adapter that reports, the battery state alone means AC
        wfile(ps + "/AC/type", "Wireless\n");
        unlink((fixroot + "/" + ps + "/AC/online").c_str());
        new_battery(fixroot + "/" + ps, &n);
        CHECK(charging_str(n) == "charged");
        wfile(ps + "/AC/type", "Mains\n");
    }

    // Unknown with the adapter offline is on battery; with no adapter, not discharging is AC
    wfile(ps + "/BAT0/status", "Unknown\n");
    wfile(ps + "/AC/online", "0\n");
    new_battery(fixroot + "/" + ps, &n);
    CHECK(n.ac == 0);
    wfile(ps + "/AC/type", "Wireless\n");
    new_battery(fixroot + "/" + ps, &n);
    CHECK(n.ac == 0);
    unlink((fixroot + "/" + ps + "/AC/online").c_str());
    new_battery(fixroot + "/" + ps, &n);
    CHECK(n.ac == 1);

    // Energy-based battery with voltage conversion: same as old
    std::string pe = "ps2";
    wfile(pe + "/BAT1/type", "Battery\n");
    wfile(pe + "/BAT1/status", "Discharging\n");
    wfile(pe + "/BAT1/energy_now", "25000000\n");
    wfile(pe + "/BAT1/energy_full", "50000000\n");
    wfile(pe + "/BAT1/power_now", "10000000\n");
    wfile(pe + "/BAT1/voltage_now", "11400000\n");
    legacy_battery(fixroot + "/" + pe, &o);
    new_battery(fixroot + "/" + pe, &n, &list);
    // 25 Wh of 50 at 11.4 V, in the integer mAh math: 2192 of 4385 mAh, 877 mA
    CHECK(o.percentage == 49 && n.percentage == 49);
    CHECK(o.remaining_sec == n.remaining_sec && n.remaining_sec == 3600 * 2192 / 877);
    CHECK(o.ac == n.ac && o.charging == n.charging);

    // Energy without voltage: same as old
    unlink((fixroot + "/" + pe + "/BAT1/voltage_now").c_str());
    legacy_battery(fixroot + "/" + pe, &o);
    new_battery(fixroot + "/" + pe, &n);
    CHECK(o.percentage == n.percentage && o.remaining_sec == n.remaining_sec);

    // Voltage 0: same as old
    wfile(pe + "/BAT1/voltage_now", "0\n");
    legacy_battery(fixroot + "/" + pe, &o);
    new_battery(fixroot + "/" + pe, &n);
    CHECK(o.percentage == n.percentage && o.remaining_sec == n.remaining_sec);

    // Capacity only (old reported 0)
    std::string pc = "ps3";
    wfile(pc + "/BAT0/type", "Battery\n");
    wfile(pc + "/BAT0/status", "Discharging\n");
    wfile(pc + "/BAT0/capacity", "64\n");
    legacy_battery(fixroot + "/" + pc, &o);
    new_battery(fixroot + "/" + pc, &n);
    CHECK(o.percentage == 0 && n.percentage == 64);

    // Garbage, huge and negative values
    wfile(pc + "/BAT0/capacity", "lots\n");
    wfile(pc + "/BAT0/charge_now", "99999999999999999999999\n");
    wfile(pc + "/BAT0/charge_full", "-5\n");
    wfile(pc + "/BAT0/current_now", "12abc\n");
    new_battery(fixroot + "/" + pc, &n, &list);
    CHECK(n.percentage == 0 && n.remaining_sec == 0);
    CHECK(list.size() == 1 && list[0].percentage == -1);
    hr.clear();
    env_battery_readings(list, -1, hr);
    CHECK(hr.empty());

    // Over 100 percent is capped
    wfile(pc + "/BAT0/charge_now", "5000000\n");
    wfile(pc + "/BAT0/charge_full", "4000000\n");
    new_battery(fixroot + "/" + pc, &n);
    CHECK(n.percentage == 100);

    // A negative discharge current (some drivers) gives a remaining time
    wfile(pc + "/BAT0/charge_now", "2000000\n");
    wfile(pc + "/BAT0/current_now", "-1000000\n");
    new_battery(fixroot + "/" + pc, &n);
    CHECK(n.percentage == 50 && n.remaining_sec == 7200);

    // Empty status file and missing files
    wfile(pc + "/BAT0/status", "");
    new_battery(fixroot + "/" + pc, &n, &list);
    CHECK(list.size() == 1 && list[0].state == kis_battery_state::unknown);

    // Several batteries: names past BAT1, sorted, peripherals and absent ones left out
    std::string pm = "ps4";
    for (const char *b : {"BAT2", "CMB0", "macsmc-battery"}) {
        wfile(pm + "/" + b + "/type", "Battery\n");
        wfile(pm + "/" + b + "/status", "Discharging\n");
        wfile(pm + "/" + b + "/charge_now", "1000000\n");
        wfile(pm + "/" + b + "/charge_full", "2000000\n");
        wfile(pm + "/" + b + "/current_now", "500000\n");
    }
    wfile(pm + "/hidpp_battery_0/type", "Battery\n");
    wfile(pm + "/hidpp_battery_0/scope", "Device\n");
    wfile(pm + "/hidpp_battery_0/capacity", "5\n");
    wfile(pm + "/BAT9/type", "Battery\n");
    wfile(pm + "/BAT9/present", "0\n");
    wfile(pm + "/bad name/type", "Battery\n");
    wfile(pm + "/.hidden/type", "Battery\n");
    wfile(pm + "/ucsi-source-psy-1/type", "USB\n");
    wfile(pm + "/ucsi-source-psy-1/online", "0\n");
    new_battery(fixroot + "/" + pm, &n, &list, &ext);
    CHECK(list.size() == 3);
    if (list.size() == 3)
        CHECK(list[0].name == "BAT2" && list[1].name == "CMB0" && list[2].name == "macsmc-battery");
    CHECK(n.percentage == 50 && n.remaining_sec == 7200);
    CHECK(ext == 0 && n.ac == 0);

    // A USB-C supply online, but too weak: the batteries still drain, so discharging
    // as before, while the readings show the external power
    wfile(pm + "/ucsi-source-psy-1/online", "1\n");
    new_battery(fixroot + "/" + pm, &n, &list, &ext);
    CHECK(ext == 1 && n.charging == 0);
    CHECK(charging_str(n) == "discharging");
    hr.clear();
    env_battery_readings(list, ext, hr);
    CHECK(hr.size() == 3 && hr[0].ext_power == 1 && hr[0].batt_state == kis_battery_state::discharging);

    // Old and new agree for a single discharging battery with the adapter online
    wfile(ps + "/BAT0/type", "Battery\n");
    wfile(ps + "/BAT0/status", "Discharging\n");
    wfile(ps + "/AC/type", "Mains\n");
    wfile(ps + "/AC/online", "1\n");
    legacy_battery(fixroot + "/" + ps, &o);
    new_battery(fixroot + "/" + ps, &n);
    CHECK(charging_str(o) == "discharging" && charging_str(n) == "discharging");

    // One battery charging and one draining reads as charging
    wfile(pm + "/CMB0/status", "Charging\n");
    new_battery(fixroot + "/" + pm, &n);
    CHECK(charging_str(n) == "charging");
    wfile(pm + "/CMB0/status", "Discharging\n");

    // Huge but in-range values don't overflow the remaining time or the percentage
    std::string ph = "ps6";
    wfile(ph + "/BAT0/type", "Battery\n");
    wfile(ph + "/BAT0/status", "Discharging\n");
    wfile(ph + "/BAT0/energy_now", "999999999999\n");
    wfile(ph + "/BAT0/energy_full", "999999999999\n");
    wfile(ph + "/BAT0/power_now", "1000\n");
    wfile(ph + "/BAT0/voltage_now", "1000\n");
    new_battery(fixroot + "/" + ph, &n, &list);
    CHECK(list.size() == 1 && n.percentage == 100);
    CHECK(n.remaining_sec == 2147483647);
    CHECK(list.size() == 1 && list[0].remaining_sec == 2147483647);
    wfile(ph + "/BAT0/energy_now", "1000000000001\n");
    new_battery(fixroot + "/" + ph, &n, &list);
    CHECK(list.size() == 1 && list[0].remaining_capacity == -1);

    // No batteries at all is AC, like before
    std::string pn = "ps5";
    wfile(pn + "/AC/type", "Mains\n");
    wfile(pn + "/AC/online", "1\n");
    new_battery(fixroot + "/" + pn, &n, &list);
    CHECK(list.empty() && n.ac == 1 && n.percentage == 0 && n.charging == 0);
    new_battery(fixroot + "/nonexistent", &n, &list);
    CHECK(list.empty() && n.ac == 1);
}

static void test_hwmon_thermal() {
    std::string h = "hwmon";
    wfile(h + "/hwmon0/name", "coretemp\n");
    wfile(h + "/hwmon0/temp1_input", "45000\n");
    wfile(h + "/hwmon0/temp1_label", "Package id 0\n");
    wfile(h + "/hwmon0/temp2_input", "43500\n");
    wfile(h + "/hwmon0/temp2_crit", "100000\n");
    wfile(h + "/hwmon3/name", "thinkpad fan/\x01\n");
    wfile(h + "/hwmon3/fan1_input", "2900\n");
    wfile(h + "/hwmon3/fan2_input", "garbage\n");
    wfile(h + "/hwmon3/temp10_input", "-5000\n");
    wfile(h + "/hwmonX/name", "nope\n");
    wfile(h + "/notahwmon/name", "nope\n");

    std::vector<env_host_reading> out;
    env_read_hwmon(fixroot + "/" + h, out);
    CHECK(out.size() == 4);
    if (out.size() == 4) {
        CHECK(out[0].id == "coretemp-temp1" && out[0].label == "Package id 0 (coretemp)");
        CHECK(out[0].kind == env_kind::thermal && out[0].value == 45.0);
        CHECK(out[1].id == "coretemp-temp2" && out[1].label == "temp2 (coretemp)" && out[1].value == 43.5);
        CHECK(out[2].id == "thinkpad_fan__-temp10" && out[2].value == -5.0);
        CHECK(out[3].id == "thinkpad_fan__-fan1" && out[3].kind == env_kind::fan && out[3].value == 2900);
        for (const auto& r : out)
            CHECK(r.id.find('/') == std::string::npos);
    }

    // Shared names: told apart by their devices, whatever the hwmon numbers
    std::vector<std::string> ids_a, ids_b;
    for (int pass = 0; pass < 2; pass++) {
        std::string hd = pass == 0 ? "hwmon_dup_a" : "hwmon_dup_b";
        // The second tree numbers the same devices the other way round
        const char *first = pass == 0 ? "hwmon1" : "hwmon2";
        const char *second = pass == 0 ? "hwmon2" : "hwmon1";
        wfile("devices/0000_01_00.0/x", "");
        wfile("devices/0000_02_00.0/x", "");
        wfile(hd + "/" + first + "/name", "nvme\n");
        wfile(hd + "/" + first + "/temp1_input", "30000\n");
        wfile(hd + "/" + second + "/name", "nvme\n");
        wfile(hd + "/" + second + "/temp1_input", "40000\n");
        CHECK(symlink((fixroot + "/devices/0000_01_00.0").c_str(), (fixroot + "/" + hd + "/" + first + "/device").c_str()) == 0);
        CHECK(symlink((fixroot + "/devices/0000_02_00.0").c_str(), (fixroot + "/" + hd + "/" + second + "/device").c_str()) == 0);
        // Two without devices fall back to their position
        wfile(hd + "/hwmon5/name", "acpi\n");
        wfile(hd + "/hwmon5/temp1_input", "1000\n");
        wfile(hd + "/hwmon7/name", "acpi\n");
        wfile(hd + "/hwmon7/temp1_input", "2000\n");

        out.clear();
        env_read_hwmon(fixroot + "/" + hd, out);
        CHECK(out.size() == 4);
        auto& ids = pass == 0 ? ids_a : ids_b;
        for (const auto& r : out)
            ids.push_back(fmt::format("{}={}", r.id, r.value));
        std::sort(ids.begin(), ids.end());
    }
    CHECK(ids_a == ids_b);
    CHECK(std::find(ids_a.begin(), ids_a.end(), "nvme-0000_01_00.0-temp1=30") != ids_a.end());
    CHECK(std::find(ids_a.begin(), ids_a.end(), "nvme-0000_02_00.0-temp1=40") != ids_a.end());
    CHECK(std::find(ids_a.begin(), ids_a.end(), "acpi-0-temp1=1") != ids_a.end());
    CHECK(std::find(ids_a.begin(), ids_a.end(), "acpi-1-temp1=2") != ids_a.end());

    std::string t = "thermal";
    wfile(t + "/thermal_zone0/temp", "51000\n");
    wfile(t + "/thermal_zone0/type", "x86_pkg_temp\n");
    wfile(t + "/thermal_zone1/type", "iwlwifi_1\n");
    wfile(t + "/thermal_zone1/temp", "\n");
    wfile(t + "/thermal_zone2/temp", "38500\n");
    wfile(t + "/thermal_zone4/temp", "99000\n");

    out.clear();
    env_read_thermal_zones(fixroot + "/" + t, out);
    // zone1 can't be read, zone3 is missing so zone4 is never reached
    CHECK(out.size() == 2);
    if (out.size() == 2) {
        CHECK(out[0].id == "system-thermal-0" && out[0].label == "x86_pkg_temp" && out[0].value == 51.0);
        CHECK(out[1].id == "system-thermal-2" && out[1].label == "thermal zone 2" && out[1].value == 38.5);
    }

    out.clear();
    env_read_hwmon(fixroot + "/none", out);
    env_read_thermal_zones(fixroot + "/none", out);
    CHECK(out.empty());
}

int main() {
    Globalreg::globalreg = new global_registry;
    auto entrytracker = entry_tracker::create_entrytracker();

    const char *tmp = getenv("TMPDIR");
    std::string tmpl = fmt::format("{}/env_test.XXXXXX", tmp != nullptr ? tmp : "/tmp");
    std::vector<char> tbuf(tmpl.begin(), tmpl.end());
    tbuf.push_back(0);
    if (mkdtemp(tbuf.data()) == nullptr) {
        fprintf(stderr, "mkdtemp failed\n");
        return 2;
    }
    fixroot = tbuf.data();

    test_parse_good();
    test_parse_malformed();
    test_parse_skips();
    test_store_sources();
    test_store_stale();
    test_store_current();
    test_store_off();
    test_store_host();
    test_round_trip();
    test_power_supply();
    test_hwmon_thermal();

    nftw(fixroot.c_str(), rm_cb, 16, FTW_DEPTH | FTW_PHYS);

    if (failures) {
        fprintf(stderr, "%d of %d check(s) failed\n", failures, checks);
        return 1;
    }

    printf("environment tests passed (%d checks)\n", checks);
    return 0;
}
