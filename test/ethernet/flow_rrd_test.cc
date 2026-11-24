/* Tests that a wired flow's history serializes like a kis_tracked_rrd: the same field ids,
 * JSON types and vector lengths, and the same values for the samples both are fed.  Also
 * feeds the flow table's rates into real RRDs, as the phy does.
 *
 *   make test/ethernet/flow_rrd_test && test/ethernet/flow_rrd_test
 */

#include "config.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "entrytracker.h"
#include "globalregistry.h"
#include "json_adapter.h"
#include "nlohmann/json.hpp"
#include "trackedrrd.h"
#include "wired_flow_history.h"
#include "wired_flow_rrd.h"
#include "wired_flow_tracker.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

using series = flow_history::series;

constexpr time_t base_time = 1700000000 - (1700000000 % 3600) + 1200;

struct sample {
    time_t t;
    bool ab;
    uint64_t bytes;
};

static nlohmann::json to_json(const std::shared_ptr<tracker_element>& e) {
    std::stringstream ss;
    json_adapter::pack(ss, e);
    return nlohmann::json::parse(ss.str());
}

static int field_id(const char *name) {
    return Globalreg::globalreg->entrytracker->get_field_id(name);
}

// Both fed the bytes a to b of samples, then serialized at now
static void feed(const std::vector<sample>& samples, time_t now, nlohmann::json& real, nlohmann::json& ours) {
    static const wired_flow_rrd builder;

    auto rrd = std::make_shared<kis_tracked_rrd<>>(field_id("test.flow.real_rrd"));
    flow_history h(samples.empty() ? now : samples[0].t);

    for (const auto& s : samples) {
        if (s.ab)
            rrd->add_sample(static_cast<double>(s.bytes), s.t);
        h.record(s.t, s.ab, s.bytes);
    }

    // As kis_ethernet_phy::flow_by_key_endpoint does, through wired_flow_tracker::lookup
    h.advance_to(now);
    Globalreg::globalreg->last_tv_sec = now;

    real = to_json(rrd);
    ours = to_json(builder.build(field_id("test.flow.our_rrd"), h.vectors(series::bytes_ab), now));
}

static bool near_equal(double a, double b) {
    return std::fabs(a - b) <= 1e-9 * std::max(1.0, std::fabs(a));
}

static bool same_vec(const nlohmann::json& a, const nlohmann::json& b, bool exact) {
    if (!a.is_array() || !b.is_array() || a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); i++) {
        const double x = a[i].get<double>(), y = b[i].get<double>();
        if (exact ? x != y : !near_equal(x, y))
            return false;
    }
    return true;
}

// Every field ours has, kis_tracked_rrd has, with the same JSON type and length; it has two more
static void check_shape(const nlohmann::json& real, const nlohmann::json& ours) {
    CHECK(real.is_object() && ours.is_object());

    std::set<std::string> extra;
    for (const auto& [name, v] : real.items()) {
        if (!ours.contains(name)) {
            extra.insert(name);
            continue;
        }
        const auto& o = ours[name];
        CHECK(o.type() == v.type());
        if (v.is_array())
            CHECK(o.size() == v.size());
    }

    CHECK((extra == std::set<std::string>{"kismet.common.rrd.last_value", "kismet.common.rrd.last_value_n1"}));
    CHECK(ours.size() == 6 && real.size() == 8);
    CHECK(ours["kismet.common.rrd.minute_vec"].size() == 60 && ours["kismet.common.rrd.hour_vec"].size() == 60 &&
            ours["kismet.common.rrd.day_vec"].size() == 24);
    CHECK(ours["kismet.common.rrd.last_time"].is_number_unsigned());
    CHECK(ours["kismet.common.rrd.serial_time"].is_number_unsigned());
    CHECK(ours["kismet.common.rrd.blank_val"].get<double>() == 0);
}

// Registering our fields after kis_tracked_rrd did (or before) gives the same ids
static void test_field_ids() {
    kis_tracked_rrd<> first;
    const wired_flow_rrd builder;
    flow_history h(base_time);
    auto m = builder.build(field_id("test.flow.our_rrd"), h.vectors(series::bytes_ab), base_time);

    const char *names[] = {
        "kismet.common.rrd.last_time", "kismet.common.rrd.serial_time", "kismet.common.rrd.minute_vec",
        "kismet.common.rrd.hour_vec", "kismet.common.rrd.day_vec", "kismet.common.rrd.blank_val",
    };

    CHECK(m->size() == 6);
    for (const auto *n : names) {
        const auto id = field_id(n);
        CHECK(id != 0 && m->find(id) != m->end());
    }
}

// Samples in one minute: every vector the same
static void test_one_minute() {
    std::vector<sample> s;
    for (time_t t = 0; t < 50; t += 3)
        s.push_back({base_time + t, true, static_cast<uint64_t>(100 + t * 7)});
    s.push_back({base_time + 49, false, 999});      // the other way: not in bytes_ab
    s.push_back({base_time + 49, true, 1});

    nlohmann::json real, ours;
    feed(s, base_time + 55, real, ours);
    check_shape(real, ours);

    CHECK(real["kismet.common.rrd.last_time"] == ours["kismet.common.rrd.last_time"]);
    CHECK(real["kismet.common.rrd.serial_time"] == ours["kismet.common.rrd.serial_time"]);
    CHECK(ours["kismet.common.rrd.last_time"].get<uint64_t>() == static_cast<uint64_t>(base_time + 55));
    CHECK(same_vec(real["kismet.common.rrd.minute_vec"], ours["kismet.common.rrd.minute_vec"], true));
    CHECK(same_vec(real["kismet.common.rrd.hour_vec"], ours["kismet.common.rrd.hour_vec"], false));
    CHECK(same_vec(real["kismet.common.rrd.day_vec"], ours["kismet.common.rrd.day_vec"], false));

    double sum = 0;
    for (const auto& v : ours["kismet.common.rrd.minute_vec"])
        sum += v.get<double>();
    CHECK(sum > 0);
}

// Gaps up to a minute over several minutes: the seconds the same.  Minutes and hours differ by
// design: kis_tracked_rrd keeps a minute's average over the 60 s before its last sample, which
// reaches into the minute before; ours is that minute's own total over 60, exact in JSON.
static void test_minutes() {
    std::vector<sample> s;
    time_t t = base_time;
    for (int i = 0; i < 400; i++) {
        t += (i * 7919) % 61;
        s.push_back({t, true, static_cast<uint64_t>(1 + (i * 104729) % 1500)});
    }

    nlohmann::json real, ours;
    feed(s, t + 3, real, ours);
    check_shape(real, ours);
    CHECK(real["kismet.common.rrd.last_time"] == ours["kismet.common.rrd.last_time"]);
    CHECK(same_vec(real["kismet.common.rrd.minute_vec"], ours["kismet.common.rrd.minute_vec"], true));

    // Seven bytes in one minute is 7/60 a second, with no float accumulation; the JSON writer
    // gives doubles 6 decimals, as for every RRD
    const auto json_double = [](double v) { return std::round(v * 1e6) / 1e6; };
    flow_history h(base_time);
    for (int i = 0; i < 7; i++)
        h.record(base_time, true, 1);
    h.advance_to(base_time + 61);
    const wired_flow_rrd builder;
    auto j = to_json(builder.build(field_id("test.flow.our_rrd"), h.vectors(series::bytes_ab), base_time + 61));
    CHECK(j["kismet.common.rrd.hour_vec"][static_cast<size_t>((base_time / 60) % 60)].get<double>() ==
            json_double(7.0 / 60));
    CHECK(j["kismet.common.rrd.day_vec"][static_cast<size_t>((base_time / 3600) % 24)].get<double>() ==
            json_double(7.0 / 3600));
}

// Nothing for a day: both blank
static void test_idle_day() {
    nlohmann::json real, ours;
    feed({{base_time, true, 500}}, base_time + 2 * 86400, real, ours);
    check_shape(real, ours);
    for (const auto *n : {"kismet.common.rrd.minute_vec", "kismet.common.rrd.hour_vec", "kismet.common.rrd.day_vec"}) {
        CHECK(same_vec(real[n], ours[n], true));
        for (const auto& v : ours[n])
            CHECK(v.get<double>() == 0);
    }
}

// The flow table's rates into real RRDs, as kis_ethernet_phy::sample_flow_rates feeds them:
// a second read twice sums the counts and keeps one gauge value; a late read spreads
static void test_table_rates() {
    using gauge_rrd = kis_tracked_rrd<kis_tracked_rrd_gauge_aggregator>;
    auto bytes = std::make_shared<kis_tracked_rrd<>>(field_id("test.flow.real_rrd"));
    auto active = std::make_shared<gauge_rrd>(field_id("test.flow.gauge_rrd"));
    bytes->update_before_serialize(false);
    active->update_before_serialize(false);

    wired_flow_rates rates;
    const auto read = [&](time_t now, uint64_t total_bytes, size_t n_flows) {
        wired_flow_tracker::totals t;
        t.bytes = total_bytes;
        t.flows = n_flows;
        const auto f = rates.next(now, t);
        CHECK(!f.restart);
        for (size_t s = 0; s < f.n_samples; s++)
            bytes->add_sample(static_cast<double>(f.samples[s].v[0]), f.samples[s].t);
        active->add_sample(static_cast<double>(f.flows), f.gauge_time);
    };

    const time_t t = base_time;
    read(t, 100, 5);
    read(t + 1, 300, 7);
    read(t + 1, 350, 7);
    read(t + 1, 360, 7);
    read(t + 4, 460, 4);    // three seconds late

    Globalreg::globalreg->last_tv_sec = t + 4;
    const auto b = to_json(bytes)["kismet.common.rrd.minute_vec"];
    const auto g = to_json(active)["kismet.common.rrd.minute_vec"];
    const auto at = [](time_t s) { return static_cast<size_t>(s % 60); };
    constexpr double blank = kis_tracked_rrd_gauge_aggregator::blank;

    CHECK(b[at(t)].get<double>() == 100);
    CHECK(b[at(t + 1)].get<double>() == 260);
    CHECK(b[at(t + 2)].get<double>() == 33);
    CHECK(b[at(t + 3)].get<double>() == 33);
    CHECK(b[at(t + 4)].get<double>() == 34);
    CHECK(g[at(t)].get<double>() == 5);
    CHECK(g[at(t + 1)].get<double>() == 7);
    CHECK(g[at(t + 2)].get<double>() == blank);
    CHECK(g[at(t + 3)].get<double>() == blank);
    CHECK(g[at(t + 4)].get<double>() == 4);

    double sum = 0;
    for (const auto& v : b)
        sum += v.get<double>();
    CHECK(sum == 460);
}

int main() {
    Globalreg::globalreg = new global_registry;
    auto entrytracker = entry_tracker::create_entrytracker();

    entrytracker->register_field("test.flow.real_rrd", tracker_element_factory<kis_tracked_rrd<>>(), "real rrd");
    entrytracker->register_field("test.flow.our_rrd", tracker_element_factory<tracker_element_map>(), "flow rrd");
    entrytracker->register_field("test.flow.gauge_rrd",
            tracker_element_factory<kis_tracked_rrd<kis_tracked_rrd_gauge_aggregator>>(), "gauge rrd");

    test_field_ids();
    test_one_minute();
    test_minutes();
    test_idle_day();
    test_table_rates();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }

    printf("flow rrd tests passed\n");
    return 0;
}
