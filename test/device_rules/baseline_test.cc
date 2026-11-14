/* Tests for the device rules baseline grammar: baseline filter blocks, recheck, and the
 * time, activity, tag, baseline and alert terms, run through the tree, VM and JIT
 * backends with a stand-in for the device tracker.  Synthetic values only.
 *
 *   make test/device_rules/baseline_test && test/device_rules/baseline_test
 */

#include "config.h"

#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "devicerules/dr_core.h"

using namespace devicerules;

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

constexpr int64_t started = 1700000000;
constexpr int64_t hour = 3600;
constexpr int64_t day = 86400;

/* The fields the terms under test read, with the types the tracker gives them */
class test_resolver : public resolver {
public:
    int resolve(const std::string& name, ftype& t) override {
        static const std::map<std::string, ftype> fields = {
            {"kismet.device.base.tags", ftype::container},
            {"kismet.device.base.first_time", ftype::uinteger},
            {"kismet.device.base.last_time", ftype::uinteger},
            {"kismet.device.base.packets.total", ftype::uinteger},
            {"kismet.device.base.name", ftype::string},
            {"kismet.device.base.packets.rrd", ftype::map},
            {"kismet.device.base.days_seen", ftype::uinteger},
            {"kismet.device.base.alerts", ftype::map},
            {"kismet.device.alerts.sent", ftype::uinteger},
            {"kismet.device.alerts.sent_severity", ftype::uinteger},
            {"kismet.device.alerts.sent_classes", ftype::string_list},
            {"kismet.device.alerts.own_sent", ftype::uinteger},
            {"kismet.device.alerts.own_severity", ftype::uinteger},
            {"dot11.device", ftype::map},
            {"dot11.device.randomized_mac", ftype::integer},
            {"dot11.device.alias_group", ftype::uinteger},
            {"dot11.device.last_bssid", ftype::mac},
            {"btle.device", ftype::map},
            {"btle.device.random_address_type", ftype::string},
            {"btle.device.alias_group", ftype::uinteger},
        };
        auto f = fields.find(name);
        if (f == fields.end())
            return -1;
        t = f->second;
        return static_cast<int>(std::distance(fields.begin(), f)) + 1;
    }
};

/* One device; the derived values are what the tracker's env works out */
struct test_device {
    std::map<std::string, int64_t> ints;
    std::map<std::string, std::string> strs;
    std::map<std::string, std::vector<std::string>> lists;
    std::map<std::string, uint64_t> macs;
    std::map<std::string, std::string> tags;
    int64_t hours_active = -1;
    int64_t days_active = -1;
};

class test_env : public env {
public:
    const test_device *d = nullptr;
    std::set<uint64_t> baseline;

    bool load(const field_slot& f, value& out) override {
        out.valid = 1;
        switch (f.how) {
            case derive::tag_number: {
                auto t = d->tags.find(f.key);
                if (t == d->tags.end() || t->second.empty())
                    return false;
                char *end = nullptr;
                out.i = strtoll(t->second.c_str(), &end, 10);
                return *end == 0;
            }
            case derive::hours_active:
                out.i = d->hours_active;
                return d->hours_active >= 0;
            case derive::days_active:
                out.i = d->days_active;
                return d->days_active >= 0;
            default:
                break;
        }
        if (auto i = d->ints.find(f.text); i != d->ints.end()) {
            out.i = i->second;
            return true;
        }
        if (auto s = d->strs.find(f.text); s != d->strs.end()) {
            out.s = s->second.c_str();
            out.len = static_cast<uint32_t>(s->second.size());
            return true;
        }
        if (auto m = d->macs.find(f.text); m != d->macs.end()) {
            out.m = m->second;
            return true;
        }
        return false;
    }

    bool any(const field_slot& f, bool (*fn)(const value&, const void *), const void *arg) override {
        auto l = d->lists.find(f.text);
        if (l == d->lists.end())
            return false;
        for (const auto& s : l->second) {
            value v;
            v.s = s.c_str();
            v.len = static_cast<uint32_t>(s.size());
            v.valid = 1;
            if (fn(v, arg))
                return true;
        }
        return false;
    }

    int64_t count(const field_slot& f) override {
        auto l = d->lists.find(f.text);
        return l == d->lists.end() ? 0 : static_cast<int64_t>(l->second.size());
    }

    bool exists(const field_slot& f) override {
        if (f.how == derive::baseline_mac) {
            auto m = d->macs.find(f.text);
            return m != d->macs.end() && baseline.count(m->second) != 0;
        }
        if (!f.key.empty())
            return d->tags.count(f.key) != 0;
        return d->ints.count(f.text) || d->strs.count(f.text) || d->lists.count(f.text) || d->macs.count(f.text);
    }
};

/* Parse and compile, returning the error text, or "" */
static std::string build(ruleset& rs, const std::string& text,
        parse_source::block only = parse_source::block::any) {
    try {
        parse_source src;
        src.only = only;
        rs.parse(text, src);
        test_resolver res;
        rs.compile(res);
    } catch (const parse_error& e) {
        return e.what();
    }
    return "";
}

static bool fails_with(const std::string& text, const std::string& want,
        parse_source::block only = parse_source::block::any) {
    ruleset rs;
    auto err = build(rs, text, only);
    if (err.find(want) == std::string::npos) {
        fprintf(stderr, "  rule: %s\n  wanted an error with '%s', got '%s'\n", text.c_str(), want.c_str(), err.c_str());
        return false;
    }
    return true;
}

/* Rule 0 of text against each device at now, through every backend; the backends must
 * agree, and match want */
static bool matches(const std::string& text, const std::vector<test_device>& devs, int64_t now,
        const std::vector<bool>& want, const std::set<uint64_t>& baseline = {}) {
    ruleset rs;
    auto err = build(rs, text);
    if (!err.empty()) {
        fprintf(stderr, "  rule: %s\n  error: %s\n", text.c_str(), err.c_str());
        return false;
    }

    test_env e;
    e.baseline = baseline;
    eval_ctx ctx;
    ctx.bind(&rs, &e);

    std::vector<bool> tree, vm, jit;
    for (const auto& d : devs) {
        e.d = &d;
        ctx.next_device(now);
        tree.push_back(rs.eval_tree(ctx, 0));
        ctx.next_device(now);
        vm.push_back(rs.eval_vm(ctx, 0));
    }

    std::string jerr;
    if (rs.jit(jerr)) {
        uint8_t out = 0;
        for (const auto& d : devs) {
            e.d = &d;
            ctx.next_device(now);
            rs.eval_all(ctx, nullptr, &out);
            jit.push_back(out != 0);
        }
    } else {
        static bool told = false;
        if (!told)
            fprintf(stderr, "no JIT here (%s); checking the tree and VM only\n", jerr.c_str());
        told = true;
        jit = vm;
    }

    bool ok = tree == want && vm == want && jit == want;
    if (!ok) {
        fprintf(stderr, "  rule: %s\n", text.c_str());
        for (size_t i = 0; i < devs.size(); i++)
            fprintf(stderr, "    device %zu: want %d tree %d vm %d jit %d\n", i, (int) want[i],
                    (int) tree[i], (int) vm[i], (int) jit[i]);
    }
    return ok;
}

static void test_baseline_block() {
    ruleset rs;
    CHECK(build(rs, "baseline b1 { description \"x\" when packets > 10 add }") == "");
    CHECK(rs.size() == 1);
    const auto& r = rs.rule(0);
    CHECK(r.baseline && !r.remove && !r.ephemeral);
    CHECK(r.every == baseline_every_default && r.expire == 0);
    CHECK(r.description == "x");
    /* Baseline filters never collect a view, alert or exclude */
    CHECK(!r.view && !r.alert && !r.exclude && r.tags.empty());

    ruleset rs2;
    CHECK(build(rs2, "baseline b2 { when packets > 10 every 5m add ephemeral expire 1d }") == "");
    CHECK(rs2.rule(0).every == 300 && rs2.rule(0).expire == day && rs2.rule(0).ephemeral);

    ruleset rs3;
    CHECK(build(rs3, "baseline b3 { when packets > 10 remove every 10s }") == "");
    CHECK(rs3.rule(0).remove && rs3.rule(0).every == 10);

    /* The config line form, without the keyword */
    ruleset rs4;
    CHECK(build(rs4, "b4 { when packets > 10 add }", parse_source::block::baseline) == "");
    CHECK(rs4.size() == 1 && rs4.rule(0).baseline && rs4.rule(0).name == "b4");

    /* Mixed with rules and sorts in one file */
    ruleset rs5;
    CHECK(build(rs5, "rule r { when packets > 1 tag \"t\" }\nbaseline b { when packets > 2 add }\n"
                "sort s { by packets desc }") == "");
    CHECK(rs5.size() == 2 && !rs5.rule(0).baseline && rs5.rule(1).baseline && rs5.sort_count() == 1);
}

static void test_baseline_errors() {
    CHECK(fails_with("baseline b { when packets > 1 }", "needs 'add' or 'remove'"));
    CHECK(fails_with("baseline b { when packets > 1 add remove }", "either adds or removes"));
    CHECK(fails_with("baseline b { when packets > 1 add add }", "either adds or removes"));
    CHECK(fails_with("baseline b { add }", "has no 'when'"));
    CHECK(fails_with("baseline b { when packets > 1 when packets > 2 add }", "more than one 'when'"));
    CHECK(fails_with("baseline b { when packets > 1 remove expire 1d }", "'expire' is only for 'add'"));
    CHECK(fails_with("baseline b { when packets > 1 add every 9s }", "every"));
    CHECK(fails_with("baseline b { when packets > 1 add every 8d }", "every"));
    CHECK(fails_with("baseline b { when packets > 1 add every 1m every 2m }", "more than one 'every'"));
    CHECK(fails_with("baseline b { when packets > 1 add expire 30s }", "expire"));
    CHECK(fails_with("baseline b { when packets > 1 add expire 366d }", "expire"));
    CHECK(fails_with("baseline b { when packets > 1 add tag \"x\" }", "unknown baseline filter statement 'tag'"));
    CHECK(fails_with("baseline b { when packets > 1 add", "missing '}'"));
    /* A config line holds one filter */
    {
        ruleset rs;
        CHECK(build(rs, "b { when packets > 1 add } b2 { when packets > 1 add }", parse_source::block::baseline) != "");
    }
}

static void test_recheck() {
    ruleset rs;
    CHECK(build(rs, "rule r { when age(last_time) > 1h recheck 5m tag \"old\" }") == "");
    CHECK(rs.rule(0).recheck == 300 && rs.rule(0).uses_now);

    /* Each of the time-dependent terms allows it */
    for (const char *c : {"uptime > 1h", "hours_active > 2", "days_active > 1",
            "in_baseline(dot11.device/dot11.device.last_bssid)", "now - first_time > 1d"}) {
        ruleset r2;
        auto err = build(r2, std::string("rule r { when ") + c + " recheck 1m tag \"t\" }");
        CHECK(err == "");
        if (err.empty())
            CHECK(r2.rule(0).uses_now);
    }

    CHECK(fails_with("rule r { when packets > 10 recheck 5m tag \"t\" }", "'recheck' needs a condition"));
    /* start_time alone doesn't change */
    CHECK(fails_with("rule r { when first_time < start_time recheck 5m tag \"t\" }", "'recheck' needs a condition"));
    CHECK(fails_with("rule r { when age(last_time) > 1h recheck 0s tag \"t\" }", "recheck"));
    CHECK(fails_with("rule r { when age(last_time) > 1h recheck 8d tag \"t\" }", "recheck"));
    CHECK(fails_with("rule r { when age(last_time) > 1h recheck 1m recheck 2m tag \"t\" }", "more than one 'recheck'"));
}

static void test_term_errors() {
    CHECK(fails_with("rule r { when in_baseline(btle.device/btle.device.random_address_type) tag \"t\" }",
                "in_baseline() needs a field holding one MAC"));
    CHECK(fails_with("rule r { when in_baseline(\"x\") tag \"t\" }", "in_baseline() needs a MAC address field"));
    CHECK(fails_with("rule r { when tag_time() > 0 tag \"t\" }", "tag_time() needs a tag name"));
    CHECK(fails_with("rule r { when tag_time(\"" + std::string(max_tag_name + 1, 'a') + "\") > 0 tag \"t\" }",
                "tag name is too long"));
}

static void test_time_terms() {
    test_device early, late;
    early.ints["kismet.device.base.first_time"] = started + 60;
    late.ints["kismet.device.base.first_time"] = started + 2 * hour;
    std::vector<test_device> devs{early, late};

    CHECK(matches("rule r { when first_time < start_time + 5m tag \"t\" }", devs, started + 3 * hour, {true, false}));
    CHECK(matches("rule r { when uptime > 1h tag \"t\" }", devs, started + 3 * hour, {true, true}));
    CHECK(matches("rule r { when uptime > 1h tag \"t\" }", devs, started + 30 * 60, {false, false}));
}

static void test_activity_terms() {
    test_device steady, brief, unknown;
    steady.hours_active = 20;
    steady.days_active = 5;
    brief.hours_active = 1;
    brief.days_active = 1;
    std::vector<test_device> devs{steady, brief, unknown};

    /* A device without the record doesn't match either way */
    CHECK(matches("rule r { when hours_active >= 12 tag \"t\" }", devs, started, {true, false, false}));
    CHECK(matches("rule r { when hours_active < 12 tag \"t\" }", devs, started, {false, true, false}));
    CHECK(matches("rule r { when days_active >= 2 tag \"t\" }", devs, started, {true, false, false}));
}

static void test_tag_terms() {
    test_device old_tag, new_tag, text_tag, none;
    old_tag.tags["baseline"] = std::to_string(started - 3 * day);
    new_tag.tags["baseline"] = std::to_string(started - hour);
    text_tag.tags["baseline"] = "yes";
    std::vector<test_device> devs{old_tag, new_tag, text_tag, none};

    CHECK(matches("rule r { when tag_time(\"baseline\") < now - 1d tag \"t\" }", devs, started,
                {true, false, false, false}));
    CHECK(matches("rule r { when has_tag(\"baseline\") tag \"t\" }", devs, started, {true, true, true, false}));
    CHECK(matches("rule r { when not has_tag(\"baseline\") tag \"t\" }", devs, started, {false, false, false, true}));
}

static void test_in_baseline() {
    constexpr uint64_t ap_known = 0x020000000a01, ap_new = 0x020000000a02;
    test_device client_known, client_new, no_bssid;
    client_known.macs["dot11.device/dot11.device.last_bssid"] = ap_known;
    client_new.macs["dot11.device/dot11.device.last_bssid"] = ap_new;
    std::vector<test_device> devs{client_known, client_new, no_bssid};

    CHECK(matches("rule r { when in_baseline(dot11.device/dot11.device.last_bssid) tag \"t\" }", devs, started,
                {true, false, false}, {ap_known}));
    CHECK(matches("rule r { when not in_baseline(dot11.device/dot11.device.last_bssid) tag \"t\" }", devs, started,
                {false, true, true}, {ap_known}));
}

static void test_random_linked() {
    test_device wifi_rand, wifi_fixed, wifi_linked, btle_rpa, btle_static, btle_nrpa;
    wifi_rand.ints["dot11.device/dot11.device.randomized_mac"] = 1;
    wifi_fixed.ints["dot11.device/dot11.device.randomized_mac"] = 0;
    wifi_linked.ints["dot11.device/dot11.device.randomized_mac"] = 1;
    wifi_linked.ints["dot11.device/dot11.device.alias_group"] = 7;
    btle_rpa.strs["btle.device/btle.device.random_address_type"] = "resolvable";
    btle_static.strs["btle.device/btle.device.random_address_type"] = "static";
    btle_nrpa.strs["btle.device/btle.device.random_address_type"] = "non-resolvable";
    std::vector<test_device> devs{wifi_rand, wifi_fixed, wifi_linked, btle_rpa, btle_static, btle_nrpa};

    CHECK(matches("rule r { when random_address tag \"t\" }", devs, started, {true, false, true, true, false, true}));
    CHECK(matches("rule r { when linked tag \"t\" }", devs, started, {false, false, true, false, false, false}));
    CHECK(matches("rule r { when random_address and not linked tag \"t\" }", devs, started,
                {true, false, false, true, false, true}));
}

static void test_alert_terms() {
    /* One alert per class, each with its severity; the linker counts the ones outside
     * DENIAL and SYSTEM as the device's own */
    using sent = std::vector<std::pair<std::string, int64_t>>;
    auto sender = [](const sent& alerts) {
        test_device d;
        int64_t sev = 0, own = 0, own_sev = 0;
        std::vector<std::string> classes;
        for (const auto& [c, s] : alerts) {
            classes.push_back(c);
            sev = std::max(sev, s);
            if (c != "DENIAL" && c != "denial" && c != "SYSTEM") {
                own++;
                own_sev = std::max(own_sev, s);
            }
        }
        const std::string a = "kismet.device.base.alerts/kismet.device.alerts.";
        d.ints[a + "sent"] = static_cast<int64_t>(alerts.size());
        d.ints[a + "sent_severity"] = sev;
        d.lists[a + "sent_classes"] = classes;
        if (own) {
            d.ints[a + "own_sent"] = own;
            d.ints[a + "own_severity"] = own_sev;
        }
        return d;
    };
    std::vector<test_device> devs{sender({{"EXPLOIT", 10}}), sender({{"denial", 10}}), sender({{"SYSTEM", 15}}),
        sender({{"EXPLOIT", 10}, {"DENIAL", 10}}), sender({{"PROBE", 0}}), test_device{},
        sender({{"PROBE", 0}, {"DENIAL", 15}})};

    /* Classes match in any case */
    CHECK(matches("rule r { when sent_alert_classes in [\"DENIAL\"] tag \"t\" }", devs, started,
                {false, true, false, true, false, false, true}));
    /* 'not in' is not (any value in the list): a device that sent a DENIAL alert as well as
     * another kind doesn't match */
    CHECK(matches("rule r { when sent_alert_classes not in [\"DENIAL\", \"SYSTEM\"] tag \"t\" }", devs, started,
                {true, false, false, false, true, true, false}));
    /* The highest severity can come from a DENIAL alert */
    CHECK(matches("rule r { when alerts_sent > 0 and alert_severity >= 5 tag \"t\" }", devs, started,
                {true, true, true, true, false, false, true}));
    /* The shipped 'alerts' filter: an EXPLOIT alert counts even with a DENIAL one, and an
     * info alert doesn't count for a DENIAL alert's severity */
    CHECK(matches("baseline alerts { when own_alerts > 0 and own_alert_severity >= 5 remove }", devs, started,
                {true, false, false, true, false, false, false}));
}

int main() {
    set_start_time(started);

    test_baseline_block();
    test_baseline_errors();
    test_recheck();
    test_term_errors();
    test_time_terms();
    test_activity_terms();
    test_tag_terms();
    test_in_baseline();
    test_random_linked();
    test_alert_terms();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("device rules baseline tests passed\n");
    return 0;
}
