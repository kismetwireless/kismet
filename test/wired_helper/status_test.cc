/* Tests for the wired datasource's status record parser (datasource_wired_status.h):
 * what a remote kismet_cap_wired, or anything claiming to be one, can put in a
 * wiredstatus record, and the source warning made from it.
 *
 *   make test/wired_helper/status_test && test/wired_helper/status_test
 */

#include "config.h"

#include <cstdio>
#include <string>

#include "datasource_wired_status.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

static void test_good() {
    wired_status::report r;

    CHECK(wired_status::parse("{\"kernel_received\":10,\"kernel_drops\":2,\"if_drops\":1,"
                "\"frames\":8,\"forwarded\":4,\"sample\":2,\"snaplen\":1600,\"buffer_mb\":64,"
                "\"promisc\":true,\"remote_excluded\":false,"
                "\"offloads\":[\"rx-vlan-filter\",\"rx-gro\"],\"carrier\":true}", r));
    CHECK(r.kernel_received == 10u && r.kernel_drops == 2u && r.if_drops == 1u);
    CHECK(r.frames == 8u && r.forwarded == 4u);
    CHECK(r.sample == 2u && r.snaplen == 1600u && r.buffer_mb == 64u);
    CHECK(r.promisc == true && r.remote_excluded == false && r.carrier == true);
    // Kept in the fixed order, whatever order they arrive in
    CHECK(r.offloads == std::string("rx-gro,rx-vlan-filter"));

    CHECK(wired_status::parse("{\"kernel_drops\":18446744073709551615}", r));
    CHECK(r.kernel_drops == UINT64_MAX);
    CHECK(!r.frames.has_value() && !r.carrier.has_value() && !r.offloads.has_value());

    CHECK(wired_status::parse("{\"offloads\":[]}", r));
    CHECK(r.offloads == std::string(""));
}

static void test_hostile() {
    wired_status::report r;

    CHECK(!wired_status::parse("", r));
    CHECK(!wired_status::parse("[1,2]", r));
    CHECK(!wired_status::parse("\"x\"", r));
    CHECK(!wired_status::parse("{\"frames\":1", r));
    CHECK(!wired_status::parse("{\"frames\":NaN}", r));
    CHECK(!wired_status::parse("{\"frames\":1}garbage", r));
    CHECK(!wired_status::parse(std::string("{\"a\":\"\xff\xfe\"}"), r));
    CHECK(!wired_status::parse(std::string("{\"a\":\"\xc0\x80\"}"), r));

    // Wrong types and out of range values are dropped, not converted
    CHECK(wired_status::parse("{\"frames\":-1,\"kernel_drops\":1.5,\"if_drops\":\"3\","
                "\"sample\":4294967296,\"snaplen\":-5,\"promisc\":1,\"carrier\":\"up\","
                "\"offloads\":\"rx-gro\",\"kernel_received\":1e30}", r));
    CHECK(!r.frames && !r.kernel_drops && !r.if_drops && !r.sample && !r.snaplen);
    CHECK(!r.promisc && !r.carrier && !r.offloads && !r.kernel_received);

    CHECK(wired_status::parse("{\"sample\":4294967295}", r));
    CHECK(r.sample == 4294967295u);

    // Only known offload names, each once; anything else is ignored
    CHECK(wired_status::parse("{\"offloads\":[\"rx-gro\",\"rx-gro\",\"<script>\",\"rx-gro\\u0000x\","
                "\"RX-GRO\",7,null,{\"a\":1},[\"rx-lro\"],\"tx-generic-segmentation\"]}", r));
    CHECK(r.offloads == std::string("rx-gro,tx-generic-segmentation"));

    // A huge record is refused before parsing
    std::string big = "{\"offloads\":[";
    while (big.size() < wired_status::max_json_len)
        big += "\"rx-gro\",";
    big += "\"rx-gro\"]}";
    CHECK(!wired_status::parse(big, r));

    // Deep nesting inside the size limit
    std::string deep(2000, '[');
    deep = "{\"x\":" + deep + std::string(2000, ']') + "}";
    CHECK(wired_status::parse(deep, r));
    CHECK(!r.frames);

    // Duplicate keys: one of them wins, either is a number
    CHECK(wired_status::parse("{\"frames\":1,\"frames\":2}", r));
    CHECK(r.frames == 1u || r.frames == 2u);
}

static void test_warning() {
    CHECK(wired_status::warning("", std::nullopt, true).empty());
    CHECK(wired_status::warning("", true, false).empty());
    CHECK(wired_status::warning("", false, true) == "No link on the interface.");

    // What nearly every NIC has on by default: kept in the field, no warning
    const std::string defaults = "rx-gro,tx-tcp-segmentation,tx-tcp6-segmentation,tx-generic-segmentation";
    CHECK(wired_status::warning(defaults, true, true).empty());
    CHECK(wired_status::warning(defaults, true, false).empty());
    CHECK(wired_status::warning("rx-gro,rx-gro-hw,rx-lro", std::nullopt, false).empty());

    // rx-vlan-filter only outside promiscuous mode
    CHECK(wired_status::warning("rx-gro,rx-vlan-filter", true, true).empty());

    auto w = wired_status::warning("rx-gro,rx-vlan-filter", true, false);
    CHECK(w.find("rx-vlan-filter") != std::string::npos && w.find("rx-gro") == std::string::npos);
    CHECK(w.find("No link") == std::string::npos && w.back() != ' ');

    w = wired_status::warning("rx-vlan-filter", false, false);
    CHECK(w.find("No link") == 0 && w.find("rx-vlan-filter") != std::string::npos && w.back() != ' ');

    // Whole names only
    CHECK(wired_status::warning("rx-vlan-filterx", true, false).empty());
    CHECK(wired_status::warning("xrx-vlan-filter", true, false).empty());
    CHECK(wired_status::warning("rx-vlan", true, false).empty());
    CHECK(!wired_status::warning(",rx-vlan-filter,", true, false).empty());

    CHECK(wired_status::list_has("a,b,c", "b") && wired_status::list_has("a,b,c", "c") &&
            wired_status::list_has("a", "a"));
    CHECK(!wired_status::list_has("", "a") && !wired_status::list_has("ab", "a") &&
            !wired_status::list_has("a,b", "a,b"));
}

// As apply_status runs it: the status only replaces or clears its own warning
static void test_warning_owner() {
    std::string current, mine;
    int writes = 0;

    auto apply = [&](const std::string& want) {
        if (wired_status::take_warning(current, mine, want)) {
            current = want;
            writes++;
        }
    };

    apply("No link on the interface.");
    CHECK(current == "No link on the interface." && writes == 1);
    // A steady report doesn't rewrite it
    apply("No link on the interface.");
    CHECK(writes == 1);
    apply("");
    CHECK(current.empty() && writes == 2);

    // Another path's warning stays through reports that want none, or another
    apply("No link on the interface.");
    current = "helper: could not set the capture buffer";
    apply("");
    CHECK(current == "helper: could not set the capture buffer");
    apply("No link on the interface.");
    CHECK(current == "helper: could not set the capture buffer");

    // Cleared by its owner, the status shows again
    current.clear();
    apply("No link on the interface.");
    CHECK(current == "No link on the interface.");

    CHECK(wired_status::warning_is_ours("", "x") && wired_status::warning_is_ours("x", "x"));
    CHECK(!wired_status::warning_is_ours("y", "x") && !wired_status::warning_is_ours("y", ""));
}

// What the source does on a close or an error, then on the next open's reports
static void test_warning_close() {
    const std::string vlan = wired_status::warning("rx-vlan-filter", true, false);
    std::string current, mine;

    auto apply = [&](const std::string& want) {
        if (wired_status::take_warning(current, mine, want))
            current = want;
    };
    auto close = [&]() {
        if (wired_status::release_warning(current, mine))
            current.clear();
    };

    // 'ethtool -K <if> rx-vlan-filter off' shows in the next report
    apply(vlan);
    CHECK(current == vlan);
    apply(wired_status::warning("", true, false));
    CHECK(current.empty());

    // The status's own warning goes with the source
    apply(vlan);
    close();
    CHECK(current.empty() && mine.empty());
    apply(vlan);
    CHECK(current == vlan);

    // Another path's warning outlives it
    current = "helper: could not set the capture buffer";
    apply(vlan);
    close();
    CHECK(current == "helper: could not set the capture buffer" && mine.empty());

    // Nothing of its own: a warning set elsewhere, equal to nothing it ever set, stays
    mine.clear();
    current = "No link on the interface.";
    close();
    CHECK(current == "No link on the interface.");
    current.clear();
    close();
    CHECK(current.empty() && mine.empty());
}

int main() {
    test_good();
    test_hostile();
    test_warning();
    test_warning_owner();
    test_warning_close();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("ok\n");
    return 0;
}
