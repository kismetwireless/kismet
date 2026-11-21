/* Tests for the external protocol command policy and the checks on plugin web routes and
 * response headers.
 *
 *   make test/external_policy/policy_test && test/external_policy/policy_test
 */

#include "config.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <regex>
#include <string>
#include <thread>
#include <vector>

#include "kis_external_packet.h"
#include "kis_external_policy.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

static bool route_ok(const std::string& p) {
    return external_route_problem(p).empty();
}

static bool header_ok(const std::string& n, const std::string& v) {
    return external_header_problem(n, v).empty();
}

static void test_commands() {
    CHECK(kis_external_v3_server_api_cmd(KIS_EXTERNAL_V3_WEB_REGISTERURI) == "WEB_REGISTERURI");
    CHECK(kis_external_v3_server_api_cmd(KIS_EXTERNAL_V3_WEB_RESPONSE) == "WEB_RESPONSE");
    CHECK(kis_external_v3_server_api_cmd(KIS_EXTERNAL_V3_EVT_REGISTER) == "EVT_REGISTER");
    CHECK(kis_external_v3_server_api_cmd(KIS_EXTERNAL_V3_EVT_PUBLISH) == "EVT_PUBLISH");

    // Web login tokens are server API too: plugins only
    CHECK(kis_external_v3_server_api_cmd(KIS_EXTERNAL_V3_WEB_AUTHREQ) == "WEB_AUTHREQ");

    for (const auto c : {KIS_EXTERNAL_V3_CMD_PING, KIS_EXTERNAL_V3_CMD_PONG, KIS_EXTERNAL_V3_CMD_MESSAGE,
            KIS_EXTERNAL_V3_CMD_SHUTDOWN, KIS_EXTERNAL_V3_KDS_PACKET, KIS_EXTERNAL_V3_KDS_OPENREPORT,
            KIS_EXTERNAL_V3_KDS_NEWSOURCE, KIS_EXTERNAL_V3_EVT_EVENT, KIS_EXTERNAL_V3_WEB_REQUEST, 0, 0xffff})
        CHECK(kis_external_v3_server_api_cmd(c).empty());

    CHECK(kis_external_v2_server_api_cmd("HTTPREGISTERURI"));
    CHECK(kis_external_v2_server_api_cmd("HTTPRESPONSE"));
    CHECK(kis_external_v2_server_api_cmd("EVENTBUSREGISTER"));
    CHECK(kis_external_v2_server_api_cmd("EVENTBUSPUBLISH"));
    CHECK(kis_external_v2_server_api_cmd("HTTPAUTHREQ"));
    CHECK(!kis_external_v2_server_api_cmd("PING"));
    CHECK(!kis_external_v2_server_api_cmd(""));
    CHECK(!kis_external_v2_server_api_cmd("httpregisteruri"));
    CHECK(!kis_external_v2_server_api_cmd("HTTPREGISTERURIX"));

    for (const auto c : {KIS_EXTERNAL_V3_CMD_PING, KIS_EXTERNAL_V3_CMD_PONG, KIS_EXTERNAL_V3_CMD_MESSAGE,
            KIS_EXTERNAL_V3_CMD_SHUTDOWN, KIS_EXTERNAL_V3_KDS_NEWSOURCE})
        CHECK(kis_external_v3_remote_handshake_cmd(c));

    for (const auto c : {KIS_EXTERNAL_V3_WEB_REGISTERURI, KIS_EXTERNAL_V3_WEB_RESPONSE,
            KIS_EXTERNAL_V3_WEB_AUTHREQ, KIS_EXTERNAL_V3_EVT_REGISTER, KIS_EXTERNAL_V3_EVT_PUBLISH,
            KIS_EXTERNAL_V3_KDS_PACKET, KIS_EXTERNAL_V3_KDS_OPENREPORT, KIS_EXTERNAL_V3_KDS_PROBEREPORT,
            KIS_EXTERNAL_V3_KDS_TIMESYNCREQ, KIS_EXTERNAL_V3_KDS_ENVREPORT, KIS_EXTERNAL_V3_CMD_REGISTER,
            KIS_EXTERNAL_V3_CMD_ERROR, 0, 0xffff})
        CHECK(!kis_external_v3_remote_handshake_cmd(c));

    for (const auto c : {"PING", "PONG", "MESSAGE", "SHUTDOWN", "KDSNEWSOURCE"})
        CHECK(kis_external_v2_remote_handshake_cmd(c));

    for (const auto c : {"HTTPREGISTERURI", "HTTPRESPONSE", "HTTPAUTHREQ", "EVENTBUSREGISTER",
            "EVENTBUSPUBLISH", "KDSDATAREPORT", "KDSOPENSOURCEREPORT", "", "ping", "KDSNEWSOURCE2"})
        CHECK(!kis_external_v2_remote_handshake_cmd(c));
}

static void test_routes() {
    // The in-tree demo plugin's routes
    CHECK(route_ok("/proxytest/python.html"));
    CHECK(route_ok("/proxytest/python_get.html"));
    CHECK(route_ok("/proxytest/python_post.html"));
    CHECK(route_ok("/proxytest/stream.raw"));

    CHECK(route_ok("/plugin/demo/status.json"));
    CHECK(route_ok("/a"));
    CHECK(route_ok("/a-b_c~d.e/f/"));
    CHECK(route_ok(std::string("/") + std::string(kis_external_max_route_len - 1, 'a')));

    CHECK(!route_ok(""));
    CHECK(!route_ok("/"));
    CHECK(!route_ok("a/b"));
    CHECK(!route_ok(std::string("/") + std::string(kis_external_max_route_len, 'a')));
    CHECK(!route_ok("/.*"));
    CHECK(!route_ok("/(a+)+$"));
    CHECK(!route_ok("/("));
    CHECK(!route_ok("/a|b"));
    CHECK(!route_ok("/a[bc]"));
    CHECK(!route_ok("/a?b"));
    CHECK(!route_ok("/a*"));
    CHECK(!route_ok("/a+"));
    CHECK(!route_ok("/a{2}"));
    CHECK(!route_ok("/a^"));
    CHECK(!route_ok("/a$"));
    CHECK(!route_ok("/a\\d"));
    CHECK(!route_ok("/devices/:key/x"));
    CHECK(!route_ok("/a b"));
    CHECK(!route_ok("/a%2e"));
    CHECK(!route_ok("//a"));
    CHECK(!route_ok("/a//b"));
    CHECK(!route_ok("/../etc"));
    CHECK(!route_ok("/a/../b"));
    CHECK(!route_ok("/a/./b"));
    CHECK(!route_ok("/.hidden"));
    CHECK(!route_ok("/a/."));
    CHECK(!route_ok(std::string("/a\0b", 4)));
    CHECK(!route_ok("/a\r\n"));
    CHECK(!route_ok("/caf\xc3\xa9"));

    CHECK(external_route_verb_ok("GET"));
    CHECK(external_route_verb_ok("POST"));
    CHECK(external_route_verb_ok("PUT"));
    CHECK(external_route_verb_ok("DELETE"));
    CHECK(!external_route_verb_ok("get"));
    CHECK(!external_route_verb_ok(""));
    CHECK(!external_route_verb_ok("OPTIONS"));
    CHECK(!external_route_verb_ok("GET "));

    CHECK(external_route_pattern("/proxytest/python.html") == "/proxytest/python\\.html");
    CHECK(external_route_pattern("/a.b.c") == "/a\\.b\\.c");
    CHECK(external_route_pattern("/a-b_c~d") == "/a-b_c~d");

    // The pattern matches its own path, with or without a query, and nothing else
    const auto re = std::regex("^" + external_route_pattern("/proxytest/python.html") + "(\\?.*?)?$");
    CHECK(std::regex_match("/proxytest/python.html", re));
    CHECK(std::regex_match("/proxytest/python.html?a=1", re));
    CHECK(!std::regex_match("/proxytest/pythonXhtml", re));
    CHECK(!std::regex_match("/proxytest/python.html/x", re));
    CHECK(!std::regex_match("/index.html", re));
    CHECK(!std::regex_match("/", re));

    // A long path compiles and matches quickly; no peer-chosen regex reaches std::regex
    const auto longpath = std::string("/") + std::string(kis_external_max_route_len - 1, 'a');
    const auto t0 = std::chrono::steady_clock::now();
    const auto lre = std::regex("^" + external_route_pattern(longpath) + "(\\?.*?)?$");
    CHECK(std::regex_match(longpath, lre));
    CHECK(!std::regex_match(longpath + "b", lre));
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ms < 1000);
}

static void test_route_clash() {
    const auto a = next_external_route_owner();
    const auto b = next_external_route_owner();
    CHECK(a != 0);
    CHECK(b != a);

    // One plugin serves a path with each verb once
    CHECK(external_route_clash(a, "POST", a, "GET").empty());
    CHECK(external_route_clash(a, "PUT", a, "POST").empty());
    CHECK(external_route_clash(a, "GET", a, "GET") == "path and method are already registered");

    // Another plugin gets none of that path, whatever the verb
    CHECK(external_route_clash(b, "GET", a, "GET") == "path is already registered by another plugin");
    CHECK(external_route_clash(b, "DELETE", a, "GET") == "path is already registered by another plugin");
}

static void test_headers() {
    CHECK(header_ok("Content-Type", "text/html"));
    CHECK(header_ok("Cache-Control", "no-cache, no-store"));
    CHECK(header_ok("X-Plugin", "a\tb"));
    CHECK(header_ok("X-Plugin", ""));
    CHECK(header_ok("X-Utf8", "caf\xc3\xa9"));
    CHECK(header_ok("!#$%&'*+-.^_`|~", "x"));
    CHECK(header_ok(std::string(kis_external_max_header_name_len, 'a'), "x"));
    CHECK(header_ok("X", std::string(kis_external_max_header_value_len, 'v')));

    CHECK(!header_ok("", "x"));
    CHECK(!header_ok(std::string(kis_external_max_header_name_len + 1, 'a'), "x"));
    CHECK(!header_ok("X", std::string(kis_external_max_header_value_len + 1, 'v')));
    CHECK(!header_ok("X-A:B", "x"));
    CHECK(!header_ok("X A", "x"));
    CHECK(!header_ok("X\r\nSet-Cookie", "x"));
    CHECK(!header_ok(std::string("X\0", 2), "x"));
    CHECK(!header_ok("X(", "x"));
    CHECK(!header_ok("X\"", "x"));
    CHECK(!header_ok("X\xc3\xa9", "x"));

    CHECK(!header_ok("X", "a\r\nSet-Cookie: KISMET=x"));
    CHECK(!header_ok("X", "a\rb"));
    CHECK(!header_ok("X", "a\nb"));
    CHECK(!header_ok("X", std::string("a\0b", 3)));
    CHECK(!header_ok("X", "a\x01"));
    CHECK(!header_ok("X", "a\x1f"));
    CHECK(!header_ok("X", "a\x7f"));

    for (const auto h : {"Content-Length", "content-length", "TRANSFER-ENCODING", "Connection",
            "Keep-Alive", "Upgrade", "TE", "Trailer", "Proxy-Connection"})
        CHECK(!header_ok(h, "x"));

    CHECK(header_ok("Content-Lengthx", "1"));
    CHECK(header_ok("X-Connection", "close"));
}

static void test_log_limiter() {
    kis_log_limiter lim{10};

    CHECK(lim.due(100) == 0);
    CHECK(!lim.due(100));
    CHECK(!lim.due(105));
    CHECK(!lim.due(109));
    CHECK(lim.due(110) == 3);
    CHECK(!lim.due(110));
    CHECK(lim.due(500) == 1);
    CHECK(lim.due(510) == 0);

    // A clock behind the last line (another thread's later now) never passes, but is counted
    CHECK(!lim.due(400));
    CHECK(!lim.due(519));
    CHECK(lim.due(520) == 2);

    kis_log_limiter each{1};
    CHECK(each.due(1) == 0);
    CHECK(!each.due(1));
    CHECK(each.due(2) == 1);

    // Each limiter counts on its own
    kis_log_limiter a{10}, b{10};
    CHECK(a.due(100) == 0);
    CHECK(b.due(100) == 0);
    CHECK(!a.due(101));
    CHECK(!a.due(102));
    CHECK(b.due(110) == 0);
    CHECK(a.due(110) == 2);

    // The clock overload: one line, then quiet within the interval
    kis_log_limiter mono{3600};
    CHECK(mono.due() == 0);
    CHECK(!mono.due());
    CHECK(!mono.due());

    // Static and namespace scope limiters are constant initialized
    static constinit kis_log_limiter at_load{10};
    CHECK(at_load.due(1) == 0);
    static constinit kis_log_limiter burst_at_load{10, 3};
    CHECK(burst_at_load.due(1) == 0);

    // A burst: that many lines per interval, then counted until the next interval
    kis_log_limiter burst{10, 3};
    CHECK(burst.due(100) == 0);
    CHECK(burst.due(101) == 0);
    CHECK(burst.due(109) == 0);
    CHECK(!burst.due(109));
    CHECK(!burst.due(109));
    CHECK(burst.due(110) == 2);
    CHECK(burst.due(110) == 0);
    CHECK(burst.due(119) == 0);
    CHECK(!burst.due(119));
    CHECK(burst.due(500) == 1);
    // A clock behind the interval's start counts as inside it
    CHECK(burst.due(400) == 0);
    CHECK(burst.due(501) == 0);
    CHECK(!burst.due(502));
    CHECK(!burst.due(509));
    CHECK(burst.due(510) == 2);

    // A burst of 0 acts as 1: the line that opens an interval always goes out
    kis_log_limiter zero{10, 0};
    CHECK(zero.due(100) == 0);
    CHECK(!zero.due(100));
    CHECK(zero.due(110) == 1);

    CHECK(kis_log_suppressed_note(0).empty());
    CHECK(kis_log_suppressed_note(1) == " (1 similar suppressed)");
    CHECK(kis_log_suppressed_note(199) == " (199 similar suppressed)");
    CHECK(kis_log_suppressed_note(UINT64_MAX) == " (18446744073709551615 similar suppressed)");
}

// Every line asked for is either logged or counted in a later logged line, exactly once
static void test_log_limiter_threads() {
    constexpr int n_threads = 8;
    constexpr int per_thread = 20000;

    // Same second: exactly one line, and the flush line carries the rest
    kis_log_limiter same{10};
    std::atomic<int> passed{0};
    std::atomic<uint64_t> counted{0};
    std::vector<std::thread> threads;

    for (int t = 0; t < n_threads; t++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < per_thread; i++) {
                if (auto n = same.due(1000)) {
                    passed++;
                    counted += *n;
                }
            }
        });
    }

    for (auto& t : threads)
        t.join();
    threads.clear();

    CHECK(passed.load() == 1);
    auto flush = same.due(2000);
    CHECK(flush.has_value());
    CHECK(counted.load() + flush.value_or(0) == n_threads * per_thread - 1);

    // Same second with a burst: exactly the burst passes
    kis_log_limiter same_burst{10, 5};
    passed = 0;
    counted = 0;

    for (int t = 0; t < n_threads; t++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < per_thread; i++) {
                if (auto n = same_burst.due(1000)) {
                    passed++;
                    counted += *n;
                }
            }
        });
    }

    for (auto& t : threads)
        t.join();
    threads.clear();

    CHECK(passed.load() == 5);
    flush = same_burst.due(2000);
    CHECK(flush.has_value());
    CHECK(counted.load() + flush.value_or(0) == n_threads * per_thread - 5);

    // The clock moving on while threads race: lines + counts + the flush add up to every call
    kis_log_limiter moving{2};
    std::atomic<uint64_t> lines{0};
    counted = 0;

    for (int t = 0; t < n_threads; t++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < per_thread; i++) {
                if (auto n = moving.due(1 + i / 100)) {
                    lines++;
                    counted += *n;
                }
            }
        });
    }

    for (auto& t : threads)
        t.join();

    flush = moving.due(1000000);
    CHECK(flush.has_value());
    CHECK(lines.load() >= 1);
    CHECK(lines.load() + 1 + counted.load() + flush.value_or(0) == n_threads * per_thread + 1);
}

int main() {
    test_commands();
    test_routes();
    test_route_clash();
    test_headers();
    test_log_limiter();
    test_log_limiter_threads();

    if (failures != 0) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("external_policy: all tests passed\n");
    return 0;
}
