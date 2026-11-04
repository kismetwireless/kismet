/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "config.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <numeric>
#include <optional>
#include <sstream>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/version.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>

#include "configfile.h"
#include "devicetracker.h"
#include "entrytracker.h"
#include "json_adapter.h"
#include "kis_net_beast_httpd.h"
#include "messagebus.h"
#include "nlohmann/json.hpp"
#include "timetracker.h"
#include "util.h"
#include "version.h"
#include "webhooks.h"

namespace {

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

constexpr size_t max_endpoints = 16;
constexpr size_t max_headers = 8;
constexpr size_t max_url_len = 2048;
constexpr size_t max_event_bytes = 256 * 1024;
constexpr size_t max_queue_bytes = 8 * 1024 * 1024;
constexpr size_t max_queue_events = 10000;
constexpr unsigned int max_attempts = 3;
constexpr int64_t max_retry_after = 3600;
constexpr int64_t max_backoff = 300;
constexpr time_t log_interval = 300;
constexpr size_t max_due_per_tick = 2000;
// Devices each hook's purge looks at per tick
constexpr size_t purge_per_tick = 1000;
constexpr time_t purge_idle = 600;
// Longer change values are compared by hash
constexpr size_t max_change_value = 1024;
// 'new' remembers this many times webhook_max_tracked devices that stopped matching
constexpr size_t new_sent_factor = 4;

constexpr const char *default_fields[] = {
    "kismet.device.base.key",
    "kismet.device.base.macaddr",
    "kismet.device.base.commonname",
    "kismet.device.base.phyname",
    "kismet.device.base.type",
    "kismet.device.base.manuf",
    "kismet.device.base.channel",
    "kismet.device.base.frequency",
    "kismet.device.base.first_time",
    "kismet.device.base.last_time",
    "kismet.device.base.signal/kismet.common.signal.last_signal",
};

bool valid_name(const std::string& n) {
    if (n.empty() || n.size() > 32)
        return false;
    for (auto c : n)
        if (!isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_')
            return false;
    return true;
}

// RFC 7230 token characters, for header names
bool valid_header_name(const std::string& n) {
    if (n.empty() || n.size() > 64)
        return false;
    for (auto c : n) {
        if (isalnum(static_cast<unsigned char>(c)))
            continue;
        if (strchr("!#$%&'*+-.^_`|~", c) == nullptr || c == 0)
            return false;
    }
    return true;
}

// Printable, with no CR or LF to split the header
bool valid_header_value(const std::string& v) {
    if (v.size() > 1024)
        return false;
    for (auto c : v) {
        auto u = static_cast<unsigned char>(c);
        if ((u < 0x20 && u != '\t') || u == 0x7f)
            return false;
    }
    return true;
}

// Seconds from a duration such as 30, 30s, 5m, 2h
bool parse_seconds(const std::string& in, int64_t lo, int64_t hi, int64_t& out) {
    if (in.empty() || in.size() > 12)
        return false;
    int64_t mult = 1;
    std::string num = in;
    switch (in.back()) {
        case 's': mult = 1; num.pop_back(); break;
        case 'm': mult = 60; num.pop_back(); break;
        case 'h': mult = 3600; num.pop_back(); break;
        case 'd': mult = 86400; num.pop_back(); break;
        default: break;
    }
    if (num.empty())
        return false;
    for (auto c : num)
        if (c < '0' || c > '9')
            return false;
    auto v = std::stoll(num) * mult;
    if (v < lo || v > hi)
        return false;
    out = v;
    return true;
}

bool parse_count(const std::string& in, uint64_t lo, uint64_t hi, uint64_t& out) {
    if (in.empty() || in.size() > 9)
        return false;
    for (auto c : in)
        if (c < '0' || c > '9')
            return false;
    auto v = std::stoull(in);
    if (v < lo || v > hi)
        return false;
    out = v;
    return true;
}

// n/period, as in 30/1m or 30/min
bool parse_rate(const std::string& in, uint32_t& n, int64_t& period) {
    auto slash = in.find('/');
    if (slash == std::string::npos)
        return false;
    uint64_t c;
    if (!parse_count(in.substr(0, slash), 1, devicerules::hook_max_rate, c))
        return false;
    auto p = in.substr(slash + 1);
    if (p == "s" || p == "sec")
        period = 1;
    else if (p == "min")
        period = 60;
    else if (p == "h" || p == "hour")
        period = 3600;
    else if (p == "d" || p == "day")
        period = 86400;
    else if (!parse_seconds(p, 1, 86400, period))
        return false;
    n = static_cast<uint32_t>(c);
    return true;
}

std::string hmac_hex(const std::string& key, const std::string& data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                reinterpret_cast<const unsigned char *>(data.data()), data.size(), md, &md_len) == nullptr)
        return "";

    static const char hex[] = "0123456789abcdef";
    std::string r;
    r.reserve(md_len * 2);
    for (unsigned int i = 0; i < md_len; i++) {
        r.push_back(hex[md[i] >> 4]);
        r.push_back(hex[md[i] & 0xf]);
    }
    return r;
}

// Length of the valid UTF-8 character at s[i], or 0; RFC 3629, so no overlong
// forms, surrogates or values past U+10FFFF
size_t utf8_len(const std::string& s, size_t i) {
    auto b = [&](size_t n) { return static_cast<unsigned char>(s[i + n]); };
    auto cont = [&](size_t n) { return i + n < s.size() && (b(n) & 0xc0) == 0x80; };

    auto c = b(0);
    if (c < 0x80)
        return 1;
    if (c >= 0xc2 && c <= 0xdf)
        return cont(1) ? 2 : 0;
    if (c >= 0xe0 && c <= 0xef) {
        if (!cont(1) || !cont(2))
            return 0;
        if ((c == 0xe0 && b(1) < 0xa0) || (c == 0xed && b(1) > 0x9f))
            return 0;
        return 3;
    }
    if (c >= 0xf0 && c <= 0xf4) {
        if (!cont(1) || !cont(2) || !cont(3))
            return 0;
        if ((c == 0xf0 && b(1) < 0x90) || (c == 0xf4 && b(1) > 0x8f))
            return 0;
        return 4;
    }
    return 0;
}

// Device strings are whatever was on the air; a strict receiver would refuse a
// whole call over one bad byte, so bad bytes become U+FFFD
void repair_utf8(std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
        auto n = utf8_len(s, i);
        if (n == 0)
            break;
        i += n;
    }
    if (i == s.size())
        return;

    std::string r;
    r.reserve(s.size() + 16);
    r.append(s, 0, i);
    while (i < s.size()) {
        auto n = utf8_len(s, i);
        if (n == 0) {
            r += "\xef\xbf\xbd";
            i++;
        } else {
            r.append(s, i, n);
            i += n;
        }
    }
    s = std::move(r);
}

// Retry-After as seconds or an HTTP date, capped; -1 when it's neither
int64_t parse_retry_after(const std::string& v, time_t now) {
    if (v.empty() || v.size() > 64)
        return -1;

    if (std::all_of(v.begin(), v.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        if (v.size() > 9)
            return max_retry_after;
        return std::min<int64_t>(std::stoll(v), max_retry_after);
    }

    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    auto end = strptime(v.c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (end == nullptr || *end != '\0')
        return -1;
    auto t = timegm(&tm);
    if (t <= now)
        return 0;
    return std::min<int64_t>(t - now, max_retry_after);
}

std::string version_string() {
    return fmt::format("{}.{}.{}-{}", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, VERSION_GIT_COMMIT);
}

std::string pack_element(const std::shared_ptr<tracker_element>& e) {
    if (e == nullptr)
        return "null";
    std::stringstream ss;
    json_adapter::pack(ss, e);
    auto s = ss.str();
    return s.empty() ? "null" : s;
}

// Visit a slice of an unordered container, resuming at the bucket the last call
// stopped at, so a big one is covered over several calls
template <typename C, typename F>
void scan_slice(C& c, size_t& bucket, F&& fn) {
    auto nb = c.bucket_count();
    if (c.empty() || nb == 0) {
        bucket = 0;
        return;
    }
    if (bucket >= nb)
        bucket = 0;
    size_t seen = 0;
    auto max_buckets = std::min(nb, purge_per_tick * 8);
    for (size_t visited = 0; visited < max_buckets && seen < purge_per_tick; visited++) {
        for (auto it = c.begin(bucket); it != c.end(bucket); ++it) {
            fn(*it);
            seen++;
        }
        bucket = (bucket + 1) % nb;
    }
}

template <typename T>
std::shared_ptr<T> status_field(const std::shared_ptr<entry_tracker>& et, const std::string& name,
        const std::string& desc) {
    return et->register_and_get_field_as<T>(name, tracker_element_factory<T>(), desc);
}

}

void webhook_bucket::init(uint32_t rate, int64_t period, uint32_t burst) {
    cap = burst > 0 ? burst : rate;
    per_sec = static_cast<double>(rate) / static_cast<double>(std::max<int64_t>(1, period));
    tokens = cap;
    last = webhook_clock::now();
}

void webhook_bucket::refill(webhook_clock::time_point now) {
    if (now <= last)
        return;
    double s = std::chrono::duration<double>(now - last).count();
    tokens = std::min(cap, tokens + s * per_sec);
    last = now;
}

bool webhook_bucket::available(webhook_clock::time_point now) {
    refill(now);
    return tokens >= 1.0;
}

bool webhook_bucket::take(webhook_clock::time_point now) {
    refill(now);
    if (tokens < 1.0)
        return false;
    tokens -= 1.0;
    return true;
}

webhook_clock::time_point webhook_bucket::ready(webhook_clock::time_point now) {
    refill(now);
    if (tokens >= 1.0 || per_sec <= 0)
        return now;
    auto wait = std::chrono::duration<double>((1.0 - tokens) / per_sec);
    return now + std::chrono::duration_cast<webhook_clock::duration>(wait) + std::chrono::milliseconds(1);
}

bool parse_webhook_url(const std::string& in, webhook_url& out, std::string& err) {
    if (in.size() > max_url_len) {
        err = "url is too long";
        return false;
    }

    for (auto c : in) {
        auto u = static_cast<unsigned char>(c);
        if (u <= 0x20 || u >= 0x7f) {
            err = "url has spaces or control characters";
            return false;
        }
    }

    std::string rest;
    if (in.compare(0, 8, "https://") == 0) {
        out.tls = true;
        rest = in.substr(8);
    } else if (in.compare(0, 7, "http://") == 0) {
        out.tls = false;
        rest = in.substr(7);
    } else {
        err = "url must start with http:// or https://";
        return false;
    }

    auto slash = rest.find_first_of("/?#");
    auto authority = rest.substr(0, slash);
    out.target = slash == std::string::npos ? "/" : rest.substr(slash);

    if (out.target.find('#') != std::string::npos) {
        err = "url can't have a fragment";
        return false;
    }
    if (out.target[0] == '?')
        out.target = "/" + out.target;

    if (authority.find('@') != std::string::npos) {
        err = "url can't hold a user or password; use a header";
        return false;
    }

    std::string port;
    if (!authority.empty() && authority[0] == '[') {
        auto close = authority.find(']');
        if (close == std::string::npos) {
            err = "bad IPv6 address in url";
            return false;
        }
        out.host = authority.substr(1, close - 1);
        for (auto c : out.host)
            if (!isxdigit(static_cast<unsigned char>(c)) && c != ':' && c != '.') {
                err = "bad IPv6 address in url";
                return false;
            }
        auto after = authority.substr(close + 1);
        if (!after.empty()) {
            if (after[0] != ':') {
                err = "bad port in url";
                return false;
            }
            port = after.substr(1);
        }
    } else {
        auto colon = authority.find(':');
        out.host = authority.substr(0, colon);
        if (colon != std::string::npos)
            port = authority.substr(colon + 1);
        for (auto c : out.host)
            if (!isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_') {
                err = "bad host name in url";
                return false;
            }
    }

    if (out.host.empty() || out.host.size() > 253) {
        err = "url has no host";
        return false;
    }

    if (port.empty()) {
        out.port = out.tls ? "443" : "80";
    } else {
        uint64_t p;
        if (!parse_count(port, 1, 65535, p)) {
            err = "bad port in url";
            return false;
        }
        out.port = std::to_string(p);
    }

    bool v6 = out.host.find(':') != std::string::npos;
    auto h = v6 ? "[" + out.host + "]" : out.host;
    bool default_port = out.port == (out.tls ? "443" : "80");
    out.host_header = default_port ? h : h + ":" + out.port;
    out.redacted = std::string(out.tls ? "https://" : "http://") + h + ":" + out.port + "/...";

    return true;
}

webhook_endpoint::webhook_endpoint(const std::string& name, const webhook_url& url) :
    name{name},
    url{url} { }

webhook_endpoint::~webhook_endpoint() {
    stop();
}

void webhook_endpoint::start() {
    if (url.tls) {
        try {
            auto ctx = std::make_shared<ssl::context>(ssl::context::tls_client);
            ctx->set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                    ssl::context::no_sslv3 | ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1 |
                    ssl::context::no_compression);
#ifdef SSL_OP_NO_RENEGOTIATION
            SSL_CTX_set_options(ctx->native_handle(), SSL_OP_NO_RENEGOTIATION);
#endif
            if (insecure) {
                ctx->set_verify_mode(ssl::verify_none);
            } else {
                ctx->set_verify_mode(ssl::verify_peer);
                if (!ca_file.empty())
                    ctx->load_verify_file(ca_file);
                else
                    ctx->set_default_verify_paths();
            }
            ssl_ctx = ctx;
        } catch (const std::exception& e) {
            // Refuse events rather than queue them for a worker that never runs
            std::lock_guard<std::mutex> lk(m);
            stopping = true;
            last_error = fmt::format("not started: {}", e.what());
            throw;
        }
    }

    bucket.init(rate, rate_period, burst);
    worker = std::thread([this]() { run(); });
}

struct webhook_endpoint::resolve_job {
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    beast::error_code ec;
    std::vector<tcp::endpoint> eps;
};

void webhook_endpoint::stop() {
    request_stop();
    join();
}

void webhook_endpoint::request_stop() {
    {
        std::lock_guard<std::mutex> lk(m);
        stopping = true;
        halt = true;
        if (cur_ioc != nullptr)
            static_cast<net::io_context *>(cur_ioc)->stop();
    }
    cv.notify_all();
}

void webhook_endpoint::join() {
    if (worker.joinable())
        worker.join();
}

void webhook_endpoint::push_locked(event&& e) {
    if (e.json.size() > max_event_bytes) {
        dropped_events++;
        dropped_unreported++;
        return;
    }

    while (!queue.empty() && (queue.size() >= queue_max || queue_bytes + e.json.size() > max_queue_bytes)) {
        queue_bytes -= queue.front().json.size();
        queue.pop_front();
        dropped_events++;
        dropped_unreported++;
    }

    queue_bytes += e.json.size();

    // Threads can arrive out of order; keep the queue in seq order
    auto pos = queue.end();
    while (pos != queue.begin() && std::prev(pos)->seq > e.seq)
        --pos;
    queue.insert(pos, std::move(e));
}

void webhook_endpoint::enqueue(uint64_t seq, uint64_t group, webhook_clock::time_point not_before,
        std::string json) {
    {
        std::lock_guard<std::mutex> lk(m);
        if (stopping)
            return;
        push_locked(event{seq, group, not_before, 0, std::move(json)});
    }
    cv.notify_all();
}

void webhook_endpoint::release(uint64_t group) {
    if (group == 0)
        return;
    {
        std::lock_guard<std::mutex> lk(m);
        auto now = webhook_clock::now();
        for (auto& e : queue)
            if (e.group == group)
                e.not_before = std::min(e.not_before, now);
    }
    cv.notify_all();
}

void webhook_endpoint::note_suppressed(uint64_t n) {
    std::lock_guard<std::mutex> lk(m);
    suppressed_events += n;
    suppressed_unreported += n;
}

std::string webhook_endpoint::envelope(const std::vector<event>& batch, uint64_t dropped, uint64_t suppressed) {
    nlohmann::json head;
    head["server_name"] = Globalreg::globalreg->kismet_config->fetch_opt("server_name");
    if (Globalreg::globalreg->server_uuid != nullptr)
        head["server_uuid"] = Globalreg::globalreg->server_uuid->get().as_string();
    head["version"] = version_string();

    std::string body;
    body.reserve(256 + std::accumulate(batch.begin(), batch.end(), size_t{0},
                [](size_t s, const event& e) { return s + e.json.size() + 1; }));

    body += "{\"kismet\":";
    body += head.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    body += ",\"endpoint\":";
    body += nlohmann::json(name).dump();
    body += fmt::format(",\"sent\":{},\"dropped\":{},\"suppressed\":{},\"events\":[", time(nullptr),
            dropped, suppressed);
    for (size_t i = 0; i < batch.size(); i++) {
        if (i > 0)
            body += ",";
        body += batch[i].json;
    }
    body += "]}";

    return body;
}

webhook_endpoint::result webhook_endpoint::deliver(const std::string& body) {
    result res;

    net::io_context ioc;

    {
        std::lock_guard<std::mutex> lk(m);
        if (stopping) {
            res.error = "shutting down";
            return res;
        }
        cur_ioc = &ioc;
    }

    // Cleared on every way out, throws included, before ioc goes away
    struct ioc_clear {
        webhook_endpoint *ep;
        ~ioc_clear() {
            std::lock_guard<std::mutex> lk(ep->m);
            ep->cur_ioc = nullptr;
        }
    } clear_ioc{this};

    auto deadline = webhook_clock::now() + timeout;

    std::optional<beast::tcp_stream> plain;
    std::optional<ssl::stream<beast::tcp_stream>> tls;

    auto lowest = [&]() -> beast::tcp_stream& {
        return tls ? beast::get_lowest_layer(*tls) : *plain;
    };

    // Run one async step to completion or the deadline; a step that runs out of time
    // is cancelled and drained, so nothing it holds outlives this call
    auto step = [&](auto&& start) -> beast::error_code {
        beast::error_code ec;
        bool done = false;

        {
            std::lock_guard<std::mutex> lk(m);
            if (stopping)
                return net::error::operation_aborted;
        }

        start([&](beast::error_code e) {
            ec = e;
            done = true;
        });

        // Restarted under the lock so a stop() can't land between the check and the run
        bool halted;
        {
            std::lock_guard<std::mutex> lk(m);
            halted = stopping;
            if (!halted)
                ioc.restart();
        }

        auto left = deadline - webhook_clock::now();
        if (!halted && left > webhook_clock::duration::zero())
            ioc.run_for(left);

        if (!done) {
            if (plain || tls) {
                beast::error_code ign;
                lowest().socket().close(ign);
            }
            ioc.restart();
            ioc.run_for(std::chrono::seconds(5));
            if (!done)
                ioc.stop();
            return net::error::timed_out;
        }

        return ec;
    };

    auto finish = [&](const std::string& err) -> result& {
        if (res.error.empty() && !err.empty())
            res.error = err;
        return res;
    };

    // A lookup that outlives the deadline is left to finish on its own; the next call
    // waits on it rather than starting another
    std::shared_ptr<resolve_job> job;
    {
        std::lock_guard<std::mutex> lk(m);
        job = resolving;
    }
    if (job == nullptr) {
        job = std::make_shared<resolve_job>();
        {
            std::lock_guard<std::mutex> lk(m);
            resolving = job;
        }
        std::thread([job, host = url.host, port = url.port]() {
            net::io_context rioc;
            tcp::resolver r(rioc);
            beast::error_code rec;
            auto res = r.resolve(host, port, rec);
            std::lock_guard<std::mutex> lk(job->m);
            job->ec = rec;
            for (const auto& e : res)
                job->eps.push_back(e.endpoint());
            job->done = true;
            job->cv.notify_all();
        }).detach();
    }

    std::vector<tcp::endpoint> eps;
    beast::error_code rec;
    {
        std::unique_lock<std::mutex> lk(job->m);
        while (!job->done && !halt && webhook_clock::now() < deadline)
            job->cv.wait_until(lk, std::min(deadline, webhook_clock::now() + std::chrono::milliseconds(100)));
        if (!job->done)
            return finish(halt ? "shutting down" : "resolve: timed out");
        rec = job->ec;
        eps = job->eps;
    }
    {
        // Finished either way, so the next call looks the name up again
        std::lock_guard<std::mutex> lk(m);
        if (resolving == job)
            resolving.reset();
    }
    if (rec)
        return finish("resolve: " + rec.message());
    if (eps.empty())
        return finish("resolve: no addresses");

    beast::error_code ec;

    if (url.tls) {
        tls.emplace(ioc, *std::static_pointer_cast<ssl::context>(ssl_ctx));

        bool is_ip = false;
        {
            beast::error_code aec;
            net::ip::make_address(url.host, aec);
            is_ip = !aec;
        }

        if (!is_ip && !SSL_set_tlsext_host_name(tls->native_handle(), url.host.c_str()))
            return finish("could not set the TLS server name");

        if (!insecure) {
#if BOOST_VERSION >= 107300
            tls->set_verify_callback(ssl::host_name_verification(url.host));
#else
            tls->set_verify_callback(ssl::rfc2818_verification(url.host));
#endif
        }
    } else {
        plain.emplace(ioc);
    }

    ec = step([&](auto h) {
        lowest().async_connect(eps,
                [h](beast::error_code e, const tcp::endpoint&) { h(e); });
    });
    if (ec)
        return finish("connect: " + ec.message());

    if (tls) {
        ec = step([&](auto h) {
            tls->async_handshake(ssl::stream_base::client, [h](beast::error_code e) { h(e); });
        });
        if (ec)
            return finish("TLS: " + ec.message());
    }

    http::request<http::string_body> req{http::verb::post, url.target, 11};
    req.set(http::field::host, url.host_header);
    req.set(http::field::user_agent, "Kismet/" + version_string());
    req.set(http::field::content_type, "application/json");
    req.set(http::field::connection, "close");
    for (const auto& h : headers)
        req.set(h.first, h.second);
    if (!secret.empty()) {
        auto ts = std::to_string(time(nullptr));
        req.set("X-Kismet-Timestamp", ts);
        req.set("X-Kismet-Signature", "sha256=" + hmac_hex(secret, ts + "." + body));
    }
    req.body() = body;
    req.prepare_payload();

    // Only the status line and headers are read; the body is ignored
    beast::flat_buffer buf(16384);
    std::optional<http::response_parser<http::empty_body>> parser;

    auto io = [&](auto&& op) {
        return step([&](auto h) {
            if (tls)
                op(*tls, h);
            else
                op(*plain, h);
        });
    };

    ec = io([&](auto& s, auto h) {
        http::async_write(s, req, [h](beast::error_code e, size_t) { h(e); });
    });
    if (ec)
        return finish("send: " + ec.message());

    // Skip a few interim 1xx answers ahead of the real one
    for (int interim = 0; ; interim++) {
        parser.emplace();
        parser->header_limit(8192);
        parser->skip(true);

        ec = io([&](auto& s, auto h) {
            http::async_read_header(s, buf, *parser, [h](beast::error_code e, size_t) { h(e); });
        });
        if (ec)
            return finish("response: " + ec.message());

        res.status = parser->get().result_int();
        if (res.status >= 200 || interim >= 3)
            break;
    }

    auto ra = parser->get().find(http::field::retry_after);
    if (ra != parser->get().end())
        res.retry_after = parse_retry_after(std::string(ra->value()), time(nullptr));

    {
        beast::error_code ign;
        lowest().socket().shutdown(tcp::socket::shutdown_both, ign);
        lowest().socket().close(ign);
    }

    return finish("");
}

void webhook_endpoint::run() {
    std::unique_lock<std::mutex> lk(m);

    while (!stopping) {
        if (queue.empty()) {
            cv.wait(lk);
            continue;
        }

        auto now = webhook_clock::now();

        auto due = queue.front().not_before;
        for (const auto& e : queue)
            due = std::min(due, e.not_before);

        auto ready = std::max({due, backoff_until, bucket.ready(now)});
        if (ready > now) {
            cv.wait_until(lk, ready);
            continue;
        }

        if (!bucket.take(now))
            continue;

        std::vector<event> batch;
        for (auto i = queue.begin(); i != queue.end() && batch.size() < max_events; ) {
            if (i->not_before <= now) {
                queue_bytes -= i->json.size();
                batch.push_back(std::move(*i));
                i = queue.erase(i);
            } else {
                ++i;
            }
        }

        auto dropped = dropped_unreported;
        auto suppressed = suppressed_unreported;

        lk.unlock();
        result res;
        try {
            res = deliver(envelope(batch, dropped, suppressed));
        } catch (const std::exception& e) {
            res = result{};
            res.error = fmt::format("internal error: {}", e.what());
        }
        lk.lock();

        auto wall = time(nullptr);
        last_status = res.status;

        if (res.status >= 200 && res.status < 300) {
            sent_requests++;
            sent_events += batch.size();
            dropped_unreported -= std::min(dropped_unreported, dropped);
            suppressed_unreported -= std::min(suppressed_unreported, suppressed);
            if (failures > 0)
                _MSG_INFO("Webhook endpoint '{}' is delivering again", name);
            failures = 0;
            last_success = wall;
            last_error.clear();
            continue;
        }

        if (stopping)
            break;

        failed_requests++;
        failures++;
        last_failure = wall;
        last_error = res.status != 0 ? fmt::format("HTTP {}", res.status) : res.error;

        bool retry = res.status == 0 || res.status == 408 || res.status == 429 ||
            (res.status >= 500 && res.status < 600);

        if (last_logged + log_interval <= wall || failures == 1) {
            _MSG_ERROR("Webhook endpoint '{}' ({}) failed: {}{}", name, url.redacted, last_error,
                    retry ? ", will retry" : ", events dropped");
            last_logged = wall;
        }

        if (!retry) {
            rejected_events += batch.size();
            continue;
        }

        int64_t wait;
        if ((res.status == 429 || res.status == 503) && res.retry_after >= 0)
            wait = res.retry_after;
        else
            wait = std::min<int64_t>(max_backoff, int64_t{5} << std::min(failures - 1, 6U));

        backoff_until = webhook_clock::now() + std::chrono::seconds(wait);
        backoff_wall = wall + wait;

        // Put the batch back ahead of newer events, dropping the ones out of tries
        for (auto i = batch.rbegin(); i != batch.rend(); ++i) {
            if (++i->attempts >= max_attempts) {
                dropped_events++;
                dropped_unreported++;
                continue;
            }
            if (queue.size() >= queue_max || queue_bytes + i->json.size() > max_queue_bytes) {
                dropped_events++;
                dropped_unreported++;
                continue;
            }
            queue_bytes += i->json.size();
            queue.push_front(std::move(*i));
        }
    }
}

std::shared_ptr<tracker_element_map> webhook_endpoint::status() {
    auto et = Globalreg::fetch_mandatory_global_as<entry_tracker>();
    auto r = std::make_shared<tracker_element_map>();

    auto f_name = status_field<tracker_element_string>(et, "kismet.webhooks.endpoint.name", "endpoint name");
    auto f_url = status_field<tracker_element_string>(et, "kismet.webhooks.endpoint.url",
            "endpoint scheme, host and port");
    auto f_queued = status_field<tracker_element_uint64>(et, "kismet.webhooks.endpoint.queued", "events waiting");
    auto f_reqs = status_field<tracker_element_uint64>(et, "kismet.webhooks.endpoint.sent_requests",
            "calls delivered");
    auto f_events = status_field<tracker_element_uint64>(et, "kismet.webhooks.endpoint.sent_events",
            "events delivered");
    auto f_failed = status_field<tracker_element_uint64>(et, "kismet.webhooks.endpoint.failed_requests",
            "calls that failed");
    auto f_dropped = status_field<tracker_element_uint64>(et, "kismet.webhooks.endpoint.dropped_events",
            "events dropped: queue full or out of retries");
    auto f_rejected = status_field<tracker_element_uint64>(et, "kismet.webhooks.endpoint.rejected_events",
            "events the receiver refused");
    auto f_suppressed = status_field<tracker_element_uint64>(et, "kismet.webhooks.endpoint.suppressed_events",
            "events a rate limit kept back");
    auto f_status = status_field<tracker_element_int32>(et, "kismet.webhooks.endpoint.last_status",
            "HTTP status of the last call, 0 when it got none");
    auto f_error = status_field<tracker_element_string>(et, "kismet.webhooks.endpoint.last_error",
            "error of the last failed call");
    auto f_success = status_field<tracker_element_uint64>(et, "kismet.webhooks.endpoint.last_success",
            "time of the last delivered call");
    auto f_failure = status_field<tracker_element_uint64>(et, "kismet.webhooks.endpoint.last_failure",
            "time of the last failed call");
    auto f_backoff = status_field<tracker_element_uint64>(et, "kismet.webhooks.endpoint.backoff_until",
            "time sending resumes after failures");

    std::lock_guard<std::mutex> lk(m);

    f_name->set(name);
    f_url->set(url.redacted);
    f_queued->set(queue.size());
    f_reqs->set(sent_requests);
    f_events->set(sent_events);
    f_failed->set(failed_requests);
    f_dropped->set(dropped_events);
    f_rejected->set(rejected_events);
    f_suppressed->set(suppressed_events);
    f_status->set(last_status);
    f_error->set(last_error);
    f_success->set(last_success);
    f_failure->set(last_failure);
    f_backoff->set(backoff_wall > time(nullptr) ? backoff_wall : 0);

    for (auto f : std::vector<shared_tracker_element>{f_name, f_url, f_queued, f_reqs, f_events, f_failed,
            f_dropped, f_rejected, f_suppressed, f_status, f_error, f_success, f_failure, f_backoff})
        r->insert(f);

    return r;
}

kis_webhooks::kis_webhooks() :
    lifetime_global(),
    deferred_startup(),
    max_tracked{100000},
    seq{0},
    group_seq{0},
    timer_id{-1} {

    mutex.set_name("webhooks");

    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();

    auto conf = Globalreg::globalreg->kismet_config;

    max_tracked = conf->fetch_opt_uint("webhook_max_tracked", 100000);

    uint32_t grate = 600;
    int64_t gperiod = 60;
    auto gr = conf->fetch_opt("webhook_global_rate");
    if (!gr.empty() && !parse_rate(gr, grate, gperiod))
        _MSG_ERROR("Ignoring webhook_global_rate={}; expected a rate such as 600/1m", gr);
    global_rate.init(grate, gperiod, std::max<uint32_t>(grate / 6, 1));

    load_endpoints();

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();
    httpd->register_route("/webhooks/status", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection>) {
                    return status_endpoint();
                }));
}

kis_webhooks::~kis_webhooks() {
    trigger_deferred_shutdown();
}

void kis_webhooks::load_endpoints() {
    auto conf = Globalreg::globalreg->kismet_config;

    for (const auto& line : conf->fetch_opt_vec("webhook_endpoint")) {
        auto colon = line.find(':');
        auto name = line.substr(0, colon);

        auto fail = [&](const std::string& why) {
            _MSG_ERROR("Webhook endpoint '{}' not loaded: {}", name, why);
        };

        if (colon == std::string::npos || !valid_name(name)) {
            _MSG_ERROR("Webhook endpoint not loaded: expected webhook_endpoint=<name>:url=...; names "
                    "are letters, digits, - and _");
            continue;
        }

        if (endpoints.find(name) != endpoints.end()) {
            fail("defined twice");
            continue;
        }

        if (endpoints.size() >= max_endpoints) {
            fail(fmt::format("more than {} endpoints", max_endpoints));
            continue;
        }

        std::vector<opt_pair> opts;
        string_to_opts(line.substr(colon + 1), ",", &opts);

        webhook_url url;
        std::string err;
        if (!parse_webhook_url(fetch_opt("url", &opts), url, err)) {
            fail(err);
            continue;
        }

        auto ep = std::make_shared<webhook_endpoint>(name, url);
        bool ok = true;

        ep->secret = fetch_opt("secret", &opts);
        if (!ep->secret.empty() && ep->secret.size() < 16)
            _MSG_ERROR("Webhook endpoint '{}' has a secret shorter than 16 characters", name);

        for (const auto& h : fetch_opt_vec("header", &opts)) {
            auto hc = h.find(':');
            auto hn = h.substr(0, hc);
            auto hv = hc == std::string::npos ? "" : h.substr(hc + 1);
            while (!hv.empty() && hv[0] == ' ')
                hv.erase(0, 1);
            if (hc == std::string::npos || !valid_header_name(hn) || !valid_header_value(hv)) {
                fail("bad header; expected header=\"Name: value\"");
                ok = false;
                break;
            }
            if (ep->headers.size() >= max_headers) {
                fail(fmt::format("more than {} headers", max_headers));
                ok = false;
                break;
            }
            ep->headers.emplace_back(hn, hv);
        }

        auto opt_seconds = [&](const char *key, int64_t lo, int64_t hi, int64_t& out) {
            auto v = fetch_opt(key, &opts);
            if (v.empty())
                return;
            if (!parse_seconds(v, lo, hi, out)) {
                fail(fmt::format("bad {}={}; expected {}s to {}s", key, v, lo, hi));
                ok = false;
            }
        };

        auto opt_count = [&](const char *key, uint64_t lo, uint64_t hi, uint64_t& out) {
            auto v = fetch_opt(key, &opts);
            if (v.empty())
                return;
            if (!parse_count(v, lo, hi, out)) {
                fail(fmt::format("bad {}={}; expected {} to {}", key, v, lo, hi));
                ok = false;
            }
        };

        int64_t timeout = 10;
        opt_seconds("timeout", 1, 60, timeout);
        ep->timeout = std::chrono::seconds(timeout);

        uint64_t queue = ep->queue_max, maxev = ep->max_events, burst = ep->burst;
        opt_count("queue", 1, max_queue_events, queue);
        opt_count("max_events", 1, devicerules::hook_max_batch_events, maxev);
        opt_count("burst", 1, devicerules::hook_max_rate, burst);
        ep->queue_max = queue;
        ep->max_events = static_cast<uint32_t>(maxev);
        ep->burst = static_cast<uint32_t>(burst);

        auto rate = fetch_opt("rate", &opts);
        if (!rate.empty() && !parse_rate(rate, ep->rate, ep->rate_period)) {
            fail(fmt::format("bad rate={}; expected a rate such as 30/1m", rate));
            ok = false;
        }

        ep->insecure = fetch_opt_bool("insecure", &opts, 0);
        ep->ca_file = fetch_opt("ca", &opts);

        if (!url.tls && (ep->insecure || !ep->ca_file.empty())) {
            fail("insecure and ca only apply to https urls");
            ok = false;
        }

        if (!ok)
            continue;

        if (!url.tls && !ep->secret.empty())
            _MSG_INFO("Webhook endpoint '{}' sends signed events over plain http; the events "
                    "themselves are not encrypted", name);

        endpoints[name] = ep;
        _MSG_INFO("Webhook endpoint '{}' sends to {}", name, url.redacted);
    }
}

void kis_webhooks::trigger_deferred_startup() {
    for (auto& e : endpoints) {
        try {
            e.second->start();
        } catch (const std::exception& ex) {
            _MSG_ERROR("Webhook endpoint '{}' could not start: {}", e.first, ex.what());
        }
    }

    timer_id =
        Globalreg::fetch_mandatory_global_as<time_tracker>()->register_timer(
                SERVER_TIMESLICES_SEC, nullptr, 1, [this](int) -> int {
                    tick();
                    return 1;
                });
}

void kis_webhooks::trigger_deferred_shutdown() {
    if (timer_id >= 0) {
        auto timetracker = Globalreg::fetch_global_as<time_tracker>(time_tracker::global_name());
        if (timetracker != nullptr)
            timetracker->remove_timer(timer_id);
        timer_id = -1;
    }

    // Every endpoint at once, then wait for them all
    for (auto& e : endpoints)
        e.second->request_stop();
    for (auto& e : endpoints)
        e.second->join();
}

std::shared_ptr<webhook_binding> kis_webhooks::bind(const devicerules::rule_def& rd, size_t idx) {
    const auto& def = rd.webhooks.at(idx);

    auto ei = endpoints.find(def.endpoint);
    if (ei == endpoints.end())
        throw devicerules::parse_error("rule '" + rd.name + "': no webhook endpoint '" + def.endpoint +
                "' in the config (webhook_endpoint=" + def.endpoint + ":url=...)", def.line, def.col);

    auto b = std::make_shared<webhook_binding>();
    b->key = fmt::format("{}/{}", rd.name, idx);
    b->rule = rd.name;
    b->description = rd.description;
    b->def = def;
    b->endpoint = ei->second;

    auto et = Globalreg::fetch_mandatory_global_as<entry_tracker>();

    auto resolve = [&](const std::string& name, std::vector<int>& path) -> std::string {
        std::string full = name;
        if (name.find('.') == std::string::npos && name.find('/') == std::string::npos) {
            auto a = devicerules::field_alias(name);
            if (a == nullptr)
                throw devicerules::parse_error("rule '" + rd.name + "': unknown field '" + name + "'",
                        def.line, def.col);
            full = a;
        }
        for (const auto& pe : str_tokenize(full, "/")) {
            auto id = et->get_field_id(pe);
            if (id == 0)
                throw devicerules::parse_error("rule '" + rd.name + "': unknown field '" + pe + "'",
                        def.line, def.col);
            path.push_back(id);
        }
        return full;
    };

    std::vector<std::string> fields;
    if (def.fields.empty())
        fields.assign(std::begin(default_fields), std::end(default_fields));
    else
        fields = def.fields;

    for (const auto& f : fields) {
        std::vector<int> path;
        auto full = resolve(f, path);
        b->fields.push_back(std::make_shared<tracker_element_summary>(full));
    }

    for (const auto& f : def.change_fields) {
        std::vector<int> path;
        auto full = resolve(f, path);
        auto inst = et->get_shared_instance(path.back());
        if (inst == nullptr || !inst->is_stringable())
            throw devicerules::parse_error("rule '" + rd.name + "': change field '" + f +
                    "' isn't a single value", def.line, def.col);
        b->change_paths.push_back(path);
        b->change_names.push_back(full);
    }

    return b;
}

std::shared_ptr<webhook_hook_state> kis_webhooks::new_state(const std::shared_ptr<webhook_binding>& b,
        uint32_t gen, time_t now) {
    auto hs = std::make_shared<hook_state>();
    hs->b = b;
    hs->installed = now;
    hs->priming = true;
    hs->prime_gen = gen;
    hs->rate.init(b->def.rate, b->def.rate_period, b->def.burst);
    return hs;
}

void kis_webhooks::install(const std::vector<std::shared_ptr<webhook_binding>>& bindings, uint32_t gen) {
    kis_lock_guard<kis_mutex> lk(mutex, "webhooks install");

    time_t now = Globalreg::globalreg->last_tv_sec;
    std::map<std::string, std::shared_ptr<hook_state>> next;

    for (const auto& b : bindings) {
        std::shared_ptr<hook_state> hs;

        auto hi = hooks.find(b->key);
        if (hi != hooks.end()) {
            hs = hi->second;
            std::lock_guard<std::mutex> hlk(hs->m);
            const auto& od = hs->b->def;
            // Kept state only means something for the same trigger; a new state
            // leaves the old one to the old rule set's bindings until it's replaced
            if (od.trigger != b->def.trigger || od.change_fields != b->def.change_fields) {
                hs.reset();
            } else {
                if (od.rate != b->def.rate || od.rate_period != b->def.rate_period || od.burst != b->def.burst)
                    hs->rate.init(b->def.rate, b->def.rate_period, b->def.burst);
                hs->b = b;
            }
        }

        if (hs == nullptr)
            hs = new_state(b, gen, now);

        b->state = hs;
        next[b->key] = hs;
    }

    hooks = std::move(next);
}

void kis_webhooks::primed(uint32_t gen) {
    kis_lock_guard<kis_mutex> lk(mutex, "webhooks primed");
    for (auto& h : hooks) {
        std::lock_guard<std::mutex> hlk(h.second->m);
        if (h.second->priming && h.second->prime_gen <= gen)
            h.second->priming = false;
    }
}

std::vector<std::string> kis_webhooks::read_values(const webhook_binding& b,
        const std::shared_ptr<kis_tracked_device_base>& dev) {
    std::vector<std::string> v;
    v.reserve(b.change_paths.size());
    for (const auto& p : b.change_paths) {
        auto s = pack_element(get_tracker_element_path(p, dev));
        if (s.size() > max_change_value)
            s = fmt::format("\"<{} bytes, hash {:016x}>\"", s.size(), std::hash<std::string>{}(s));
        v.push_back(std::move(s));
    }
    return v;
}

bool kis_webhooks::allow(hook_state& hs) {
    auto now = webhook_clock::now();

    bool ok;
    {
        // Both limits are checked before either token is taken
        std::lock_guard<std::mutex> lk(global_m);
        ok = hs.rate.available(now) && global_rate.available(now);
        if (ok) {
            hs.rate.take(now);
            global_rate.take(now);
        }
    }

    if (!ok) {
        hs.suppressed++;
        hs.b->endpoint->note_suppressed(1);
        return false;
    }

    hs.fired++;
    return true;
}

void kis_webhooks::device_event(const std::shared_ptr<webhook_binding>& b, dev_event ev,
        const std::shared_ptr<kis_tracked_device_base>& dev) {
    using devicerules::hook_trigger;

    auto hsp = b->state;
    if (hsp == nullptr)
        return;
    auto& hs = *hsp;

    const auto& def = b->def;
    const bool change = def.trigger == hook_trigger::change;
    time_t now = Globalreg::globalreg->last_tv_sec;

    fire f;
    f.trigger = nullptr;
    bool warn_full = false;

    {
        std::lock_guard<std::mutex> lk(hs.m);

        auto key = dev->get_key();

        auto queue_at = [&](dev_state& st, time_t when) {
            if (st.due == when)
                return;
            if (st.due != 0)
                hs.due_q.erase({st.due, key});
            st.due = when;
            hs.due_q.emplace(when, key);
        };

        auto unqueue = [&](dev_state& st) {
            if (st.due != 0) {
                hs.due_q.erase({st.due, key});
                st.due = 0;
            }
        };

        auto read = [&](dev_state& st) {
            st.checked = now;
            return read_values(*b, dev);
        };

        auto full = [&]() {
            hs.untracked++;
            if (!hs.warned_full) {
                hs.warned_full = true;
                warn_full = true;
            }
        };

        auto decide = [&]() {
            bool old = static_cast<time_t>(dev->get_first_time()) < hs.installed;

            if (!b->per_device()) {
                // Plain match and once keep no state per device
                if (ev != dev_event::start)
                    return;
                if (hs.priming && !def.fire_existing && old) {
                    hs.primed_devices++;
                    if (def.trigger == hook_trigger::once)
                        hs.once_fired = true;
                    return;
                }
                if (def.trigger == hook_trigger::once && hs.once_fired)
                    return;
                if (!allow(hs))
                    return;
                if (def.trigger == hook_trigger::once) {
                    hs.once_fired = true;
                    f.trigger = "once";
                } else {
                    f.trigger = "match";
                }
                return;
            }

            if (ev == dev_event::stop) {
                auto si = hs.devs.find(key);
                if (si == hs.devs.end())
                    return;
                if (si->second.notified && def.stop && allow(hs))
                    f.trigger = "stop";
                bool sent_new = si->second.new_done;
                unqueue(si->second);
                hs.devs.erase(si);
                // Only 'new' needs to remember a device that's no longer matching
                if (def.trigger == hook_trigger::new_device && sent_new) {
                    if (hs.new_sent.size() < max_tracked * new_sent_factor)
                        hs.new_sent.insert(key);
                    else
                        full();
                }
                return;
            }

            auto si = hs.devs.find(key);
            if (si == hs.devs.end()) {
                if (hs.devs.size() >= max_tracked) {
                    full();
                    return;
                }
                si = hs.devs.emplace(key, dev_state{}).first;
                si->second.new_done = hs.new_sent.erase(key) > 0;
                // A device already matching when its state was lost isn't a new match
                if (ev != dev_event::start) {
                    si->second.match_since = now;
                    si->second.handled = true;
                    si->second.last_sent = now;
                    if (change)
                        si->second.values = read(si->second);
                }
            }

            auto& st = si->second;
            st.touched = now;

            if (ev == dev_event::start || st.match_since == 0) {
                st.match_since = now;
                st.handled = false;
                st.notified = false;
                st.trailing = false;
                unqueue(st);

                if (hs.priming && !def.fire_existing && old) {
                    hs.primed_devices++;
                    st.handled = true;
                    st.last_sent = now;
                    if (change)
                        st.values = read(st);
                    if (def.trigger == hook_trigger::new_device)
                        st.new_done = true;
                    return;
                }
            }

            if (!st.handled) {
                if (def.hold > 0 && now - st.match_since < def.hold) {
                    queue_at(st, st.match_since + def.hold);
                    return;
                }
                unqueue(st);
                st.handled = true;
                st.last_sent = now;
                if (change)
                    st.values = read(st);

                const char *trig = "match";
                bool eligible = true;
                if (def.trigger == hook_trigger::new_device) {
                    eligible = !st.new_done && !old;
                    trig = "new";
                } else if (def.trigger == hook_trigger::once) {
                    eligible = !hs.once_fired;
                    trig = "once";
                }

                // once and new are only spent on a send the rate limits let through
                if (!eligible || !allow(hs))
                    return;
                if (def.trigger == hook_trigger::new_device)
                    st.new_done = true;
                else if (def.trigger == hook_trigger::once)
                    hs.once_fired = true;
                st.notified = true;
                f.trigger = trig;
                return;
            }

            if (def.trigger == hook_trigger::every) {
                if (now - st.last_sent >= def.interval) {
                    st.last_sent = now;
                    if (allow(hs)) {
                        f.trigger = "every";
                        st.notified = true;
                    }
                }
                return;
            }

            if (!change)
                return;

            // Packets read the fields at most once a second, and not at all while a
            // change waits on the limit; the due queue checks it when the limit is up
            if (ev != dev_event::due &&
                    (st.checked == now || (st.trailing && now - st.last_sent < def.interval)))
                return;

            auto values = read(st);

            if (values == st.values) {
                if (st.trailing) {
                    st.trailing = false;
                    unqueue(st);
                }
                return;
            }

            if (now - st.last_sent < def.interval) {
                // Merged into one send when the limit is up
                st.trailing = true;
                queue_at(st, st.last_sent + def.interval);
                return;
            }

            if (!allow(hs)) {
                // Try again after another limit, not every tick
                st.last_sent = now;
                st.trailing = true;
                queue_at(st, now + def.interval);
                return;
            }

            for (size_t i = 0; i < values.size(); i++)
                if (i >= st.values.size() || values[i] != st.values[i]) {
                    f.changed_old.emplace_back(b->change_names[i],
                            i < st.values.size() ? st.values[i] : "null");
                    f.changed_new.push_back(values[i]);
                }
            f.trigger = "change";
            st.notified = true;
            st.values = std::move(values);
            st.last_sent = now;
            st.trailing = false;
            unqueue(st);
        };

        decide();

        if (f.trigger != nullptr) {
            f.b = b;
            f.seq = ++seq;

            // Events of one batch window share a release time; a full window goes at once
            f.not_before = webhook_clock::now();
            f.group = 0;
            f.release = false;
            if (def.batch > 0) {
                if (hs.batch_group == 0 || f.not_before >= hs.batch_until || hs.batch_count >= def.batch_max) {
                    hs.batch_group = ++group_seq;
                    hs.batch_until = f.not_before + std::chrono::seconds(def.batch);
                    hs.batch_count = 0;
                }
                hs.batch_count++;
                f.group = hs.batch_group;
                f.not_before = hs.batch_until;
                f.release = hs.batch_count >= def.batch_max;
            }
        }
    }

    if (warn_full)
        _MSG_ERROR("The webhook for device rule '{}' is keeping state for webhook_max_tracked={} "
                "devices; more devices are skipped until some stop matching", b->rule, max_tracked);

    if (f.trigger == nullptr)
        return;

    send(f, dev, now);
}

void kis_webhooks::send(fire& f, const std::shared_ptr<kis_tracked_device_base>& dev, time_t now) {
    const auto& b = *f.b;

    std::string js;
    js.reserve(1024);

    nlohmann::json head;
    head["rule"] = b.rule;
    if (!b.description.empty())
        head["description"] = b.description;
    head["trigger"] = f.trigger;
    head["time"] = now;
    head["seq"] = f.seq;

    // The device as the REST api's fields would give it
    auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();
    auto summary = summarize_tracker_element(std::static_pointer_cast<tracker_element>(dev), b.fields, rename_map);
    std::stringstream ss;
    json_adapter::pack(ss, summary, rename_map);

    js = head.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    js.pop_back();
    js += ",\"device\":";
    js += ss.str().empty() ? "null" : ss.str();

    if (!f.changed_new.empty()) {
        js += ",\"changed\":{";
        for (size_t i = 0; i < f.changed_new.size(); i++) {
            if (i > 0)
                js += ",";
            js += nlohmann::json(f.changed_old[i].first).dump();
            js += ":{\"old\":";
            js += f.changed_old[i].second;
            js += ",\"new\":";
            js += f.changed_new[i];
            js += "}";
        }
        js += "}";
    }

    js += "}";

    repair_utf8(js);

    b.endpoint->enqueue(f.seq, f.group, f.not_before, std::move(js));
    if (f.release)
        b.endpoint->release(f.group);
}

void kis_webhooks::tick() {
    time_t now = Globalreg::globalreg->last_tv_sec;

    std::vector<std::shared_ptr<hook_state>> list;
    {
        kis_lock_guard<kis_mutex> lk(mutex, "webhooks tick");
        for (const auto& h : hooks)
            list.push_back(h.second);
    }

    for (const auto& hs : list)
        tick_hook(hs, now);
}

void kis_webhooks::tick_hook(const std::shared_ptr<hook_state>& hs, time_t now) {
    std::shared_ptr<webhook_binding> b;
    std::vector<device_key> due, idle, idle_new;

    {
        std::lock_guard<std::mutex> lk(hs->m);
        b = hs->b;

        while (!hs->due_q.empty() && hs->due_q.begin()->first <= now && due.size() < max_due_per_tick) {
            auto k = hs->due_q.begin()->second;
            hs->due_q.erase(hs->due_q.begin());
            auto si = hs->devs.find(k);
            if (si != hs->devs.end())
                si->second.due = 0;
            due.push_back(k);
        }

        // A slice of the purge each tick
        scan_slice(hs->devs, hs->purge_bucket, [&](const std::pair<const device_key, dev_state>& d) {
            if (d.second.touched + purge_idle < now)
                idle.push_back(d.first);
        });
        scan_slice(hs->new_sent, hs->purge_new_bucket, [&](const device_key& k) {
            idle_new.push_back(k);
        });
    }

    for (const auto& k : due) {
        auto dev = devicetracker->fetch_device(k);
        if (dev == nullptr)
            continue;
        kis_device_lock dlk(dev, false);
        device_event(b, dev_event::due, dev);
    }

    if (idle.empty() && idle_new.empty())
        return;

    // Devices timed out of the tracker never send a stop; forget them
    std::vector<device_key> gone, gone_new;
    for (const auto& k : idle)
        if (devicetracker->fetch_device(k) == nullptr)
            gone.push_back(k);
    for (const auto& k : idle_new)
        if (devicetracker->fetch_device(k) == nullptr)
            gone_new.push_back(k);

    std::lock_guard<std::mutex> lk(hs->m);
    for (const auto& k : idle) {
        auto si = hs->devs.find(k);
        if (si != hs->devs.end())
            si->second.touched = now;
    }
    for (const auto& k : gone) {
        auto si = hs->devs.find(k);
        if (si == hs->devs.end())
            continue;
        if (si->second.due != 0)
            hs->due_q.erase({si->second.due, k});
        hs->devs.erase(si);
    }
    for (const auto& k : gone_new)
        hs->new_sent.erase(k);
}

std::shared_ptr<tracker_element> kis_webhooks::status_endpoint() {
    auto et = Globalreg::fetch_mandatory_global_as<entry_tracker>();
    auto ret = std::make_shared<tracker_element_map>();

    auto eps = status_field<tracker_element_vector>(et, "kismet.webhooks.endpoints", "webhook endpoints");
    for (const auto& e : endpoints)
        eps->push_back(e.second->status());
    ret->insert(eps);

    auto rules = status_field<tracker_element_vector>(et, "kismet.webhooks.rules", "device rule webhooks");

    std::vector<std::shared_ptr<hook_state>> list;
    {
        kis_lock_guard<kis_mutex> lk(mutex, "webhooks status");
        for (const auto& h : hooks)
            list.push_back(h.second);
    }

    for (const auto& hsp : list) {
        std::lock_guard<std::mutex> hlk(hsp->m);
        const auto& hs = *hsp;
        auto r = std::make_shared<tracker_element_map>();

        auto f_rule = status_field<tracker_element_string>(et, "kismet.webhooks.rule.rule", "device rule");
        auto f_endpoint = status_field<tracker_element_string>(et, "kismet.webhooks.rule.endpoint",
                "endpoint the rule sends to");
        auto f_trigger = status_field<tracker_element_string>(et, "kismet.webhooks.rule.trigger",
                "when the rule sends");
        auto f_fired = status_field<tracker_element_uint64>(et, "kismet.webhooks.rule.fired", "events sent");
        auto f_supp = status_field<tracker_element_uint64>(et, "kismet.webhooks.rule.suppressed",
                "events the rate limits kept back");
        auto f_primed = status_field<tracker_element_uint64>(et, "kismet.webhooks.rule.primed",
                "devices already matching when the rule loaded, not sent");
        auto f_tracked = status_field<tracker_element_uint64>(et, "kismet.webhooks.rule.tracked",
                "devices with webhook state");
        auto f_untracked = status_field<tracker_element_uint64>(et, "kismet.webhooks.rule.untracked",
                "devices skipped at webhook_max_tracked");
        auto f_priming = status_field<tracker_element_uint8>(et, "kismet.webhooks.rule.priming",
                "still recording the devices that matched at load");

        f_rule->set(hs.b->rule);
        f_endpoint->set(hs.b->def.endpoint);
        f_trigger->set(devicerules::hook_trigger_name(hs.b->def.trigger));
        f_fired->set(hs.fired);
        f_supp->set(hs.suppressed);
        f_primed->set(hs.primed_devices);
        f_tracked->set(hs.devs.size());
        f_untracked->set(hs.untracked);
        f_priming->set(hs.priming);

        for (auto f : std::vector<shared_tracker_element>{f_rule, f_endpoint, f_trigger, f_fired, f_supp,
                f_primed, f_tracked, f_untracked, f_priming})
            r->insert(f);

        rules->push_back(r);
    }

    ret->insert(rules);

    return ret;
}
