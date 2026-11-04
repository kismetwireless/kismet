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

#ifndef __WEBHOOKS_H__
#define __WEBHOOKS_H__

#include "config.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "devicerules/dr_core.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "trackedelement.h"

// Webhooks: device rules send JSON to HTTP endpoints set in the config.  Rule
// evaluation only decides and queues; each endpoint delivers from its own thread,
// with rate limits, a bounded queue and backoff, so nothing waits on the network.

class kis_tracked_device_base;
class device_tracker;

using webhook_clock = std::chrono::steady_clock;

// Tokens refill at rate per period up to burst
struct webhook_bucket {
    double tokens = 0;
    double cap = 0;
    double per_sec = 0;
    webhook_clock::time_point last;

    void init(uint32_t rate, int64_t period, uint32_t burst);
    bool take(webhook_clock::time_point now);
    // A token is there to take
    bool available(webhook_clock::time_point now);
    // When the next token is due
    webhook_clock::time_point ready(webhook_clock::time_point now);

private:
    void refill(webhook_clock::time_point now);
};

struct webhook_url {
    bool tls = false;
    std::string host;
    std::string port;
    // Request target: path and query
    std::string target;
    // Host header
    std::string host_header;
    // Scheme, host and port only; the path and query can hold secrets
    std::string redacted;
};

// Parse an http or https url; false with err when it isn't one we'll send to
bool parse_webhook_url(const std::string& in, webhook_url& out, std::string& err);

class webhook_endpoint {
public:
    webhook_endpoint(const std::string& name, const webhook_url& url);
    ~webhook_endpoint();

    webhook_endpoint(const webhook_endpoint&) = delete;
    webhook_endpoint& operator=(const webhook_endpoint&) = delete;

    const std::string name;
    const webhook_url url;

    std::string secret;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string ca_file;
    bool insecure = false;
    std::chrono::seconds timeout{10};
    size_t queue_max = 200;
    uint32_t max_events = 100;
    uint32_t rate = 30;
    int64_t rate_period = 60;
    uint32_t burst = 10;

    void start();
    void stop();
    // stop() in two halves, so many endpoints can stop at once
    void request_stop();
    void join();

    // Queue an event's JSON; events go out in seq order, and wait in the queue
    // until not_before.  group ties the events of one batch window together.
    void enqueue(uint64_t seq, uint64_t group, webhook_clock::time_point not_before, std::string json);

    // Send a batch window's events without waiting out its time
    void release(uint64_t group);

    // Events a rate limit kept from being queued, reported in the next call
    void note_suppressed(uint64_t n);

    std::shared_ptr<tracker_element_map> status();

protected:
    struct event {
        uint64_t seq;
        uint64_t group;
        webhook_clock::time_point not_before;
        unsigned int attempts;
        std::string json;
    };

    // A name lookup on a thread of its own, since getaddrinfo can't be cancelled
    struct resolve_job;

    struct result {
        int status = 0;
        std::string error;
        int64_t retry_after = -1;
    };

    std::mutex m;
    std::condition_variable cv;
    std::deque<event> queue;
    size_t queue_bytes = 0;
    bool stopping = false;
    std::atomic<bool> halt{false};
    // The lookup still running, if any; one at a time
    std::shared_ptr<resolve_job> resolving;
    std::thread worker;
    // The io_context of the request in flight, so stop() can end it
    void *cur_ioc = nullptr;

    webhook_bucket bucket;
    webhook_clock::time_point backoff_until;

    uint64_t sent_requests = 0, sent_events = 0, failed_requests = 0;
    uint64_t dropped_events = 0, rejected_events = 0, suppressed_events = 0;
    // Not yet reported to the receiver
    uint64_t dropped_unreported = 0, suppressed_unreported = 0;
    unsigned int failures = 0;
    int last_status = 0;
    std::string last_error;
    time_t last_success = 0, last_failure = 0, last_logged = 0;
    time_t backoff_wall = 0;

    std::shared_ptr<void> ssl_ctx;

    void run();
    void push_locked(event&& e);
    result deliver(const std::string& body);
    std::string envelope(const std::vector<event>& batch, uint64_t dropped, uint64_t suppressed);
};

struct webhook_dev_state {
    // 0 when not matching
    time_t match_since = 0;
    time_t last_sent = 0;
    // When the change fields were last read
    time_t checked = 0;
    time_t touched = 0;
    // Its time in the hook's due queue, or 0
    time_t due = 0;
    // This run of matching has been handled: sent, primed or not eligible
    bool handled = false;
    // A match was sent, so a stop goes too
    bool notified = false;
    bool new_done = false;
    // A change waits for the limit to pass
    bool trailing = false;
    std::vector<std::string> values;
};

struct webhook_binding;

// One rule webhook's state, kept across reloads while its trigger stays the same.
// Its mutex is taken after the device lock.
struct webhook_hook_state {
    std::mutex m;
    std::shared_ptr<webhook_binding> b;
    time_t installed = 0;
    bool priming = true;
    uint32_t prime_gen = 0;
    bool once_fired = false;
    bool warned_full = false;
    webhook_bucket rate;
    // The open batch window
    uint64_t batch_group = 0;
    webhook_clock::time_point batch_until;
    uint32_t batch_count = 0;
    uint64_t fired = 0, suppressed = 0, primed_devices = 0, untracked = 0;
    // Devices matching now, or with state still to finish
    std::unordered_map<device_key, webhook_dev_state> devs;
    // Devices 'new' already sent for that aren't matching now
    std::unordered_set<device_key> new_sent;
    // Devices waiting on the clock for a 'for' or a change limit, by time due
    std::set<std::pair<time_t, device_key>> due_q;
    // Where the purge left off
    size_t purge_bucket = 0, purge_new_bucket = 0;
};

// A rule's webhook, ready to use; built for each rule set
struct webhook_binding {
    // Rule name and webhook index, which state carries over reloads by
    std::string key;
    std::string rule;
    std::string description;
    devicerules::webhook_def def;
    std::shared_ptr<webhook_endpoint> endpoint;

    std::vector<std::shared_ptr<tracker_element_summary>> fields;
    std::vector<std::vector<int>> change_paths;
    std::vector<std::string> change_names;

    // Set when the rule set is installed
    std::shared_ptr<webhook_hook_state> state;

    // Needs to see devices that keep matching, not just the changes
    bool repeats() const {
        return def.trigger == devicerules::hook_trigger::every ||
            def.trigger == devicerules::hook_trigger::change || def.hold > 0;
    }

    // Keeps per-device state
    bool per_device() const {
        return repeats() || def.stop || def.trigger == devicerules::hook_trigger::new_device;
    }
};

class kis_webhooks : public lifetime_global, public deferred_startup {
public:
    static std::string global_name() { return "WEBHOOKS"; }

    static std::shared_ptr<kis_webhooks> create_webhooks() {
        std::shared_ptr<kis_webhooks> wh(new kis_webhooks());
        Globalreg::globalreg->register_lifetime_global(wh);
        Globalreg::globalreg->insert_global(global_name(), wh);
        Globalreg::globalreg->register_deferred_global(wh);
        return wh;
    }

private:
    kis_webhooks();

public:
    virtual ~kis_webhooks();

    virtual void trigger_deferred_startup() override;
    virtual void trigger_deferred_shutdown() override;

    // Build the binding for webhook idx of a rule; throws parse_error for an
    // unknown endpoint or field
    std::shared_ptr<webhook_binding> bind(const devicerules::rule_def& rd, size_t idx);

    // A rule set is in use.  Bindings new to it record the devices that already
    // match without sending, until primed() for its gen.
    void install(const std::vector<std::shared_ptr<webhook_binding>>& bindings, uint32_t gen);

    // A full pass over the devices for gen is done
    void primed(uint32_t gen);

    enum class dev_event {
        start,
        cont,
        stop,
        // From the webhooks timer: a 'for' or a change limit is up
        due,
    };

    // From a rule evaluation, with the device locked
    void device_event(const std::shared_ptr<webhook_binding>& b, dev_event ev,
            const std::shared_ptr<kis_tracked_device_base>& dev);

protected:
    using dev_state = webhook_dev_state;
    using hook_state = webhook_hook_state;

    // A send decided under the mutex, made after it's released
    struct fire {
        std::shared_ptr<webhook_binding> b;
        const char *trigger;
        uint64_t seq;
        uint64_t group;
        webhook_clock::time_point not_before;
        bool release;
        std::vector<std::pair<std::string, std::string>> changed_old;
        std::vector<std::string> changed_new;
    };

    // Guards hooks; device events only take their hook's own mutex
    kis_mutex mutex;

    std::map<std::string, std::shared_ptr<webhook_endpoint>> endpoints;
    std::map<std::string, std::shared_ptr<hook_state>> hooks;

    // Taken after a hook's mutex
    std::mutex global_m;
    webhook_bucket global_rate;
    size_t max_tracked;
    std::atomic<uint64_t> seq;
    std::atomic<uint64_t> group_seq;

    std::shared_ptr<device_tracker> devicetracker;
    int timer_id;

    void load_endpoints();

    std::vector<std::string> read_values(const webhook_binding& b, const std::shared_ptr<kis_tracked_device_base>& dev);

    // Rate limits for a send; false and counted when either is out of tokens
    bool allow(hook_state& hs);

    std::shared_ptr<hook_state> new_state(const std::shared_ptr<webhook_binding>& b, uint32_t gen, time_t now);

    void tick();
    void tick_hook(const std::shared_ptr<hook_state>& hs, time_t now);

    void send(fire& f, const std::shared_ptr<kis_tracked_device_base>& dev, time_t now);

    std::shared_ptr<tracker_element> status_endpoint();
};

#endif
