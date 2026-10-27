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

#include <chrono>
#include <fstream>
#include <sstream>

#include "alertracker.h"
#include "configfile.h"
#include "device_rules.h"
#include "devicetracker_view_workers.h"
#include "entrytracker.h"
#include "messagebus.h"
#include "packetchain.h"
#include "timetracker.h"

namespace {

constexpr size_t max_rules_text = 256 * 1024;
constexpr size_t max_views = 256;

using namespace devicerules;

tracker_element *deref_alias(tracker_element *e) {
    while (e != nullptr && e->get_type() == tracker_type::tracker_alias)
        e = static_cast<tracker_element_alias *>(e)->get().get();
    return e;
}

// Device field access over the tracked element tree; the device is locked by the caller
class kismet_env : public env {
public:
    tracker_element *root = nullptr;

    virtual bool load(const field_slot& f, value& out) override {
        auto e = walk(root, f, 0, f.path.size());
        if (e == nullptr)
            return false;
        return leaf(e, out);
    }

    virtual bool any(const field_slot& f, bool (*fn)(const value&, const void *), const void *arg) override {
        return fan(root, f, 0, fn, arg, nullptr);
    }

    virtual int64_t count(const field_slot& f) override {
        if (!f.multi) {
            auto e = walk(root, f, 0, f.path.size());
            if (e == nullptr)
                return 0;
            return container_size(e);
        }

        int64_t c = 0;
        fan(root, f, 0, nullptr, nullptr, &c);
        return c;
    }

    virtual bool exists(const field_slot& f) override {
        return found(root, f, 0);
    }

    virtual void reset() override {
        holds.clear();
    }

private:
    // Children of lazily built maps only live as long as we hold them
    std::vector<shared_tracker_element> holds;

    tracker_element *child(tracker_element *e, int id) {
        e = deref_alias(e);
        if (e == nullptr || e->get_type() != tracker_type::tracker_map)
            return nullptr;

        shared_tracker_element hold;
        auto c = static_cast<tracker_element_map *>(e)->peek_sub(id, hold);
        if (hold != nullptr)
            holds.push_back(std::move(hold));
        return deref_alias(c);
    }

    // Walk plain path elements [from, to)
    tracker_element *walk(tracker_element *e, const field_slot& f, size_t from, size_t to) {
        for (size_t i = from; i < to && e != nullptr; i++)
            e = child(e, f.path[i]);
        return e;
    }

    static bool leaf(tracker_element *e, value& out) {
        out = value{};

        switch (e->get_type()) {
            case tracker_type::tracker_string: {
                const auto& s = static_cast<tracker_element_string *>(e)->get();
                out.s = s.data();
                out.len = s.size();
                break;
            }
            case tracker_type::tracker_string_pointer: {
                auto s = static_cast<tracker_element_string_ptr *>(e)->get();
                if (s == nullptr)
                    return false;
                out.s = s->data();
                out.len = s->size();
                break;
            }
            case tracker_type::tracker_int8:
                out.i = static_cast<tracker_element_int8 *>(e)->get();
                break;
            case tracker_type::tracker_uint8:
                out.i = static_cast<tracker_element_uint8 *>(e)->get();
                break;
            case tracker_type::tracker_int16:
                out.i = static_cast<tracker_element_int16 *>(e)->get();
                break;
            case tracker_type::tracker_uint16:
                out.i = static_cast<tracker_element_uint16 *>(e)->get();
                break;
            case tracker_type::tracker_int32:
                out.i = static_cast<tracker_element_int32 *>(e)->get();
                break;
            case tracker_type::tracker_uint32:
                out.i = static_cast<tracker_element_uint32 *>(e)->get();
                break;
            case tracker_type::tracker_int64:
                out.i = static_cast<tracker_element_int64 *>(e)->get();
                break;
            case tracker_type::tracker_uint64: {
                auto u = static_cast<tracker_element_uint64 *>(e)->get();
                // Out of the signed range is treated as missing
                if (u > (uint64_t) INT64_MAX)
                    return false;
                out.i = (int64_t) u;
                break;
            }
            case tracker_type::tracker_float:
                out.f = static_cast<tracker_element_float *>(e)->get();
                break;
            case tracker_type::tracker_double:
                out.f = static_cast<tracker_element_double *>(e)->get();
                break;
            case tracker_type::tracker_mac_addr:
                out.m = static_cast<tracker_element_mac_addr *>(e)->get().longmac;
                break;
            default:
                return false;
        }

        out.valid = 1;
        return true;
    }

    template<typename C, typename F>
    static bool each_value(C *c, F fn) {
        for (const auto& i : *c)
            if (fn(i.second.get()))
                return true;
        return false;
    }

    // Call fn for each element of a container until it returns true
    template<typename F>
    static bool each(tracker_element *c, F fn) {
        switch (c->get_type()) {
            case tracker_type::tracker_vector:
                for (const auto& i : *static_cast<tracker_element_vector *>(c))
                    if (fn(i.get()))
                        return true;
                return false;
            case tracker_type::tracker_int_map:
                return each_value(static_cast<tracker_element_int_map *>(c), fn);
            case tracker_type::tracker_hashkey_map:
                return each_value(static_cast<tracker_element_hashkey_map *>(c), fn);
            case tracker_type::tracker_double_map:
                return each_value(static_cast<tracker_element_double_map *>(c), fn);
            case tracker_type::tracker_string_map:
                return each_value(static_cast<tracker_element_string_map *>(c), fn);
            case tracker_type::tracker_key_map:
                return each_value(static_cast<tracker_element_device_key_map *>(c), fn);
            case tracker_type::tracker_uuid_map:
                return each_value(static_cast<tracker_element_uuid_map *>(c), fn);
            case tracker_type::tracker_mac_map: {
                // Filter maps share the type tag with a different container
                if (auto m = dynamic_cast<tracker_element_mac_map *>(c))
                    return each_value(m, fn);
                if (auto m = dynamic_cast<tracker_element_macfilter_map *>(c))
                    return each_value(m, fn);
                return false;
            }
            default:
                return false;
        }
    }

    static int64_t container_size(tracker_element *c) {
        switch (c->get_type()) {
            case tracker_type::tracker_vector:
                return static_cast<tracker_element_vector *>(c)->size();
            case tracker_type::tracker_vector_string:
                return static_cast<tracker_element_vector_string *>(c)->size();
            case tracker_type::tracker_vector_double:
                return static_cast<tracker_element_vector_double *>(c)->size();
            default: {
                int64_t n = 0;
                each(c, [&n](tracker_element *) { n++; return false; });
                return n;
            }
        }
    }

    // Leaves of a multi path from path element i of e
    bool fan(tracker_element *e, const field_slot& f, size_t i,
            bool (*fn)(const value&, const void *), const void *arg, int64_t *cnt) {
        while (i < f.path.size()) {
            e = child(e, f.path[i]);
            if (e == nullptr)
                return false;

            if (f.fanout[i]) {
                return each(e, [&](tracker_element *c) {
                        return c != nullptr && fan(deref_alias(c), f, i + 1, fn, arg, cnt);
                    });
            }

            i++;
        }

        // Lists of plain values at the end of the path
        if (e->get_type() == tracker_type::tracker_vector_string) {
            for (const auto& s : *static_cast<tracker_element_vector_string *>(e)) {
                if (cnt != nullptr) {
                    (*cnt)++;
                    continue;
                }
                value v{};
                v.s = s.data();
                v.len = s.size();
                v.valid = 1;
                if (fn(v, arg))
                    return true;
            }
            return false;
        }

        if (e->get_type() == tracker_type::tracker_vector_double) {
            for (const auto& d : *static_cast<tracker_element_vector_double *>(e)) {
                if (cnt != nullptr) {
                    (*cnt)++;
                    continue;
                }
                value v{};
                v.f = d;
                v.valid = 1;
                if (fn(v, arg))
                    return true;
            }
            return false;
        }

        if (cnt != nullptr) {
            (*cnt)++;
            return false;
        }

        value v;
        if (!leaf(e, v))
            return false;
        return fn(v, arg);
    }

    bool found(tracker_element *e, const field_slot& f, size_t i) {
        while (i < f.path.size()) {
            e = child(e, f.path[i]);
            if (e == nullptr)
                return false;

            if (f.fanout[i])
                return each(e, [&](tracker_element *c) {
                        return c != nullptr && found(deref_alias(c), f, i + 1);
                    });

            i++;
        }

        return true;
    }
};

class kismet_resolver : public resolver {
public:
    kismet_resolver(std::shared_ptr<entry_tracker> et) :
        entrytracker{et} { }

    virtual int resolve(const std::string& name, ftype& t) override {
        auto id = entrytracker->get_field_id(name);
        if (id == 0)
            return -1;

        auto inst = entrytracker->get_shared_instance(id);
        if (inst == nullptr)
            return -1;

        switch (inst->get_type()) {
            case tracker_type::tracker_string:
            case tracker_type::tracker_string_pointer:
                t = ftype::string;
                break;
            case tracker_type::tracker_int8:
            case tracker_type::tracker_uint8:
            case tracker_type::tracker_int16:
            case tracker_type::tracker_uint16:
            case tracker_type::tracker_int32:
            case tracker_type::tracker_uint32:
            case tracker_type::tracker_int64:
                t = ftype::integer;
                break;
            case tracker_type::tracker_uint64:
                t = ftype::uinteger;
                break;
            case tracker_type::tracker_float:
            case tracker_type::tracker_double:
                t = ftype::real;
                break;
            case tracker_type::tracker_mac_addr:
                t = ftype::mac;
                break;
            case tracker_type::tracker_map:
                t = ftype::map;
                break;
            case tracker_type::tracker_vector:
            case tracker_type::tracker_int_map:
            case tracker_type::tracker_hashkey_map:
            case tracker_type::tracker_double_map:
            case tracker_type::tracker_string_map:
            case tracker_type::tracker_key_map:
            case tracker_type::tracker_uuid_map:
            case tracker_type::tracker_mac_map:
                t = ftype::container;
                break;
            case tracker_type::tracker_vector_string:
                t = ftype::string_list;
                break;
            case tracker_type::tracker_vector_double:
                t = ftype::real_list;
                break;
            default:
                t = ftype::unsupported;
                break;
        }

        return id;
    }

private:
    std::shared_ptr<entry_tracker> entrytracker;
};

}

// Evaluation state for the timer pass
struct device_rules::pass_state {
    uint32_t gen = 0;
    devicerules::eval_ctx ctx;
    kismet_env env;
    std::vector<uint8_t> out, prev;
};

namespace {

// Per-thread evaluation state for live rules
struct live_ctx {
    std::shared_ptr<device_rules::active_set> set;
    uint32_t gen = 0;
    devicerules::eval_ctx ctx;
    kismet_env env;
    std::vector<uint8_t> out, prev;
    std::vector<device_rules::pending_change> changes;
};

}

device_rules::device_rules() :
    lifetime_global(),
    deferred_startup(),
    next_gen{1},
    rule_state_id{-1},
    alert_ref{-1},
    timer_id{-1},
    pchain_id{-1},
    pass_count{0},
    last_pass{0},
    full_pending{true},
    stat_passes{0},
    stat_devices{0},
    stat_last_us{0},
    pass{std::make_unique<pass_state>()} {

    mutex.set_name("device_rules");
    alert_mutex.set_name("device_rules_alerts");

    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();
    entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();

    rule_state_id =
        entrytracker->register_field("kismet.device.base.rules",
                tracker_element_factory<device_rule_state>(),
                "device rule results");

    auto conf = Globalreg::globalreg->kismet_config;
    use_jit = conf->fetch_opt_bool("device_rules_jit", true);
    pass_interval = std::max(1U, conf->fetch_opt_uint("device_rules_interval", 1));
    full_interval = conf->fetch_opt_uint("device_rules_full_interval", 10);
    alert_backlog_max = conf->fetch_opt_uint("device_rules_alert_backlog", 64);

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/devices/rules/rules", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection>) {
                    return rules_endpoint();
                }));

    httpd->register_route("/devices/rules/check", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    check_endpoint(con);
                }));

    httpd->register_route("/devices/rules/set", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    set_endpoint(con);
                }));

    httpd->register_route("/devices/rules/test", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    test_endpoint(con);
                }));
}

device_rules::~device_rules() {
    trigger_deferred_shutdown();
}

void device_rules::trigger_deferred_startup() {
    auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();
    alert_ref =
        alertracker->activate_configured_alert("DEVICERULE", "SYSTEM", kis_alert_severity::info,
                "A device matched a device rule marked 'alert'.");

    auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
    pack_comp_device = packetchain->register_packet_component("DEVICE");

    // Rules are compiled here so every phy and plugin field is registered
    auto path = Globalreg::globalreg->kismet_config->fetch_opt_path("device_rules_file",
            "%E/kismet_device_rules.txt");

    std::ifstream f(path);
    if (f.good()) {
        std::stringstream ss;
        ss << f.rdbuf();

        if (ss.str().size() > max_rules_text) {
            _MSG_ERROR("Device rules file {} is larger than {} bytes; not loading it", path, max_rules_text);
        } else {
            try {
                set_rules(ss.str());
            } catch (const devicerules::parse_error& e) {
                _MSG_ERROR("Device rules in {}, line {} column {}: {}", path, e.line, e.col, e.what());
            } catch (const std::exception& e) {
                _MSG_ERROR("Could not load device rules from {}: {}", path, e.what());
            }
        }
    }

    timer_id =
        Globalreg::fetch_mandatory_global_as<time_tracker>()->register_timer(
                SERVER_TIMESLICES_SEC * pass_interval, nullptr, 1, [this](int) -> int {
                    timer_pass();
                    return 1;
                });

    pchain_id =
        packetchain->register_handler([](void *auxdata, const std::shared_ptr<kis_packet>& in_pack) -> int {
                return static_cast<device_rules *>(auxdata)->packet_hook(in_pack);
            }, this, CHAINPOS_TRACKER, 0x7FFFFFFE);
}

void device_rules::trigger_deferred_shutdown() {
    if (timer_id >= 0) {
        auto timetracker = Globalreg::fetch_global_as<time_tracker>(time_tracker::global_name());
        if (timetracker != nullptr)
            timetracker->remove_timer(timer_id);
        timer_id = -1;
    }

    if (pchain_id >= 0) {
        auto packetchain = Globalreg::fetch_global_as<packet_chain>(packet_chain::global_name());
        if (packetchain != nullptr)
            packetchain->remove_handler(pchain_id, CHAINPOS_TRACKER);
        pchain_id = -1;
    }
}

std::shared_ptr<device_rules::active_set> device_rules::compile_set(const std::string& text) {
    if (text.size() > max_rules_text)
        throw devicerules::parse_error("rules are larger than " + std::to_string(max_rules_text) + " bytes", 0, 0);

    auto as = std::make_shared<active_set>();
    as->rs = std::make_unique<devicerules::ruleset>();
    as->text = text;
    as->jit = false;
    as->any_live = false;

    as->rs->parse(text);

    kismet_resolver r(entrytracker);
    as->rs->compile(r);

    if (use_jit) {
        as->jit = as->rs->jit(as->jit_error);
    } else {
        as->jit_error = "disabled by device_rules_jit";
    }

    size_t n = as->rs->size();
    as->live_want.assign(n, 0);
    as->views.assign(n, nullptr);

    for (size_t i = 0; i < n; i++) {
        const auto& rd = as->rs->rule(i);
        as->by_name[rd.name] = i;
        if (rd.live) {
            as->live_want[i] = 1;
            as->any_live = true;
        }
    }

    return as;
}

void device_rules::set_rules(const std::string& text) {
    auto as = compile_set(text);

    kis_lock_guard<kis_mutex> lk(mutex, "device_rules set_rules");

    size_t new_views = 0;
    for (size_t i = 0; i < as->rs->size(); i++)
        if (as->rs->rule(i).view && views.find(as->rs->rule(i).name) == views.end())
            new_views++;

    if (views.size() + new_views > max_views)
        throw devicerules::parse_error("rules would make more than " + std::to_string(max_views) +
                " views", 0, 0);

    for (size_t i = 0; i < as->rs->size(); i++) {
        const auto& rd = as->rs->rule(i);
        if (!rd.view)
            continue;

        auto vi = views.find(rd.name);
        if (vi == views.end()) {
            auto desc = rd.view_desc.empty() ? fmt::format("Devices matching rule {}", rd.name) : rd.view_desc;
            auto v = std::make_shared<device_tracker_view>(fmt::format("rule-{}", rd.name), desc,
                    nullptr, nullptr);
            devicetracker->add_view(v);
            vi = views.emplace(rd.name, v).first;
        }

        as->views[i] = vi->second;
    }

    for (const auto& v : views) {
        auto ri = as->by_name.find(v.first);
        if (ri == as->by_name.end() || as->views[ri->second] == nullptr)
            as->retired[v.first] = v.second;
    }

    as->gen = next_gen++;

    std::atomic_store(&current, as);
    full_pending = true;

    _MSG_INFO("Loaded {} device rule(s), evaluated by {}{}", as->rs->size(),
            as->jit ? "the JIT" : "the VM",
            as->jit ? "" : fmt::format(" ({})", as->jit_error));
}

void device_rules::eval_device(active_set& as, devicerules::eval_ctx& ctx,
        const std::shared_ptr<kis_tracked_device_base>& dev, const uint8_t *want,
        std::vector<uint8_t>& out, std::vector<uint8_t>& prev, std::vector<pending_change>& changes) {

    if (dev->get_removed())
        return;

    const size_t n = as.rs->size();
    out.resize(n);
    prev.assign(n, 0);

    auto env = static_cast<kismet_env *>(ctx.e);
    env->root = dev.get();
    ctx.next_device(Globalreg::globalreg->last_tv_sec);
    as.rs->eval_all(ctx, want, out.data());
    env->reset();
    env->root = nullptr;

    auto state = dev->get_sub_as<device_rule_state>(rule_state_id);

    if (state != nullptr) {
        if (state->gen == as.gen && state->hits.size() == n) {
            prev = state->hits;
        } else {
            // Rules carry over a reload by name
            for (const auto& m : *state->get_matched()) {
                auto ri = as.by_name.find(m);
                if (ri != as.by_name.end())
                    prev[ri->second] = 1;
            }
        }
    }

    if (want != nullptr)
        for (size_t r = 0; r < n; r++)
            if (!want[r])
                out[r] = prev[r];

    bool any = false;
    for (size_t r = 0; r < n; r++)
        any |= out[r] != 0;

    if (state == nullptr && !any)
        return;

    if (state != nullptr && state->gen == as.gen && out == prev)
        return;

    for (size_t r = 0; r < n; r++) {
        if (out[r] == prev[r])
            continue;

        const auto& rd = as.rs->rule(r);

        if (as.views[r] != nullptr)
            changes.push_back(pending_change{dev, as.views[r], out[r] != 0, "", mac_addr{}});

        if (out[r] && rd.alert)
            changes.push_back(pending_change{dev, nullptr, false,
                    fmt::format("Device {} ({}) matched device rule '{}'", dev->get_macaddr(),
                            dev->get_commonname(), rd.name),
                    dev->get_macaddr()});
    }

    // Leave the views of rules that went away
    if (state != nullptr && state->gen != as.gen) {
        for (const auto& m : *state->get_matched()) {
            auto vi = as.retired.find(m);
            if (vi != as.retired.end())
                changes.push_back(pending_change{dev, vi->second, false, "", mac_addr{}});
        }
    }

    if (!any) {
        dev->erase(state);
        return;
    }

    if (state == nullptr) {
        state = entrytracker->get_shared_instance_as<device_rule_state>(rule_state_id);
        dev->insert(state);
    }

    state->gen = as.gen;
    state->hits = out;

    auto matched = state->get_matched();
    auto tags = state->get_tags();
    matched->clear();
    tags->clear();
    state->set_color("");

    bool have_color = false;

    for (size_t r = 0; r < n; r++) {
        if (!out[r])
            continue;

        const auto& rd = as.rs->rule(r);
        matched->push_back(rd.name);

        for (const auto& t : rd.tags)
            if (std::find(tags->begin(), tags->end(), t) == tags->end())
                tags->push_back(t);

        if (!have_color && !rd.color.empty()) {
            state->set_color(rd.color);
            have_color = true;
        }
    }
}

void device_rules::apply_changes(std::vector<pending_change>& changes) {
    if (changes.empty())
        return;

    for (auto& c : changes) {
        if (c.view != nullptr) {
            if (c.add)
                c.view->add_device_direct(c.device);
            else
                c.view->remove_device_direct(c.device);
        }

        if (!c.alert.empty() && alert_ref >= 0)
            raise_or_hold(c.mac, c.alert);
    }

    changes.clear();
}

void device_rules::raise_or_hold(const mac_addr& mac, const std::string& text) {
    auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();

    kis_lock_guard<kis_mutex> lk(alert_mutex, "device_rules raise_or_hold");

    // Keep order behind anything already held back
    if (alert_backlog.empty()) {
        auto r = alertracker->raise_alert(alert_ref, nullptr, mac_addr{}, mac, mac_addr{}, mac_addr{}, "", text);
        if (r != 0)
            return;
    }

    if (alert_backlog_max == 0)
        return;

    if (alert_backlog.size() >= alert_backlog_max)
        alert_backlog.pop_front();
    alert_backlog.emplace_back(mac, text);
}

void device_rules::drain_alerts() {
    if (alert_ref < 0)
        return;

    auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();

    kis_lock_guard<kis_mutex> lk(alert_mutex, "device_rules drain_alerts");

    while (!alert_backlog.empty()) {
        const auto& a = alert_backlog.front();
        auto r = alertracker->raise_alert(alert_ref, nullptr, mac_addr{}, a.first, mac_addr{}, mac_addr{}, "", a.second);
        if (r == 0)
            break;
        alert_backlog.pop_front();
    }
}

void device_rules::timer_pass() {
    drain_alerts();

    auto as = get_current();
    if (as == nullptr || as->rs->size() == 0)
        return;

    bool full;
    time_t since;

    {
        kis_lock_guard<kis_mutex> lk(mutex, "device_rules timer_pass");

        pass_count++;
        full = full_pending ||
            (as->rs->uses_now() && full_interval > 0 && pass_count % full_interval == 0);
        full_pending = false;
        since = last_pass;
        last_pass = Globalreg::globalreg->last_tv_sec;
    }

    // Timers don't overlap, so the pass state is only used here
    if (pass->gen != as->gen) {
        pass->ctx.bind(as->rs.get(), &pass->env);
        pass->gen = as->gen;
    }

    auto start = std::chrono::steady_clock::now();
    uint64_t evaluated = 0;
    std::vector<pending_change> changes;

    // Live rules are evaluated on packets; a reload evaluates everything once
    const uint8_t *want = nullptr;

    device_tracker_view_function_worker worker(
            [&](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                if (!full && (time_t) dev->get_mod_time() < since)
                    return false;
                eval_device(*as, pass->ctx, dev, want, pass->out, pass->prev, changes);
                evaluated++;
                return false;
            });

    devicetracker->do_device_work(worker);

    apply_changes(changes);

    stat_passes++;
    stat_devices += evaluated;
    stat_last_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start).count();
}

int device_rules::packet_hook(const std::shared_ptr<kis_packet>& in_pack) {
    auto as = get_current();
    if (as == nullptr || !as->any_live)
        return 1;

    auto devinfo = in_pack->fetch<kis_tracked_device_info>(pack_comp_device);
    if (devinfo == nullptr)
        return 1;

    thread_local live_ctx lc;

    if (lc.gen != as->gen) {
        lc.set = as;
        lc.ctx.bind(as->rs.get(), &lc.env);
        lc.gen = as->gen;
    }

    for (const auto& d : devinfo->devrefs) {
        if (d.second == nullptr)
            continue;
        kis_device_lock dlk(d.second, false);
        eval_device(*as, lc.ctx, d.second, as->live_want.data(), lc.out, lc.prev, lc.changes);
    }

    apply_changes(lc.changes);

    return 1;
}

std::shared_ptr<tracker_element> device_rules::rules_endpoint() {
    auto ret = std::make_shared<tracker_element_map>();

    auto f_backend = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.backend",
            tracker_element_factory<tracker_element_string>(), "how device rules are evaluated (jit or vm)");
    auto f_jiterr = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.jit_error",
            tracker_element_factory<tracker_element_string>(), "why device rules aren't using the jit");
    auto f_passes = entrytracker->register_and_get_field_as<tracker_element_uint64>("kismet.devicerules.passes",
            tracker_element_factory<tracker_element_uint64>(), "device rule passes run");
    auto f_devices = entrytracker->register_and_get_field_as<tracker_element_uint64>("kismet.devicerules.evaluated",
            tracker_element_factory<tracker_element_uint64>(), "devices evaluated by device rule passes");
    auto f_last = entrytracker->register_and_get_field_as<tracker_element_uint64>("kismet.devicerules.last_pass_us",
            tracker_element_factory<tracker_element_uint64>(), "duration of the last device rule pass, in microseconds");
    auto f_rules = entrytracker->register_and_get_field_as<tracker_element_vector>("kismet.devicerules.rules",
            tracker_element_factory<tracker_element_vector>(), "device rules");

    ret->insert(f_backend);
    ret->insert(f_jiterr);
    ret->insert(f_passes);
    ret->insert(f_devices);
    ret->insert(f_last);
    ret->insert(f_rules);

    f_passes->set(stat_passes.load());
    f_devices->set(stat_devices.load());
    f_last->set(stat_last_us.load());

    auto as = get_current();
    if (as == nullptr) {
        f_backend->set("none");
        return ret;
    }

    f_backend->set(as->jit ? "jit" : "vm");
    f_jiterr->set(as->jit_error);

    for (size_t i = 0; i < as->rs->size(); i++) {
        const auto& rd = as->rs->rule(i);

        auto r = std::make_shared<tracker_element_map>();

        auto name = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.rule.name",
                tracker_element_factory<tracker_element_string>(), "rule name");
        auto source = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.rule.source",
                tracker_element_factory<tracker_element_string>(), "rule text");
        auto tags = entrytracker->register_and_get_field_as<tracker_element_vector_string>("kismet.devicerules.rule.tags",
                tracker_element_factory<tracker_element_vector_string>(), "tags set by the rule");
        auto color = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.rule.color",
                tracker_element_factory<tracker_element_string>(), "highlight color set by the rule");
        auto view = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.rule.view",
                tracker_element_factory<tracker_element_string>(), "view of devices matching the rule");
        auto alert = entrytracker->register_and_get_field_as<tracker_element_uint8>("kismet.devicerules.rule.alert",
                tracker_element_factory<tracker_element_uint8>(), "rule raises an alert");
        auto live = entrytracker->register_and_get_field_as<tracker_element_uint8>("kismet.devicerules.rule.live",
                tracker_element_factory<tracker_element_uint8>(), "rule is checked on every packet");

        name->set(rd.name);
        source->set(rd.source);
        for (const auto& t : rd.tags)
            tags->push_back(t);
        color->set(rd.color);
        if (rd.view)
            view->set(fmt::format("rule-{}", rd.name));
        alert->set(rd.alert);
        live->set(rd.live);

        r->insert(name);
        r->insert(source);
        r->insert(tags);
        r->insert(color);
        r->insert(view);
        r->insert(alert);
        r->insert(live);

        f_rules->push_back(r);
    }

    return ret;
}

namespace {
    void json_error(std::ostream& stream, const devicerules::parse_error& e) {
        nlohmann::json j;
        j["ok"] = false;
        j["error"] = e.what();
        j["line"] = e.line;
        j["col"] = e.col;
        stream << j.dump();
    }

    std::string rules_param(std::shared_ptr<kis_net_beast_httpd_connection> con) {
        auto& j = con->json();
        if (!j.contains("rules") || !j["rules"].is_string())
            throw std::runtime_error("expected 'rules'");
        auto s = j["rules"].get<std::string>();
        if (s.size() > max_rules_text)
            throw std::runtime_error("rules are too large");
        return s;
    }
}

void device_rules::check_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());
    con->set_mime_type("application/json");

    try {
        auto text = rules_param(con);
        auto as = compile_set(text);

        nlohmann::json j;
        j["ok"] = true;
        j["backend"] = as->jit ? "jit" : "vm";
        auto names = nlohmann::json::array();
        for (size_t i = 0; i < as->rs->size(); i++)
            names.push_back(as->rs->rule(i).name);
        j["rules"] = names;
        stream << j.dump();
    } catch (const devicerules::parse_error& e) {
        json_error(stream, e);
    } catch (const std::exception& e) {
        con->set_status(400);
        stream << nlohmann::json{{"ok", false}, {"error", e.what()}}.dump();
    }
}

void device_rules::set_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());
    con->set_mime_type("application/json");

    try {
        set_rules(rules_param(con));
        auto as = get_current();
        stream << nlohmann::json{{"ok", true}, {"rules", as->rs->size()},
            {"backend", as->jit ? "jit" : "vm"}}.dump();
    } catch (const devicerules::parse_error& e) {
        json_error(stream, e);
    } catch (const std::exception& e) {
        con->set_status(400);
        stream << nlohmann::json{{"ok", false}, {"error", e.what()}}.dump();
    }
}

void device_rules::test_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());
    con->set_mime_type("application/json");

    try {
        auto text = rules_param(con);
        auto& j = con->json();

        if (!j.contains("device") || !j["device"].is_string())
            throw std::runtime_error("expected 'device', a device key");

        auto key = device_key(j["device"].get<std::string>());
        if (key.get_error())
            throw std::runtime_error("invalid device key");

        auto dev = devicetracker->fetch_device(key);
        if (dev == nullptr) {
            con->set_status(404);
            stream << nlohmann::json{{"ok", false}, {"error", "no such device"}}.dump();
            return;
        }

        auto as = compile_set(text);

        kismet_env env;
        devicerules::eval_ctx ctx;
        ctx.bind(as->rs.get(), &env);
        std::vector<uint8_t> out(as->rs->size());

        {
            kis_device_lock dlk(dev, true);
            env.root = dev.get();
            ctx.next_device(Globalreg::globalreg->last_tv_sec);
            as->rs->eval_all(ctx, nullptr, out.data());
            env.reset();
        }

        nlohmann::json res;
        res["ok"] = true;
        auto m = nlohmann::json::object();
        for (size_t i = 0; i < as->rs->size(); i++)
            m[as->rs->rule(i).name] = out[i] != 0;
        res["matches"] = m;
        stream << res.dump();
    } catch (const devicerules::parse_error& e) {
        json_error(stream, e);
    } catch (const std::exception& e) {
        con->set_status(400);
        stream << nlohmann::json{{"ok", false}, {"error", e.what()}}.dump();
    }
}
